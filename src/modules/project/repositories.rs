//! 项目域的数据访问层：项目、负责人、配额、回收站与级联软删。
//!
//! 所有 SQL 走运行时查询（`query_as` + `bind`），不使用 `query!` 宏，避免编译期连库。
//! 行结构复用 `src/models/project.rs` 里已定义的结构体。

use std::collections::HashMap;

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder, Transaction};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::audit::{AuditDefinitionRow, AuditRuleRow, TriggerSourceRow};
use crate::models::common::ProjectQuota;
use crate::models::project::ProjectRow;

/// 项目表列清单。
const PROJECT_COLUMNS: &str = "id, name, code, env, status, owner_id, quota_json, retain_days, \
     description, deleted_at, deleted_by, created_by, created_at, updated_at";

/// 项目列表的筛选与排序条件。
#[derive(Debug, Clone, Default)]
pub struct ProjectListFilter {
    /// 状态多选。
    pub statuses: Vec<String>,
    /// 环境多选。
    pub envs: Vec<String>,
    /// 名称 / 编码模糊匹配。
    pub keyword: Option<String>,
    /// 数据权限：可见项目 ID；`None` 表示不限制。
    pub visible_ids: Option<Vec<u64>>,
    /// 排序列（白名单内）。
    pub sort_field: String,
    /// 是否倒序。
    pub sort_desc: bool,
    /// 分页偏移。
    pub offset: u64,
    /// 每页条数。
    pub page_size: u64,
}

/// 项目负责人名。
#[derive(Debug, Clone, FromRow)]
pub struct OwnerNameRow {
    pub id: u64,
    pub name: String,
}

/// 项目统计（子查询实时统计）。
#[derive(Debug, Clone, FromRow)]
pub struct ProjectStatsRow {
    pub project_id: u64,
    /// 审核定义数（未删除）。
    pub audit_count: i64,
    /// 今日任务数。
    pub task_today: i64,
    /// 累计任务数。
    pub task_total: i64,
}

/// 项目配额行。
#[derive(Debug, Clone, FromRow)]
pub struct QuotaRow {
    pub id: u64,
    pub project_id: u64,
    pub max_concurrency: i64,
    pub max_qps: i64,
    pub max_mysql_pool: i64,
    pub max_redis_conn: i64,
    pub max_media_size_mb: i64,
    pub max_daily_tasks: Option<i64>,
    pub max_api_call_per_task: i64,
    pub updated_by: Option<u64>,
    pub updated_at: NaiveDateTime,
}

/// 回收站写入参数。
#[derive(Debug, Clone)]
pub struct RecycleBinInsert {
    pub id: u64,
    pub project_id: u64,
    pub object_type: String,
    pub object_id: u64,
    pub object_name: String,
    pub object_code: Option<String>,
    pub snapshot_json: serde_json::Value,
    pub deleted_by: u64,
    pub expire_at: NaiveDateTime,
}

/// 级联软删命中条数。
#[derive(Debug, Clone, Copy, Default)]
pub struct AffectedCounts {
    pub audits: u64,
    pub trigger_sources: u64,
    pub rules: u64,
    pub routes: u64,
}

/// 按 ID 查项目（不含已删除）。
pub async fn find_project(state: &AppState, project_id: u64) -> Result<ProjectRow, ApiError> {
    let sql = format!(
        "SELECT {PROJECT_COLUMNS} FROM project WHERE id = ? AND deleted_at IS NULL LIMIT 1"
    );
    let row = sqlx::query_as::<_, ProjectRow>(&sql)
        .bind(project_id)
        .fetch_optional(&state.db)
        .await?;
    row.ok_or_else(|| ApiError::not_found("项目不存在"))
}

/// 按编码查项目（含已删除）：回收站里的项目仍然占用编码。
pub async fn find_project_by_code(
    state: &AppState,
    code: &str,
) -> Result<Option<ProjectRow>, ApiError> {
    let sql = format!("SELECT {PROJECT_COLUMNS} FROM project WHERE code = ? LIMIT 1");
    Ok(sqlx::query_as::<_, ProjectRow>(&sql)
        .bind(code)
        .fetch_optional(&state.db)
        .await?)
}

/// 按名称查项目（不含已删除）。
pub async fn find_project_by_name(
    state: &AppState,
    name: &str,
) -> Result<Option<ProjectRow>, ApiError> {
    let sql = format!(
        "SELECT {PROJECT_COLUMNS} FROM project WHERE name = ? AND deleted_at IS NULL LIMIT 1"
    );
    Ok(sqlx::query_as::<_, ProjectRow>(&sql)
        .bind(name)
        .fetch_optional(&state.db)
        .await?)
}

/// 项目列表。
pub async fn list_projects(
    state: &AppState,
    filter: &ProjectListFilter,
) -> Result<Vec<ProjectRow>, ApiError> {
    let mut builder = QueryBuilder::new(format!("SELECT {PROJECT_COLUMNS} FROM project p"));
    push_filters(&mut builder, filter);
    builder.push(" ORDER BY ").push(sort_expression(&filter.sort_field));
    if filter.sort_desc {
        builder.push(" DESC");
    } else {
        builder.push(" ASC");
    }
    builder
        .push(" LIMIT ")
        .push_bind(filter.page_size)
        .push(" OFFSET ")
        .push_bind(filter.offset);

    let sql = builder.build_query_as::<ProjectRow>();
    Ok(sql.fetch_all(&state.db).await?)
}

/// 项目总数。
pub async fn count_projects(state: &AppState, filter: &ProjectListFilter) -> Result<u64, ApiError> {
    let mut builder = QueryBuilder::new("SELECT CAST(COUNT(*) AS SIGNED) FROM project p");
    push_filters(&mut builder, filter);
    let total: i64 = builder.build_query_scalar().fetch_one(&state.db).await?;
    Ok(total.max(0) as u64)
}

/// 追加筛选条件。
fn push_filters<'q>(builder: &mut QueryBuilder<'q, MySql>, filter: &ProjectListFilter) {
    builder.push(" WHERE p.deleted_at IS NULL");

    if !filter.statuses.is_empty() {
        builder.push(" AND p.status IN (");
        let mut separated = builder.separated(", ");
        for status in &filter.statuses {
            separated.push_bind(status.clone());
        }
        separated.push_unseparated(")");
    }

    if !filter.envs.is_empty() {
        builder.push(" AND p.env IN (");
        let mut separated = builder.separated(", ");
        for env in &filter.envs {
            separated.push_bind(env.clone());
        }
        separated.push_unseparated(")");
    }

    if let Some(keyword) = filter.keyword.as_ref().filter(|v| !v.is_empty()) {
        builder
            .push(" AND (p.name LIKE ")
            .push_bind(format!("%{keyword}%"))
            .push(" OR p.code LIKE ")
            .push_bind(format!("%{keyword}%"))
            .push(")");
    }

    if let Some(ids) = filter.visible_ids.as_ref() {
        if ids.is_empty() {
            builder.push(" AND 1 = 0");
        } else {
            builder.push(" AND p.id IN (");
            let mut separated = builder.separated(", ");
            for id in ids {
                separated.push_bind(*id);
            }
            separated.push_unseparated(")");
        }
    }
}

/// 排序列白名单映射：只允许固定列参与排序。
fn sort_expression(field: &str) -> String {
    match field {
        "name" => "p.name".to_string(),
        "code" => "p.code".to_string(),
        "status" => "p.status".to_string(),
        "env" => "p.env".to_string(),
        "updated_at" => "p.updated_at".to_string(),
        _ => "p.created_at".to_string(),
    }
}

/// 批量取负责人名。
pub async fn load_owner_names(
    state: &AppState,
    user_ids: &[u64],
) -> Result<HashMap<u64, String>, ApiError> {
    let mut result: HashMap<u64, String> = HashMap::new();
    if user_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::new(
        "SELECT id, COALESCE(display_name, username) AS name FROM admin_user WHERE id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in user_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let rows = builder
        .build_query_as::<OwnerNameRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.insert(row.id, row.name);
    }
    Ok(result)
}

/// 批量取项目统计（审核数、今日任务数、累计任务数）。
pub async fn load_stats(
    state: &AppState,
    project_ids: &[u64],
) -> Result<HashMap<u64, ProjectStatsRow>, ApiError> {
    let mut result: HashMap<u64, ProjectStatsRow> = HashMap::new();
    if project_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::new(
        "SELECT p.id AS project_id,
                CAST((SELECT COUNT(*) FROM audit_definition a
                       WHERE a.project_id = p.id AND a.deleted_at IS NULL) AS SIGNED) AS audit_count,
                CAST((SELECT COUNT(*) FROM audit_task t
                       WHERE t.project_id = p.id AND t.created_at >= CURDATE()) AS SIGNED) AS task_today,
                CAST((SELECT COUNT(*) FROM audit_task t2 WHERE t2.project_id = p.id) AS SIGNED) AS task_total
           FROM project p
          WHERE p.id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in project_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let rows = builder
        .build_query_as::<ProjectStatsRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.insert(row.project_id, row);
    }
    Ok(result)
}

/// 批量取项目配额。
pub async fn load_quotas(
    state: &AppState,
    project_ids: &[u64],
) -> Result<HashMap<u64, QuotaRow>, ApiError> {
    let mut result: HashMap<u64, QuotaRow> = HashMap::new();
    if project_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::new(
        "SELECT id, project_id, max_concurrency, max_qps, max_mysql_pool, max_redis_conn,
                max_media_size_mb, max_daily_tasks, max_api_call_per_task, updated_by, updated_at
           FROM resource_quota
          WHERE project_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in project_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let rows = builder.build_query_as::<QuotaRow>().fetch_all(&state.db).await?;
    for row in rows {
        result.insert(row.project_id, row);
    }
    Ok(result)
}

/// 取单个项目配额。
pub async fn find_quota(
    state: &AppState,
    project_id: u64,
) -> Result<Option<QuotaRow>, ApiError> {
    let row = sqlx::query_as::<_, QuotaRow>(
        "SELECT id, project_id, max_concurrency, max_qps, max_mysql_pool, max_redis_conn,
                max_media_size_mb, max_daily_tasks, max_api_call_per_task, updated_by, updated_at
           FROM resource_quota
          WHERE project_id = ?
          LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// 其他 ACTIVE 项目已占用的 MySQL 连接池额度合计。
pub async fn sum_active_mysql_pool(
    state: &AppState,
    exclude_project_id: Option<u64>,
) -> Result<i64, ApiError> {
    let mut builder = QueryBuilder::new(
        "SELECT CAST(COALESCE(SUM(q.max_mysql_pool), 0) AS SIGNED)
           FROM resource_quota q
           JOIN project p ON p.id = q.project_id
          WHERE p.status = 'ACTIVE' AND p.deleted_at IS NULL",
    );
    if let Some(project_id) = exclude_project_id {
        builder.push(" AND q.project_id <> ").push_bind(project_id);
    }
    let total: i64 = builder.build_query_scalar().fetch_one(&state.db).await?;
    Ok(total.max(0))
}

/// 项目运行中的任务数（删除项目前要确认）。
pub async fn count_running_tasks(state: &AppState, project_id: u64) -> Result<i64, ApiError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED)
           FROM audit_task
          WHERE project_id = ?
            AND status IN ('QUEUED','WAITING_QUOTA','PROCESSING','RULE_EVALUATING',
                           'MEDIA_REVIEWING','ROUTING','REVIEW_PENDING')",
    )
    .bind(project_id)
    .fetch_one(&state.db)
    .await?;
    Ok(total.max(0))
}

/// 插入项目。
#[allow(clippy::too_many_arguments)]
pub async fn insert_project(
    tx: &mut Transaction<'_, MySql>,
    id: u64,
    name: &str,
    code: &str,
    env: &str,
    owner_id: u64,
    quota_json: &serde_json::Value,
    description: Option<&str>,
    retain_days: i32,
    created_by: u64,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO project
            (id, name, code, env, status, owner_id, quota_json, retain_days, description,
             created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(name)
    .bind(code)
    .bind(env)
    .bind(owner_id)
    .bind(quota_json)
    .bind(retain_days)
    .bind(description)
    .bind(created_by)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 更新项目。传入 `expected_updated_at` 时按乐观锁校验，影响 0 行表示版本冲突。
pub async fn update_project(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    name: &str,
    env: &str,
    owner_id: u64,
    description: Option<&str>,
    expected_updated_at: Option<NaiveDateTime>,
) -> Result<u64, ApiError> {
    let result = match expected_updated_at {
        Some(expected) => {
            sqlx::query(
                "UPDATE project
                    SET name = ?, env = ?, owner_id = ?, description = ?
                  WHERE id = ? AND updated_at = ?",
            )
            .bind(name)
            .bind(env)
            .bind(owner_id)
            .bind(description)
            .bind(project_id)
            .bind(expected)
            .execute(&mut **tx)
            .await?
        }
        None => {
            sqlx::query(
                "UPDATE project
                    SET name = ?, env = ?, owner_id = ?, description = ?
                  WHERE id = ?",
            )
            .bind(name)
            .bind(env)
            .bind(owner_id)
            .bind(description)
            .bind(project_id)
            .execute(&mut **tx)
            .await?
        }
    };
    Ok(result.rows_affected())
}

/// 更新项目状态。
pub async fn update_project_status(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    status: &str,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE project SET status = ? WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(status)
    .bind(project_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// 写入 / 更新资源配额。
pub async fn upsert_quota(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    quota: &ProjectQuota,
    updated_by: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO resource_quota
            (id, project_id, max_concurrency, max_qps, max_mysql_pool, max_redis_conn,
             max_media_size_mb, max_daily_tasks, max_api_call_per_task, updated_by, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            max_concurrency = VALUES(max_concurrency),
            max_qps = VALUES(max_qps),
            max_mysql_pool = VALUES(max_mysql_pool),
            max_redis_conn = VALUES(max_redis_conn),
            max_media_size_mb = VALUES(max_media_size_mb),
            max_daily_tasks = VALUES(max_daily_tasks),
            max_api_call_per_task = VALUES(max_api_call_per_task),
            updated_by = VALUES(updated_by),
            updated_at = VALUES(updated_at)",
    )
    .bind(crate::common::ids::next_id())
    .bind(project_id)
    .bind(quota.max_concurrency)
    .bind(quota.max_qps)
    .bind(quota.max_mysql_pool)
    .bind(quota.max_redis_conn)
    .bind(quota.max_media_size_mb)
    .bind(quota.max_daily_tasks)
    .bind(quota.max_api_call_per_task)
    .bind(updated_by)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 同步项目行上的配额快照。
pub async fn update_quota_json(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    quota_json: &serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE project SET quota_json = ? WHERE id = ?")
        .bind(quota_json)
        .bind(project_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 软删项目。
pub async fn soft_delete_project(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    operator_id: u64,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE project
            SET status = 'DELETED', deleted_at = ?, deleted_by = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(operator_id)
    .bind(project_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// 级联软删项目下的审核定义、触发源、规则与结果路由。
pub async fn soft_delete_children(
    tx: &mut Transaction<'_, MySql>,
    project_id: u64,
    operator_id: u64,
) -> Result<AffectedCounts, ApiError> {
    let now = chrono::Utc::now().naive_utc();

    let audits = sqlx::query(
        "UPDATE audit_definition
            SET deleted_at = ?, deleted_by = ?
          WHERE project_id = ? AND deleted_at IS NULL",
    )
    .bind(now)
    .bind(operator_id)
    .bind(project_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let trigger_sources = sqlx::query(
        "UPDATE trigger_source SET deleted_at = ? WHERE project_id = ? AND deleted_at IS NULL",
    )
    .bind(now)
    .bind(project_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let rules = sqlx::query(
        "UPDATE audit_rule SET deleted_at = ? WHERE project_id = ? AND deleted_at IS NULL",
    )
    .bind(now)
    .bind(project_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let routes = sqlx::query(
        "UPDATE result_route SET deleted_at = ? WHERE project_id = ? AND deleted_at IS NULL",
    )
    .bind(now)
    .bind(project_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(AffectedCounts {
        audits,
        trigger_sources,
        rules,
        routes,
    })
}

/// 写回收站。
pub async fn insert_recycle_bin(
    tx: &mut Transaction<'_, MySql>,
    entry: &RecycleBinInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO recycle_bin
            (id, project_id, object_type, object_id, object_name, object_code, snapshot_json,
             deleted_by, deleted_at, expire_at, purge_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NONE')",
    )
    .bind(entry.id)
    .bind(entry.project_id)
    .bind(&entry.object_type)
    .bind(entry.object_id)
    .bind(&entry.object_name)
    .bind(&entry.object_code)
    .bind(&entry.snapshot_json)
    .bind(entry.deleted_by)
    .bind(chrono::Utc::now().naive_utc())
    .bind(entry.expire_at)
    .execute(&mut **tx)
    .await?;
    Ok(entry.id)
}

/// 项目下的审核定义（未删除），删除项目时用于快照。
pub async fn list_project_audits(
    state: &AppState,
    project_id: u64,
) -> Result<Vec<AuditDefinitionRow>, ApiError> {
    let rows = sqlx::query_as::<_, AuditDefinitionRow>(
        "SELECT id, project_id, name, code, media_types, status, concurrency, timeout_ms,
                retry_policy, dedupe_window_sec, media_hash_in_key, config_json, config_version,
                description, deleted_at, deleted_by, created_by, created_at, updated_at
           FROM audit_definition
          WHERE project_id = ? AND deleted_at IS NULL
          ORDER BY id",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 项目下的触发源（未删除），删除项目时用于快照。
pub async fn list_project_triggers(
    state: &AppState,
    project_id: u64,
) -> Result<Vec<TriggerSourceRow>, ApiError> {
    let rows = sqlx::query_as::<_, TriggerSourceRow>(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status, last_error,
                last_consume_at, success_count, fail_count, deleted_at, created_at, updated_at
           FROM trigger_source
          WHERE project_id = ? AND deleted_at IS NULL
          ORDER BY id",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 项目下的规则组（未删除），删除项目时用于快照。
pub async fn list_project_rules(
    state: &AppState,
    project_id: u64,
) -> Result<Vec<AuditRuleRow>, ApiError> {
    let rows = sqlx::query_as::<_, AuditRuleRow>(
        "SELECT id, project_id, audit_id, name, priority, logic, stop_on_hit, on_hit_result,
                status, deleted_at, created_at, updated_at
           FROM audit_rule
          WHERE project_id = ? AND deleted_at IS NULL
          ORDER BY id",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}
