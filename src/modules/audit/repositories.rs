//! 审核配置域的数据访问层：审核定义、触发源、规则、结果路由、回收站与审计日志。
//!
//! 所有 SQL 走运行时查询（`query_as` + `bind`），不使用 `query!` 宏，
//! 避免编译期连库。行结构统一用 `src/models/` 里已定义的 `FromRow` 结构。

use std::collections::HashMap;

use chrono::NaiveDateTime;
use sqlx::{MySql, QueryBuilder, Row, Transaction};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::audit::{
    AuditDefinitionRow, AuditRuleRow, ResultRouteRow, RuleItemRow, TriggerSourceRow,
};
use crate::models::common::ProjectQuota;
use crate::models::ops::AuditLogEntry;

/// 审核定义落库参数。
#[derive(Debug, Clone)]
pub struct AuditInsert {
    pub id: u64,
    pub project_id: u64,
    pub name: String,
    pub code: String,
    pub media_types: serde_json::Value,
    pub status: String,
    pub concurrency: i32,
    pub timeout_ms: i32,
    pub retry_policy: Option<serde_json::Value>,
    pub dedupe_window_sec: i32,
    pub media_hash_in_key: bool,
    pub config_json: Option<serde_json::Value>,
    pub description: Option<String>,
    pub created_by: u64,
}

/// 审核定义更新参数。
#[derive(Debug, Clone)]
pub struct AuditUpdate {
    pub name: String,
    pub code: String,
    pub media_types: serde_json::Value,
    pub status: String,
    pub concurrency: i32,
    pub timeout_ms: i32,
    pub retry_policy: Option<serde_json::Value>,
    pub dedupe_window_sec: i32,
    pub media_hash_in_key: bool,
    pub config_json: Option<serde_json::Value>,
    pub description: Option<String>,
    pub config_version: i32,
}

/// 审核列表的筛选与排序条件。
#[derive(Debug, Clone, Default)]
pub struct AuditListFilter {
    pub statuses: Vec<String>,
    pub media_types: Vec<String>,
    pub keyword: Option<String>,
    pub created_at_from: Option<NaiveDateTime>,
    pub created_at_to: Option<NaiveDateTime>,
    pub sort_field: String,
    pub sort_desc: bool,
    pub offset: u64,
    pub page_size: u64,
}

/// 审核任务统计。
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditTaskStats {
    pub task_total: u64,
    pub task_today: u64,
    pub pass_count: u64,
}

/// 写审计日志。审核域与触发源域共用这一个入口。
pub async fn write_audit_log(state: &AppState, entry: AuditLogEntry) -> Result<(), ApiError> {
    let id = crate::common::ids::next_id();
    sqlx::query(
        "INSERT INTO audit_log
            (id, project_id, operator, operator_id, operator_ip, action,
             object_type, object_id, result, detail_json, trace_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(entry.project_id)
    .bind(&entry.operator)
    .bind(entry.operator_id)
    .bind(&entry.operator_ip)
    .bind(&entry.action)
    .bind(&entry.object_type)
    .bind(&entry.object_id)
    .bind(if entry.result.is_empty() {
        "SUCCESS".to_string()
    } else {
        entry.result
    })
    .bind(entry.detail)
    .bind(entry.trace_id)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 取审核定义。不存在或已删除返回 404。
pub async fn find_audit(state: &AppState, audit_id: u64) -> Result<AuditDefinitionRow, ApiError> {
    let row = sqlx::query_as::<_, AuditDefinitionRow>(
        "SELECT id, project_id, name, code, media_types, status, concurrency, timeout_ms,
                retry_policy, dedupe_window_sec, media_hash_in_key, config_json, config_version,
                description, deleted_at, deleted_by, created_by, created_at, updated_at
           FROM audit_definition
          WHERE id = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(audit_id)
    .fetch_optional(&state.db)
    .await?;

    row.ok_or_else(|| ApiError::not_found("审核定义不存在"))
}

/// 在事务里取审核定义。
pub async fn find_audit_in(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
) -> Result<AuditDefinitionRow, ApiError> {
    let row = sqlx::query_as::<_, AuditDefinitionRow>(
        "SELECT id, project_id, name, code, media_types, status, concurrency, timeout_ms,
                retry_policy, dedupe_window_sec, media_hash_in_key, config_json, config_version,
                description, deleted_at, deleted_by, created_by, created_at, updated_at
           FROM audit_definition
          WHERE id = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(audit_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.ok_or_else(|| ApiError::not_found("审核定义不存在"))
}

/// 分页查询审核定义。返回 `(当前页数据, 总条数)`。
pub async fn list_audits(
    state: &AppState,
    project_id: u64,
    filter: &AuditListFilter,
) -> Result<(Vec<AuditDefinitionRow>, u64), ApiError> {
    // 计数与列表用同一套筛选条件，保证分页总数与实际条数一致。
    let mut count_builder =
        QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM audit_definition WHERE project_id = ");
    count_builder.push_bind(project_id);
    push_audit_conditions(&mut count_builder, filter);
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, project_id, name, code, media_types, status, concurrency, timeout_ms,
                retry_policy, dedupe_window_sec, media_hash_in_key, config_json, config_version,
                description, deleted_at, deleted_by, created_by, created_at, updated_at
           FROM audit_definition
          WHERE project_id = ",
    );
    builder.push_bind(project_id);
    push_audit_conditions(&mut builder, filter);

    let sort_column = match filter.sort_field.as_str() {
        "name" => "name",
        "code" => "code",
        "status" => "status",
        "updated_at" => "updated_at",
        "concurrency" => "concurrency",
        _ => "created_at",
    };
    let direction = if filter.sort_desc { "DESC" } else { "ASC" };
    builder.push(format!(" ORDER BY {sort_column} {direction}, id DESC"));
    builder.push(" LIMIT ");
    builder.push_bind(filter.page_size);
    builder.push(" OFFSET ");
    builder.push_bind(filter.offset);

    let rows = builder
        .build_query_as::<AuditDefinitionRow>()
        .fetch_all(&state.db)
        .await?;

    Ok((rows, total.max(0) as u64))
}

/// 把审核列表的筛选条件拼进查询构造器。
fn push_audit_conditions(builder: &mut QueryBuilder<'_, MySql>, filter: &AuditListFilter) {
    builder.push(" AND deleted_at IS NULL");

    if !filter.statuses.is_empty() {
        builder.push(" AND status IN (");
        for (index, status) in filter.statuses.iter().enumerate() {
            if index > 0 {
                builder.push(", ");
            }
            builder.push_bind(status.clone());
        }
        builder.push(")");
    }

    if !filter.media_types.is_empty() {
        // 媒体类型存 JSON 数组，用 JSON_CONTAINS 判断交集。
        builder.push(" AND (");
        for (index, media_type) in filter.media_types.iter().enumerate() {
            if index > 0 {
                builder.push(" OR ");
            }
            builder.push("JSON_CONTAINS(media_types, JSON_QUOTE(");
            builder.push_bind(media_type.clone());
            builder.push("))");
        }
        builder.push(")");
    }

    if let Some(keyword) = &filter.keyword {
        let pattern = format!("%{keyword}%");
        builder.push(" AND (name LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR code LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }

    if let Some(from) = filter.created_at_from {
        builder.push(" AND created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = filter.created_at_to {
        builder.push(" AND created_at <= ");
        builder.push_bind(to);
    }
}

/// 项目内是否已存在同编码的审核（不含已删除的）。
pub async fn audit_code_exists(
    state: &AppState,
    project_id: u64,
    code: &str,
    exclude_id: u64,
) -> Result<bool, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_definition
          WHERE project_id = ? AND code = ? AND deleted_at IS NULL AND id <> ?",
    )
    .bind(project_id)
    .bind(code)
    .bind(exclude_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

/// 项目内是否已存在同名称的审核（不含已删除的）。
pub async fn audit_name_exists(
    state: &AppState,
    project_id: u64,
    name: &str,
    exclude_id: u64,
) -> Result<bool, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_definition
          WHERE project_id = ? AND name = ? AND deleted_at IS NULL AND id <> ?",
    )
    .bind(project_id)
    .bind(name)
    .bind(exclude_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

/// 回收站里是否已占用该编码。
pub async fn code_in_recycle_bin(
    state: &AppState,
    project_id: u64,
    code: &str,
) -> Result<bool, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recycle_bin
          WHERE project_id = ? AND object_type = 'AUDIT' AND object_code = ?",
    )
    .bind(project_id)
    .bind(code)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

/// 插入审核定义。
pub async fn insert_audit(
    tx: &mut Transaction<'_, MySql>,
    insert: &AuditInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO audit_definition
            (id, project_id, name, code, media_types, status, concurrency, timeout_ms,
             retry_policy, dedupe_window_sec, media_hash_in_key, config_json, config_version,
             description, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
    )
    .bind(insert.id)
    .bind(insert.project_id)
    .bind(&insert.name)
    .bind(&insert.code)
    .bind(&insert.media_types)
    .bind(&insert.status)
    .bind(insert.concurrency)
    .bind(insert.timeout_ms)
    .bind(&insert.retry_policy)
    .bind(insert.dedupe_window_sec)
    .bind(insert.media_hash_in_key)
    .bind(&insert.config_json)
    .bind(&insert.description)
    .bind(insert.created_by)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(insert.id)
}

/// 更新审核定义。
pub async fn update_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
    update: &AuditUpdate,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_definition
            SET name = ?, code = ?, media_types = ?, status = ?, concurrency = ?, timeout_ms = ?,
                retry_policy = ?, dedupe_window_sec = ?, media_hash_in_key = ?, config_json = ?,
                description = ?, config_version = ?, updated_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&update.name)
    .bind(&update.code)
    .bind(&update.media_types)
    .bind(&update.status)
    .bind(update.concurrency)
    .bind(update.timeout_ms)
    .bind(&update.retry_policy)
    .bind(update.dedupe_window_sec)
    .bind(update.media_hash_in_key)
    .bind(&update.config_json)
    .bind(&update.description)
    .bind(update.config_version)
    .bind(chrono::Utc::now().naive_utc())
    .bind(audit_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 改审核状态。
pub async fn set_audit_status(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
    status: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE audit_definition SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(chrono::Utc::now().naive_utc())
        .bind(audit_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 软删除审核定义。
pub async fn soft_delete_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
    user_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_definition
            SET status = 'DELETED', deleted_at = ?, deleted_by = ?, updated_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(user_id)
    .bind(chrono::Utc::now().naive_utc())
    .bind(audit_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 项目名称。
pub async fn find_project_name(
    state: &AppState,
    project_id: u64,
) -> Result<Option<String>, ApiError> {
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM project WHERE id = ? LIMIT 1")
        .bind(project_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(name)
}

/// 项目状态。
pub async fn find_project_status(
    state: &AppState,
    project_id: u64,
) -> Result<Option<String>, ApiError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM project WHERE id = ? LIMIT 1")
            .bind(project_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(status)
}

/// 项目并发配额。`resource_quota` 没有记录时用默认配额。
pub async fn load_quota(state: &AppState, project_id: u64) -> Result<ProjectQuota, ApiError> {
    let row = sqlx::query(
        "SELECT max_concurrency, max_qps, max_mysql_pool, max_redis_conn,
                max_media_size_mb, max_daily_tasks, max_api_call_per_task
           FROM resource_quota WHERE project_id = ? LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(ProjectQuota::default());
    };

    Ok(ProjectQuota {
        max_concurrency: row.get::<i64, _>("max_concurrency"),
        max_qps: row.get::<i64, _>("max_qps"),
        max_mysql_pool: row.get::<i64, _>("max_mysql_pool"),
        max_redis_conn: row.get::<i64, _>("max_redis_conn"),
        max_media_size_mb: row.get::<i64, _>("max_media_size_mb"),
        max_daily_tasks: row.get::<Option<i64>, _>("max_daily_tasks"),
        max_api_call_per_task: row.get::<i64, _>("max_api_call_per_task"),
    })
}

/// 批量统计审核的任务量与通过量。
pub async fn load_task_stats(
    state: &AppState,
    audit_ids: &[u64],
    today_start: NaiveDateTime,
) -> Result<HashMap<u64, AuditTaskStats>, ApiError> {
    let mut stats: HashMap<u64, AuditTaskStats> = HashMap::new();
    if audit_ids.is_empty() {
        return Ok(stats);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT audit_id,
                COUNT(*) AS task_total,
                COUNT(CASE WHEN created_at >= ",
    );
    builder.push_bind(today_start);
    builder.push(
        " THEN 1 END) AS task_today,
                COUNT(CASE WHEN result = 'PASS' THEN 1 END) AS pass_count
           FROM audit_task
          WHERE status IN ('SUCCESS', 'FAILED') AND audit_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in audit_ids {
        separated.push_bind(*id);
    }
    builder.push(") GROUP BY audit_id");

    let rows = builder
        .build_query_as::<TaskStatsRow>()
        .fetch_all(&state.db)
        .await?;

    for row in rows {
        stats.insert(
            row.audit_id,
            AuditTaskStats {
                task_total: row.task_total.max(0) as u64,
                task_today: row.task_today.max(0) as u64,
                pass_count: row.pass_count.max(0) as u64,
            },
        );
    }
    Ok(stats)
}

/// 任务统计行。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TaskStatsRow {
    pub audit_id: u64,
    pub task_total: i64,
    pub task_today: i64,
    pub pass_count: i64,
}

/// 取审核下的触发源。
pub async fn list_triggers(
    state: &AppState,
    audit_id: u64,
) -> Result<Vec<TriggerSourceRow>, ApiError> {
    let rows = sqlx::query_as::<_, TriggerSourceRow>(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE audit_id = ? AND deleted_at IS NULL
          ORDER BY priority ASC, id ASC",
    )
    .bind(audit_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 批量取多个审核的触发源，按审核 ID 分组。
pub async fn list_triggers_for_audits(
    state: &AppState,
    audit_ids: &[u64],
) -> Result<HashMap<u64, Vec<TriggerSourceRow>>, ApiError> {
    let mut result: HashMap<u64, Vec<TriggerSourceRow>> = HashMap::new();
    if audit_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE deleted_at IS NULL AND audit_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in audit_ids {
        separated.push_bind(*id);
    }
    builder.push(") ORDER BY priority ASC, id ASC");

    let rows = builder
        .build_query_as::<TriggerSourceRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.entry(row.audit_id).or_default().push(row);
    }
    Ok(result)
}

/// 取单个触发源。
pub async fn find_trigger(state: &AppState, trigger_id: u64) -> Result<TriggerSourceRow, ApiError> {
    let row = sqlx::query_as::<_, TriggerSourceRow>(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE id = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(trigger_id)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("触发源不存在"))
}

/// 插入触发源。
pub async fn insert_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger: &TriggerInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO trigger_source
            (id, project_id, audit_id, type, name, config_json, priority, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(trigger.id)
    .bind(trigger.project_id)
    .bind(trigger.audit_id)
    .bind(&trigger.trigger_type)
    .bind(&trigger.name)
    .bind(&trigger.config_json)
    .bind(trigger.priority)
    .bind(&trigger.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(trigger.id)
}

/// 更新触发源。
pub async fn update_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
    trigger: &TriggerUpdate,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source
            SET type = ?, name = ?, config_json = ?, priority = ?, status = ?, updated_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&trigger.trigger_type)
    .bind(&trigger.name)
    .bind(&trigger.config_json)
    .bind(trigger.priority)
    .bind(&trigger.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(trigger_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 改触发源状态。
pub async fn set_trigger_status(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
    status: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE trigger_source SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(chrono::Utc::now().naive_utc())
        .bind(trigger_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 软删除触发源。
pub async fn soft_delete_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(trigger_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 软删除某审核下的全部触发源。
pub async fn soft_delete_triggers_of_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE audit_id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(audit_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 触发源落库参数。
#[derive(Debug, Clone)]
pub struct TriggerInsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_type: String,
    pub name: String,
    pub config_json: serde_json::Value,
    pub priority: i32,
    pub status: String,
}

/// 触发源更新参数。
#[derive(Debug, Clone)]
pub struct TriggerUpdate {
    pub trigger_type: String,
    pub name: String,
    pub config_json: serde_json::Value,
    pub priority: i32,
    pub status: String,
}

/// 取审核下的规则组。
pub async fn list_rules(state: &AppState, audit_id: u64) -> Result<Vec<AuditRuleRow>, ApiError> {
    let rows = sqlx::query_as::<_, AuditRuleRow>(
        "SELECT id, project_id, audit_id, name, priority, logic, stop_on_hit, on_hit_result,
                status, deleted_at, created_at, updated_at
           FROM audit_rule
          WHERE audit_id = ? AND deleted_at IS NULL
          ORDER BY priority ASC, id ASC",
    )
    .bind(audit_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 批量取多个审核的规则组，按审核 ID 分组。
pub async fn list_rules_for_audits(
    state: &AppState,
    audit_ids: &[u64],
) -> Result<HashMap<u64, Vec<AuditRuleRow>>, ApiError> {
    let mut result: HashMap<u64, Vec<AuditRuleRow>> = HashMap::new();
    if audit_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, project_id, audit_id, name, priority, logic, stop_on_hit, on_hit_result,
                status, deleted_at, created_at, updated_at
           FROM audit_rule
          WHERE deleted_at IS NULL AND audit_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in audit_ids {
        separated.push_bind(*id);
    }
    builder.push(") ORDER BY priority ASC, id ASC");

    let rows = builder
        .build_query_as::<AuditRuleRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.entry(row.audit_id).or_default().push(row);
    }
    Ok(result)
}

/// 取单个规则组。
pub async fn find_rule(state: &AppState, rule_id: u64) -> Result<AuditRuleRow, ApiError> {
    let row = sqlx::query_as::<_, AuditRuleRow>(
        "SELECT id, project_id, audit_id, name, priority, logic, stop_on_hit, on_hit_result,
                status, deleted_at, created_at, updated_at
           FROM audit_rule
          WHERE id = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(rule_id)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("规则组不存在"))
}

/// 取规则组下的条件项。
pub async fn list_rule_items(state: &AppState, rule_id: u64) -> Result<Vec<RuleItemRow>, ApiError> {
    let rows = sqlx::query_as::<_, RuleItemRow>(
        "SELECT id, rule_id, field, operator, value_json, case_sensitive, negate, sort_order
           FROM rule_item
          WHERE rule_id = ?
          ORDER BY sort_order ASC, id ASC",
    )
    .bind(rule_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 批量取多个规则组的条件项，按规则 ID 分组。
pub async fn list_rule_items_for_rules(
    state: &AppState,
    rule_ids: &[u64],
) -> Result<HashMap<u64, Vec<RuleItemRow>>, ApiError> {
    let mut result: HashMap<u64, Vec<RuleItemRow>> = HashMap::new();
    if rule_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, rule_id, field, operator, value_json, case_sensitive, negate, sort_order
           FROM rule_item
          WHERE rule_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in rule_ids {
        separated.push_bind(*id);
    }
    builder.push(") ORDER BY sort_order ASC, id ASC");

    let rows = builder
        .build_query_as::<RuleItemRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.entry(row.rule_id).or_default().push(row);
    }
    Ok(result)
}

/// 插入规则组。
pub async fn insert_rule(
    tx: &mut Transaction<'_, MySql>,
    rule: &RuleInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO audit_rule
            (id, project_id, audit_id, name, priority, logic, stop_on_hit, on_hit_result,
             status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(rule.id)
    .bind(rule.project_id)
    .bind(rule.audit_id)
    .bind(&rule.name)
    .bind(rule.priority)
    .bind(&rule.logic)
    .bind(rule.stop_on_hit)
    .bind(&rule.on_hit_result)
    .bind(&rule.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(rule.id)
}

/// 更新规则组。
pub async fn update_rule(
    tx: &mut Transaction<'_, MySql>,
    rule_id: u64,
    rule: &RuleUpdate,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_rule
            SET name = ?, priority = ?, logic = ?, stop_on_hit = ?, on_hit_result = ?,
                status = ?, updated_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&rule.name)
    .bind(rule.priority)
    .bind(&rule.logic)
    .bind(rule.stop_on_hit)
    .bind(&rule.on_hit_result)
    .bind(&rule.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(rule_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 软删除规则组。
pub async fn soft_delete_rule(
    tx: &mut Transaction<'_, MySql>,
    rule_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_rule SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(rule_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 软删除某审核下的全部规则组。
pub async fn soft_delete_rules_of_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE audit_rule SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE audit_id = ?")
        .bind(chrono::Utc::now().naive_utc())
        .bind(chrono::Utc::now().naive_utc())
        .bind(audit_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 规则组落库参数。
#[derive(Debug, Clone)]
pub struct RuleInsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub name: String,
    pub priority: i32,
    pub logic: String,
    pub stop_on_hit: bool,
    pub on_hit_result: String,
    pub status: String,
}

/// 规则组更新参数。
#[derive(Debug, Clone)]
pub struct RuleUpdate {
    pub name: String,
    pub priority: i32,
    pub logic: String,
    pub stop_on_hit: bool,
    pub on_hit_result: String,
    pub status: String,
}

/// 删除规则组下的全部条件项。
pub async fn delete_rule_items(
    tx: &mut Transaction<'_, MySql>,
    rule_id: u64,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM rule_item WHERE rule_id = ?")
        .bind(rule_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 插入规则条件项。
pub async fn insert_rule_item(
    tx: &mut Transaction<'_, MySql>,
    item: &RuleItemInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO rule_item
            (id, rule_id, field, operator, value_json, case_sensitive, negate, sort_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(item.id)
    .bind(item.rule_id)
    .bind(&item.field)
    .bind(&item.operator)
    .bind(&item.value_json)
    .bind(item.case_sensitive)
    .bind(item.negate)
    .bind(item.sort_order)
    .execute(&mut **tx)
    .await?;
    Ok(item.id)
}

/// 规则条件项落库参数。
#[derive(Debug, Clone)]
pub struct RuleItemInsert {
    pub id: u64,
    pub rule_id: u64,
    pub field: String,
    pub operator: String,
    pub value_json: serde_json::Value,
    pub case_sensitive: bool,
    pub negate: bool,
    pub sort_order: i32,
}

/// 取审核下的结果路由。
pub async fn list_routes(state: &AppState, audit_id: u64) -> Result<Vec<ResultRouteRow>, ApiError> {
    let rows = sqlx::query_as::<_, ResultRouteRow>(
        "SELECT id, project_id, audit_id, result_type, exec_mode, on_error, actions_json,
                status, deleted_at, updated_at
           FROM result_route
          WHERE audit_id = ? AND deleted_at IS NULL
          ORDER BY result_type ASC",
    )
    .bind(audit_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 批量取多个审核的结果路由，按审核 ID 分组。
pub async fn list_routes_for_audits(
    state: &AppState,
    audit_ids: &[u64],
) -> Result<HashMap<u64, Vec<ResultRouteRow>>, ApiError> {
    let mut result: HashMap<u64, Vec<ResultRouteRow>> = HashMap::new();
    if audit_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, project_id, audit_id, result_type, exec_mode, on_error, actions_json,
                status, deleted_at, updated_at
           FROM result_route
          WHERE deleted_at IS NULL AND audit_id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in audit_ids {
        separated.push_bind(*id);
    }
    builder.push(") ORDER BY result_type ASC");

    let rows = builder
        .build_query_as::<ResultRouteRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.entry(row.audit_id).or_default().push(row);
    }
    Ok(result)
}

/// 新增或更新结果路由。
pub async fn upsert_route(
    tx: &mut Transaction<'_, MySql>,
    route: &RouteUpsert,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO result_route
            (id, project_id, audit_id, result_type, exec_mode, on_error, actions_json, status, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            exec_mode = VALUES(exec_mode),
            on_error = VALUES(on_error),
            actions_json = VALUES(actions_json),
            status = VALUES(status),
            deleted_at = NULL,
            updated_at = VALUES(updated_at)",
    )
    .bind(route.id)
    .bind(route.project_id)
    .bind(route.audit_id)
    .bind(&route.result_type)
    .bind(&route.exec_mode)
    .bind(&route.on_error)
    .bind(&route.actions_json)
    .bind(&route.status)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 结果路由落库参数。
#[derive(Debug, Clone)]
pub struct RouteUpsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub result_type: String,
    pub exec_mode: String,
    pub on_error: String,
    pub actions_json: serde_json::Value,
    pub status: String,
}

/// 软删除某审核下的全部结果路由。
pub async fn soft_delete_routes_of_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE result_route SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE audit_id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(audit_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 写回收站记录。`expire_at` 是过期时间（删除时间 + 保留天数）。
pub async fn insert_recycle_bin(
    tx: &mut Transaction<'_, MySql>,
    entry: &RecycleBinInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO recycle_bin
            (id, project_id, object_type, object_id, object_name, object_code,
             snapshot_json, deleted_by, deleted_at, expire_at, purge_status)
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

/// 回收站落库参数。
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

/// 写触发源消费记录。
pub async fn insert_consume_log(
    tx: &mut Transaction<'_, MySql>,
    entry: &ConsumeLogInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO trigger_consume_log
            (id, project_id, audit_id, trigger_id, message_id, status, duration_ms, error_message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.id)
    .bind(entry.project_id)
    .bind(entry.audit_id)
    .bind(entry.trigger_id)
    .bind(&entry.message_id)
    .bind(&entry.status)
    .bind(entry.duration_ms)
    .bind(&entry.error_message)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(entry.id)
}

/// 触发源消费记录落库参数。
#[derive(Debug, Clone)]
pub struct ConsumeLogInsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_id: u64,
    pub message_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
}

/// 取触发源最近的消费记录。
pub async fn list_consume_logs(
    state: &AppState,
    trigger_id: u64,
    limit: i64,
) -> Result<Vec<ConsumeLogRow>, ApiError> {
    let rows = sqlx::query_as::<_, ConsumeLogRow>(
        "SELECT id, project_id, audit_id, trigger_id, message_id, status, duration_ms,
                error_message, created_at
           FROM trigger_consume_log
          WHERE trigger_id = ?
          ORDER BY created_at DESC, id DESC
          LIMIT ?",
    )
    .bind(trigger_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 触发源消费记录行。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsumeLogRow {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_id: u64,
    pub message_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 列出项目下指定类型的连接配置名称。
pub async fn list_config_names(
    state: &AppState,
    project_id: u64,
    config_type: &str,
) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT name FROM project_config
          WHERE project_id = ? AND type = ? AND deleted_at IS NULL
          ORDER BY name ASC",
    )
    .bind(project_id)
    .bind(config_type)
    .fetch_all(&state.db)
    .await?;

    let mut names = Vec::with_capacity(rows.len());
    for row in rows {
        names.push(row.get::<String, _>("name"));
    }
    Ok(names)
}

/// 取连接配置的密文。
pub async fn find_config_cipher(
    state: &AppState,
    project_id: u64,
    config_type: &str,
    name: &str,
) -> Result<Option<Vec<u8>>, ApiError> {
    let row = sqlx::query(
        "SELECT config_encrypted FROM project_config
          WHERE project_id = ? AND type = ? AND name = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(project_id)
    .bind(config_type)
    .bind(name)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(row.get::<Vec<u8>, _>("config_encrypted")))
}
