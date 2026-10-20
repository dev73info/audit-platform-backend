//! 项目域的业务编排层：参数校验、状态流转、事务边界与审计写入。
//!
//! 分层约定见 `doc/开发约定.md`：handler 只做参数解析与权限判定，
//! 业务校验、状态流转与事务都在这一层，SQL 在 `repositories.rs`。

use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::db::AppState;
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::common::ProjectQuota;
use crate::models::ops::AuditLogEntry;
use crate::models::project::{
    CreateProjectRequest, ProjectListItem, ProjectStats, UpdateProjectRequest, UpdateQuotaRequest,
};
use crate::response::{ListQuery, Page};

use super::repositories as repo;

/// 合法的项目环境。
const PROJECT_ENVS: &[&str] = &["dev", "test", "staging", "prod"];

/// 允许排序的列。
const SORT_FIELDS: &[&str] = &["created_at", "updated_at", "name", "code", "status", "env"];

/// 控制面预留的数据库连接数：平台自身查询（任务、审计日志、回收站）要留出余量。
const CONTROL_PLANE_RESERVED_CONNECTIONS: i64 = 5;

/// 回收站默认保留天数。
const DEFAULT_RETAIN_DAYS: i32 = 30;

/// 项目编码正则。
fn code_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_-]{2,31}$").expect("正则表达式合法"))
}

/// 暂停项目入参。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PauseProjectRequest {
    /// 暂停原因。
    #[serde(default)]
    pub reason: Option<String>,
}

/// 项目列表。
pub async fn list_projects(
    state: &AppState,
    ctx: &AuthContext,
    query: &ListQuery,
) -> Result<Page<ProjectListItem>, ApiError> {
    let filter = build_filter(ctx, query);
    let total = repo::count_projects(state, &filter).await?;
    let rows = repo::list_projects(state, &filter).await?;
    let items = build_items(state, rows).await?;
    Ok(Page::new(items, total, query.page(), query.page_size()))
}

/// 项目详情。
pub async fn get_project(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
) -> Result<ProjectListItem, ApiError> {
    let row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目读取失败"))
}

/// 新建项目。
pub async fn create_project(
    state: &AppState,
    ctx: &AuthContext,
    req: CreateProjectRequest,
) -> Result<ProjectListItem, ApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::invalid_param(
            "项目名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }
    if name.chars().count() > 64 {
        return Err(ApiError::invalid_param(
            "项目名称过长",
            vec![FieldError::new("name", "最长 64 个字符")],
        ));
    }

    let code = req.code.trim().to_ascii_lowercase();
    validate_code(&code)?;
    let env = validate_env(&req.env)?;
    let owner_id = req.owner_id.unwrap_or(ctx.user_id);

    // 编码全局唯一：回收站里的项目仍然占用编码。
    if repo::find_project_by_code(state, &code).await?.is_some() {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("项目编码 {code} 已被占用"),
        ));
    }
    if repo::find_project_by_name(state, &name).await?.is_some() {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("项目名称 {name} 已存在"),
        ));
    }

    let quota = req.quota.clone().unwrap_or_default();
    check_quota(state, quota.max_mysql_pool, None).await?;

    let project_id = crate::common::ids::next_id();
    let quota_json = serde_json::to_value(&quota)?;
    let mut tx = state.db.begin().await?;
    repo::insert_project(
        &mut tx,
        project_id,
        &name,
        &code,
        &env,
        owner_id,
        &quota_json,
        req.description.as_deref(),
        DEFAULT_RETAIN_DAYS,
        ctx.user_id,
    )
    .await?;
    repo::upsert_quota(&mut tx, project_id, &quota, ctx.user_id).await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        Some(project_id),
        "PROJECT_CREATE",
        "PROJECT",
        project_id,
        json!({ "name": name, "code": code, "env": env, "owner_id": owner_id }),
    )
    .await?;

    let row = repo::find_project(state, project_id).await?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目创建后读取失败"))
}

/// 更新项目。
pub async fn update_project(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: UpdateProjectRequest,
) -> Result<ProjectListItem, ApiError> {
    let row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;

    let name = match req.name.as_ref() {
        Some(value) => value.trim().to_string(),
        None => row.name.clone(),
    };
    if name.is_empty() {
        return Err(ApiError::invalid_param(
            "项目名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }
    let env = match req.env.as_ref() {
        Some(value) => validate_env(value)?,
        None => row.env.clone(),
    };
    let owner_id = req.owner_id.unwrap_or(row.owner_id);
    let description = req.description.clone().or_else(|| row.description.clone());

    if name != row.name && repo::find_project_by_name(state, &name).await?.is_some() {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("项目名称 {name} 已存在"),
        ));
    }

    // 乐观锁：传入 version 时必须与当前版本一致。
    let expected = match req.version {
        Some(version) => {
            let current = version_of(&row);
            if version != current {
                return Err(ApiError::conflict_with(
                    "VERSION_CONFLICT",
                    "项目已被其他人修改，请重新拉取",
                    json!({ "version": current }),
                ));
            }
            Some(row.updated_at)
        }
        None => None,
    };

    let mut tx = state.db.begin().await?;
    let affected = repo::update_project(
        &mut tx,
        project_id,
        &name,
        &env,
        owner_id,
        description.as_deref(),
        expected,
    )
    .await?;
    tx.commit().await?;
    if affected == 0 {
        return Err(ApiError::conflict_with(
            "VERSION_CONFLICT",
            "项目已被其他人修改，请重新拉取",
            json!({}),
        ));
    }

    write_audit(
        state,
        ctx,
        Some(project_id),
        "PROJECT_UPDATE",
        "PROJECT",
        project_id,
        json!({ "name": name, "env": env, "owner_id": owner_id }),
    )
    .await?;

    let row = repo::find_project(state, project_id).await?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目读取失败"))
}

/// 启用项目。
pub async fn enable_project(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
) -> Result<ProjectListItem, ApiError> {
    let row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;
    if row.status == crate::common::ProjectStatus::Deleted.as_str() {
        return Err(ApiError::forbidden("PROJECT_DELETED", "项目已删除"));
    }

    let mut tx = state.db.begin().await?;
    repo::update_project_status(&mut tx, project_id, crate::common::ProjectStatus::Active.as_str())
        .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        Some(project_id),
        "PROJECT_ENABLE",
        "PROJECT",
        project_id,
        json!({ "name": row.name }),
    )
    .await?;

    let row = repo::find_project(state, project_id).await?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目读取失败"))
}

/// 暂停项目。
pub async fn pause_project(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    reason: Option<String>,
) -> Result<ProjectListItem, ApiError> {
    let row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;
    if row.status == crate::common::ProjectStatus::Deleted.as_str() {
        return Err(ApiError::forbidden("PROJECT_DELETED", "项目已删除"));
    }

    let mut tx = state.db.begin().await?;
    repo::update_project_status(&mut tx, project_id, crate::common::ProjectStatus::Paused.as_str())
        .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        Some(project_id),
        "PROJECT_PAUSE",
        "PROJECT",
        project_id,
        json!({ "name": row.name, "reason": reason }),
    )
    .await?;

    let row = repo::find_project(state, project_id).await?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目读取失败"))
}

/// 更新资源配额。
pub async fn update_quota(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: UpdateQuotaRequest,
) -> Result<ProjectListItem, ApiError> {
    let _row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;

    validate_quota_values(&req)?;

    let quota = ProjectQuota {
        max_concurrency: req.max_concurrency,
        max_qps: req.max_qps,
        max_mysql_pool: req.max_mysql_pool,
        max_redis_conn: req.max_redis_conn,
        max_media_size_mb: req.max_media_size_mb,
        max_daily_tasks: req.max_daily_tasks,
        max_api_call_per_task: req.max_api_call_per_task.unwrap_or(10),
    };
    check_quota(state, quota.max_mysql_pool, Some(project_id)).await?;

    let quota_json = serde_json::to_value(&quota)?;
    let mut tx = state.db.begin().await?;
    repo::upsert_quota(&mut tx, project_id, &quota, ctx.user_id).await?;
    repo::update_quota_json(&mut tx, project_id, &quota_json).await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        Some(project_id),
        "QUOTA_UPDATE",
        "PROJECT",
        project_id,
        json!({
            "max_concurrency": quota.max_concurrency,
            "max_qps": quota.max_qps,
            "max_mysql_pool": quota.max_mysql_pool,
            "max_redis_conn": quota.max_redis_conn,
            "max_media_size_mb": quota.max_media_size_mb,
        }),
    )
    .await?;

    let row = repo::find_project(state, project_id).await?;
    let items = build_items(state, vec![row]).await?;
    items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("项目读取失败"))
}

/// 删除项目（软删 + 级联软删 + 写回收站）。
pub async fn delete_project(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    force: bool,
) -> Result<Value, ApiError> {
    let row = repo::find_project(state, project_id).await?;
    ctx.require_project(project_id)?;

    let running_tasks = repo::count_running_tasks(state, project_id).await?;
    if running_tasks > 0 && !force {
        return Err(ApiError::invalid_param(
            format!("该项目还有 {running_tasks} 个运行中的任务，确认后请传 force=true 强制删除"),
            vec![FieldError::new("force", "存在运行中任务，必须显式传 force=true")],
        ));
    }

    let snapshot = build_snapshot(state, &row).await?;
    let retain_days = row.retain_days.max(1) as i64;
    let expire_at = chrono::Utc::now().naive_utc() + chrono::Duration::days(retain_days);

    let mut tx = state.db.begin().await?;
    repo::soft_delete_project(&mut tx, project_id, ctx.user_id).await?;
    let affected = repo::soft_delete_children(&mut tx, project_id, ctx.user_id).await?;
    let recycle_id = repo::insert_recycle_bin(
        &mut tx,
        &repo::RecycleBinInsert {
            id: crate::common::ids::next_id(),
            project_id,
            object_type: crate::common::ObjectType::Project.as_str().to_string(),
            object_id: project_id,
            object_name: row.name.clone(),
            object_code: Some(row.code.clone()),
            snapshot_json: snapshot,
            deleted_by: ctx.user_id,
            expire_at,
        },
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        Some(project_id),
        "PROJECT_DELETE",
        "PROJECT",
        project_id,
        json!({
            "name": row.name,
            "code": row.code,
            "recycle_id": recycle_id,
            "running_tasks": running_tasks,
        }),
    )
    .await?;

    Ok(json!({
        "recycle_id": recycle_id,
        "affected": {
            "audits": affected.audits,
            "trigger_sources": affected.trigger_sources,
            "rules": affected.rules,
        },
        "running_tasks": running_tasks,
        "expire_at": crate::common::format_datetime(expire_at),
    }))
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 构造列表筛选条件。
fn build_filter(ctx: &AuthContext, query: &ListQuery) -> repo::ProjectListFilter {
    let (sort_field, sort_desc) = query.sort_field(SORT_FIELDS, ("created_at", true));
    repo::ProjectListFilter {
        statuses: query.filter_list("status"),
        envs: query.filter_list("env"),
        keyword: query
            .keyword
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        visible_ids: ctx.visible_projects().map(|ids| ids.to_vec()),
        sort_field,
        sort_desc,
        offset: query.offset(),
        page_size: query.page_size(),
    }
}

/// 批量组装项目列表项（负责人、配额、统计）。
async fn build_items(
    state: &AppState,
    rows: Vec<crate::models::project::ProjectRow>,
) -> Result<Vec<ProjectListItem>, ApiError> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let project_ids: Vec<u64> = rows.iter().map(|row| row.id).collect();
    let mut owner_ids: Vec<u64> = rows.iter().map(|row| row.owner_id).collect();
    owner_ids.sort_unstable();
    owner_ids.dedup();

    let owner_names = repo::load_owner_names(state, &owner_ids).await?;
    let stats = repo::load_stats(state, &project_ids).await?;
    let quotas = repo::load_quotas(state, &project_ids).await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let quota = match quotas.get(&row.id) {
            Some(item) => ProjectQuota {
                max_concurrency: item.max_concurrency,
                max_qps: item.max_qps,
                max_mysql_pool: item.max_mysql_pool,
                max_redis_conn: item.max_redis_conn,
                max_media_size_mb: item.max_media_size_mb,
                max_daily_tasks: item.max_daily_tasks,
                max_api_call_per_task: item.max_api_call_per_task,
            },
            // 没有配额行时回落到项目行上的快照，再回落到系统默认模板。
            None => row
                .quota_json
                .as_ref()
                .and_then(|value| serde_json::from_value::<ProjectQuota>(value.clone()).ok())
                .unwrap_or_default(),
        };

        let stat = stats.get(&row.id);
        let project_stats = ProjectStats {
            audit_count: stat.map(|item| item.audit_count).unwrap_or(0),
            task_today: stat.map(|item| item.task_today).unwrap_or(0),
            task_total: stat.map(|item| item.task_total).unwrap_or(0),
            // TODO: 真实队列积压需要连 Redis 统计各队列长度，当前先返回 0。
            queue_backlog: 0,
        };

        items.push(ProjectListItem {
            id: row.id,
            name: row.name.clone(),
            code: row.code.clone(),
            env: row.env.clone(),
            status: row.status.clone(),
            owner_id: row.owner_id,
            owner_name: owner_names.get(&row.owner_id).cloned(),
            description: row.description.clone(),
            retain_days: row.retain_days,
            quota,
            stats: project_stats,
            version: version_of(&row),
            created_at: crate::common::format_datetime(row.created_at),
            updated_at: crate::common::format_datetime(row.updated_at),
        });
    }

    Ok(items)
}

/// 项目版本号：取 `updated_at` 的毫秒时间戳作为乐观锁令牌。
fn version_of(row: &crate::models::project::ProjectRow) -> i64 {
    row.updated_at.and_utc().timestamp_millis()
}

/// 校验项目编码。
fn validate_code(code: &str) -> Result<(), ApiError> {
    if !code_regex().is_match(code) {
        return Err(ApiError::invalid_param(
            "项目编码格式不合法",
            vec![FieldError::new(
                "code",
                "须以小写字母开头，由 3~32 位小写字母、数字、下划线或连字符组成",
            )],
        ));
    }
    Ok(())
}

/// 校验项目环境。
fn validate_env(env: &str) -> Result<String, ApiError> {
    let normalized = env.trim().to_ascii_lowercase();
    if !PROJECT_ENVS.contains(&normalized.as_str()) {
        return Err(ApiError::invalid_param(
            "项目环境取值不合法",
            vec![FieldError::new("env", "只允许 dev / test / staging / prod")],
        ));
    }
    Ok(normalized)
}

/// 校验配额字段。
fn validate_quota_values(req: &UpdateQuotaRequest) -> Result<(), ApiError> {
    let mut errors = Vec::new();
    let checks = [
        ("max_concurrency", req.max_concurrency),
        ("max_qps", req.max_qps),
        ("max_mysql_pool", req.max_mysql_pool),
        ("max_redis_conn", req.max_redis_conn),
        ("max_media_size_mb", req.max_media_size_mb),
        ("max_api_call_per_task", req.max_api_call_per_task.unwrap_or(10)),
    ];
    for (field, value) in checks {
        if value <= 0 {
            errors.push(FieldError::new(field, "必须大于 0"));
        }
    }
    if let Some(value) = req.max_daily_tasks {
        if value <= 0 {
            errors.push(FieldError::new("max_daily_tasks", "必须大于 0"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiError::invalid_param("配额参数不合法", errors))
    }
}

/// 全局连接池配额校验。
async fn check_quota(
    state: &AppState,
    mysql_pool: i64,
    exclude_project_id: Option<u64>,
) -> Result<(), ApiError> {
    let settings = state.settings.as_ref();

    let hard_limit = settings.audit.quota_hard_limit_mysql_pool;
    if mysql_pool > hard_limit {
        return Err(ApiError::forbidden_with(
            "QUOTA_EXCEEDED",
            format!("单项目 MySQL 连接池配额不能超过 {hard_limit}"),
            json!({
                "max_mysql_pool": mysql_pool,
                "quota_hard_limit_mysql_pool": hard_limit,
            }),
        ));
    }

    let global_limit = ((settings.database.max_connections as f64)
        * settings.audit.global_pool_ratio)
        .floor() as i64;
    let sum_other = repo::sum_active_mysql_pool(state, exclude_project_id).await?
        + CONTROL_PLANE_RESERVED_CONNECTIONS;

    if sum_other + mysql_pool > global_limit {
        let remain = (global_limit - sum_other).max(0);
        return Err(ApiError::forbidden_with(
            "GLOBAL_POOL_EXHAUSTED",
            format!(
                "全局连接池额度不足：其他项目已占用 {sum_other}，全局上限 {global_limit}，剩余 {remain}"
            ),
            json!({
                "sum_other": sum_other,
                "global_limit": global_limit,
                "remain": remain,
            }),
        ));
    }

    Ok(())
}

/// 删除项目时的快照（项目 + 审核 + 触发源 + 规则）。
async fn build_snapshot(
    state: &AppState,
    row: &crate::models::project::ProjectRow,
) -> Result<Value, ApiError> {
    let audits = repo::list_project_audits(state, row.id).await?;
    let triggers = repo::list_project_triggers(state, row.id).await?;
    let rules = repo::list_project_rules(state, row.id).await?;

    Ok(json!({
        "project": {
            "id": row.id,
            "name": row.name,
            "code": row.code,
            "env": row.env,
            "status": row.status,
            "owner_id": row.owner_id,
            "description": row.description,
            "retain_days": row.retain_days,
            "quota": row.quota_json,
        },
        "audits": audits
            .iter()
            .map(|item| json!({
                "id": item.id,
                "name": item.name,
                "code": item.code,
                "status": item.status,
                "config": item.config_json,
            }))
            .collect::<Vec<Value>>(),
        "triggers": triggers
            .iter()
            .map(|item| json!({
                "id": item.id,
                "audit_id": item.audit_id,
                "type": item.r#type,
                "name": item.name,
                "status": item.status,
                "config": item.config_json,
            }))
            .collect::<Vec<Value>>(),
        "rules": rules
            .iter()
            .map(|item| json!({
                "id": item.id,
                "audit_id": item.audit_id,
                "name": item.name,
                "priority": item.priority,
                "logic": item.logic,
                "on_hit_result": item.on_hit_result,
                "status": item.status,
            }))
            .collect::<Vec<Value>>(),
    }))
}

/// 写审计日志。
async fn write_audit(
    state: &AppState,
    ctx: &AuthContext,
    project_id: Option<u64>,
    action: &str,
    object_type: &str,
    object_id: u64,
    detail: Value,
) -> Result<(), ApiError> {
    let entry = AuditLogEntry {
        project_id,
        operator: ctx.username.clone(),
        operator_id: Some(ctx.user_id),
        operator_ip: None,
        action: action.to_string(),
        object_type: Some(object_type.to_string()),
        object_id: Some(object_id.to_string()),
        result: "SUCCESS".to_string(),
        detail: Some(detail),
        trace_id: Some(ctx.trace_id.clone()),
    };
    crate::modules::auth::repositories::write_audit_log(state, entry).await
}
