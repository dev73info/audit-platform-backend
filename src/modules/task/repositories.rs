//! 任务域的数据访问层：任务、事件流水、动作日志、媒体、复核意见、导出任务。
//!
//! 所有 SQL 走运行时查询（`query_as` + `bind`），不使用 `query!` 宏，
//! 避免编译期连库。行结构优先复用 `src/models/` 里已定义的 `FromRow` 结构。

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::{FromRow, MySql, QueryBuilder, Row};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::audit::{ResultRouteRow, ResultRouteView};
use crate::models::task::{
    ActionExecRow, AuditTaskRow, MediaAssetRow, ReviewOpinionRow, TaskEventRow,
};

/// `audit_task` 的列清单。
const TASK_COLUMNS: &str = "id, task_no, project_id, audit_id, source_type, source_id, biz_key, \
     dedupe_hash, media_type, status, result, dedupe_flag, payload_ref, payload_json, \
     rule_hit_json, model_result_json, retry_count, error_code, error_message, duration_ms, \
     trace_id, created_at, updated_at, finished_at";

/// 任务列表的 JOIN 行：任务字段 + 项目名 + 审核名 + 复核人。
#[derive(Debug, Clone, FromRow)]
pub struct TaskJoinedRow {
    pub id: u64,
    pub task_no: String,
    pub project_id: u64,
    pub project_name: Option<String>,
    pub audit_id: u64,
    pub audit_name: Option<String>,
    pub source_type: String,
    pub biz_key: Option<String>,
    pub media_type: String,
    pub status: String,
    pub result: Option<String>,
    pub dedupe_flag: Option<String>,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
    pub reviewer_id: Option<u64>,
    pub reviewer_name: Option<String>,
}

/// 任务列表筛选条件。
#[derive(Debug, Clone, Default)]
pub struct TaskListFilter {
    pub project_id: Option<u64>,
    pub audit_id: Option<u64>,
    pub source_types: Vec<String>,
    pub results: Vec<String>,
    pub statuses: Vec<String>,
    pub dedupe_flags: Vec<String>,
    pub duration_min: Option<i64>,
    pub duration_max: Option<i64>,
    pub created_at_from: Option<NaiveDateTime>,
    pub created_at_to: Option<NaiveDateTime>,
    pub keyword: Option<String>,
    /// 数据权限可见的项目 ID；`None` 表示不限制。
    pub visible_projects: Option<Vec<u64>>,
    pub sort_field: String,
    pub sort_desc: bool,
    pub page: u64,
    pub page_size: u64,
    pub offset: u64,
    /// 只看待议复核（`REVIEW_PENDING`）的任务。
    pub review_pending_only: bool,
}

/// 按 ID 取任务。
pub async fn find_task(state: &AppState, task_id: u64) -> Result<Option<AuditTaskRow>, ApiError> {
    let sql = format!("SELECT {TASK_COLUMNS} FROM audit_task WHERE id = ? LIMIT 1");
    Ok(sqlx::query_as::<_, AuditTaskRow>(&sql)
        .bind(task_id)
        .fetch_optional(&state.db)
        .await?)
}

/// 分页查询任务。返回 `(当前页数据, 总条数)`。
pub async fn list_tasks(
    state: &AppState,
    filter: &TaskListFilter,
) -> Result<(Vec<TaskJoinedRow>, u64), ApiError> {
    // 计数与列表用同一套筛选条件，保证分页总数与实际条数一致。
    let mut count_builder = QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM audit_task t ");
    push_task_conditions(&mut count_builder, filter);
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let rows = fetch_task_rows(state, filter, Some(filter.page_size), Some(filter.offset)).await?;
    Ok((rows, total.max(0) as u64))
}

/// 取导出用的任务行（不分页，最多 `limit` 条）。
pub async fn list_tasks_for_export(
    state: &AppState,
    filter: &TaskListFilter,
    limit: u64,
) -> Result<Vec<TaskJoinedRow>, ApiError> {
    fetch_task_rows(state, filter, Some(limit), None).await
}

/// 执行任务列表查询。
async fn fetch_task_rows(
    state: &AppState,
    filter: &TaskListFilter,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<Vec<TaskJoinedRow>, ApiError> {
    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT t.id, t.task_no, t.project_id, p.name AS project_name, t.audit_id,
                a.name AS audit_name, t.source_type, t.biz_key, t.media_type, t.status, t.result,
                t.dedupe_flag, t.retry_count, t.duration_ms, t.error_code, t.error_message,
                t.created_at, t.finished_at,
                ro.reviewer_id AS reviewer_id,
                COALESCE(u.display_name, u.username) AS reviewer_name
           FROM audit_task t
           LEFT JOIN project p ON p.id = t.project_id
           LEFT JOIN audit_definition a ON a.id = t.audit_id
           LEFT JOIN review_opinion ro ON ro.task_id = t.id
           LEFT JOIN admin_user u ON u.id = ro.reviewer_id",
    );
    push_task_conditions(&mut builder, filter);

    let sort_column = match filter.sort_field.as_str() {
        "finished_at" => "t.finished_at",
        "duration_ms" => "t.duration_ms",
        "result" => "t.result",
        "status" => "t.status",
        _ => "t.created_at",
    };
    let direction = if filter.sort_desc { "DESC" } else { "ASC" };
    builder.push(format!(" ORDER BY {sort_column} {direction}, t.id DESC"));

    if let Some(limit) = limit {
        builder.push(" LIMIT ");
        builder.push_bind(limit);
    }
    if let Some(offset) = offset {
        builder.push(" OFFSET ");
        builder.push_bind(offset);
    }

    Ok(builder
        .build_query_as::<TaskJoinedRow>()
        .fetch_all(&state.db)
        .await?)
}

/// 把任务列表的筛选条件拼进查询构造器。
fn push_task_conditions(builder: &mut QueryBuilder<'_, MySql>, filter: &TaskListFilter) {
    builder.push(" WHERE t.id > 0");

    if let Some(project_id) = filter.project_id {
        builder.push(" AND t.project_id = ");
        builder.push_bind(project_id);
    }
    if let Some(audit_id) = filter.audit_id {
        builder.push(" AND t.audit_id = ");
        builder.push_bind(audit_id);
    }
    if let Some(projects) = filter.visible_projects.as_ref() {
        if projects.is_empty() {
            // 没有任何可见项目：直接不匹配。
            builder.push(" AND t.project_id < 0");
        } else {
            builder.push(" AND t.project_id IN (");
            for (index, project_id) in projects.iter().enumerate() {
                if index > 0 {
                    builder.push(", ");
                }
                builder.push_bind(*project_id);
            }
            builder.push(")");
        }
    }
    if filter.review_pending_only {
        builder.push(" AND t.status = ");
        builder.push_bind(
            crate::common::enums::TaskStatus::ReviewPending
                .as_str()
                .to_string(),
        );
    }
    push_in_clause(builder, "t.source_type", &filter.source_types);
    push_in_clause(builder, "t.result", &filter.results);
    push_in_clause(builder, "t.status", &filter.statuses);
    push_in_clause(builder, "t.dedupe_flag", &filter.dedupe_flags);

    if let Some(min) = filter.duration_min {
        builder.push(" AND t.duration_ms >= ");
        builder.push_bind(min);
    }
    if let Some(max) = filter.duration_max {
        builder.push(" AND t.duration_ms <= ");
        builder.push_bind(max);
    }
    if let Some(from) = filter.created_at_from {
        builder.push(" AND t.created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = filter.created_at_to {
        builder.push(" AND t.created_at <= ");
        builder.push_bind(to);
    }
    if let Some(keyword) = filter.keyword.as_ref() {
        let pattern = format!("%{keyword}%");
        builder.push(" AND (t.task_no LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR t.biz_key LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR t.source_id LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }
}

/// 拼一个 `IN (...)` 条件。
fn push_in_clause(builder: &mut QueryBuilder<'_, MySql>, column: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    builder.push(format!(" AND {column} IN ("));
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            builder.push(", ");
        }
        builder.push_bind(value.clone());
    }
    builder.push(")");
}

/// 取任务的媒体资产。
pub async fn list_media(state: &AppState, task_id: u64) -> Result<Vec<MediaAssetRow>, ApiError> {
    let rows = sqlx::query_as::<_, MediaAssetRow>(
        "SELECT id, task_id, project_id, type, url, oss_key, hash, size_bytes, meta_json, created_at
           FROM media_asset
          WHERE task_id = ?
          ORDER BY id ASC",
    )
    .bind(task_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 取任务的事件流水。
pub async fn list_events(state: &AppState, task_id: u64) -> Result<Vec<TaskEventRow>, ApiError> {
    let rows = sqlx::query_as::<_, TaskEventRow>(
        "SELECT id, task_id, project_id, from_status, to_status, message, cost_ms, created_at
           FROM task_event
          WHERE task_id = ?
          ORDER BY created_at ASC, id ASC",
    )
    .bind(task_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 取任务的动作执行日志。
pub async fn list_actions(state: &AppState, task_id: u64) -> Result<Vec<ActionExecRow>, ApiError> {
    let rows = sqlx::query_as::<_, ActionExecRow>(
        "SELECT id, task_id, project_id, route_type, action_id, action_type, action_name,
                request_json, response_json, status, retry_count, duration_ms, error_message,
                created_at
           FROM action_exec_log
          WHERE task_id = ?
          ORDER BY created_at ASC, id ASC",
    )
    .bind(task_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 取单条动作执行日志（必须属于该任务）。
pub async fn find_action_exec(
    state: &AppState,
    task_id: u64,
    action_exec_id: u64,
) -> Result<Option<ActionExecRow>, ApiError> {
    let row = sqlx::query_as::<_, ActionExecRow>(
        "SELECT id, task_id, project_id, route_type, action_id, action_type, action_name,
                request_json, response_json, status, retry_count, duration_ms, error_message,
                created_at
           FROM action_exec_log
          WHERE id = ? AND task_id = ?
          LIMIT 1",
    )
    .bind(action_exec_id)
    .bind(task_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// 取任务的复核意见。
pub async fn find_review_opinion(
    state: &AppState,
    task_id: u64,
) -> Result<Option<ReviewOpinionRow>, ApiError> {
    let row = sqlx::query_as::<_, ReviewOpinionRow>(
        "SELECT id, task_id, project_id, reviewer_id, conclusion, reason_code, remark, created_at
           FROM review_opinion
          WHERE task_id = ?
          LIMIT 1",
    )
    .bind(task_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// 写复核意见。同一任务重复复核命中唯一索引时返回 409 `VERSION_CONFLICT`。
pub async fn insert_review_opinion(
    state: &AppState,
    task_id: u64,
    project_id: u64,
    reviewer_id: u64,
    conclusion: &str,
    reason_code: Option<&str>,
    remark: Option<&str>,
) -> Result<(), ApiError> {
    let result = sqlx::query(
        "INSERT INTO review_opinion
            (id, task_id, project_id, reviewer_id, conclusion, reason_code, remark, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(task_id)
    .bind(project_id)
    .bind(reviewer_id)
    .bind(conclusion)
    .bind(reason_code)
    .bind(remark)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await;

    if let Err(err) = result {
        if let sqlx::Error::Database(db_err) = &err {
            if db_err.is_unique_violation() {
                return Err(ApiError::conflict(
                    "VERSION_CONFLICT",
                    "该任务已完成人工复核",
                ));
            }
        }
        return Err(err.into());
    }
    Ok(())
}

/// 写一条任务事件流水。
pub async fn insert_task_event(
    state: &AppState,
    task_id: u64,
    project_id: u64,
    from_status: Option<&str>,
    to_status: &str,
    message: Option<&str>,
    cost_ms: Option<i32>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO task_event
            (id, task_id, project_id, from_status, to_status, message, cost_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(task_id)
    .bind(project_id)
    .bind(from_status)
    .bind(to_status)
    .bind(message)
    .bind(cost_ms)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 把任务置回待执行状态：清空结束时间与错误信息，重试次数加一。
pub async fn reset_task_for_retry(state: &AppState, task_id: u64) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_task
            SET status = ?,
                retry_count = retry_count + 1,
                finished_at = NULL,
                error_code = NULL,
                error_message = NULL,
                duration_ms = NULL,
                updated_at = ?
          WHERE id = ?",
    )
    .bind(crate::common::enums::TaskStatus::Queued.as_str())
    .bind(chrono::Utc::now().naive_utc())
    .bind(task_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 把任务置为失败（强制停止）。
pub async fn mark_task_failed(
    state: &AppState,
    task_id: u64,
    error_code: &str,
    error_message: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_task
            SET status = ?,
                error_code = ?,
                error_message = ?,
                finished_at = ?,
                updated_at = ?
          WHERE id = ?",
    )
    .bind(crate::common::enums::TaskStatus::Failed.as_str())
    .bind(error_code)
    .bind(error_message)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(task_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 人工复核后收尾：任务置成功并写入结论。
pub async fn finish_task_with_conclusion(
    state: &AppState,
    task_id: u64,
    conclusion: &str,
    duration_ms: Option<i32>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE audit_task
            SET status = ?,
                result = ?,
                duration_ms = COALESCE(?, duration_ms),
                finished_at = ?,
                updated_at = ?
          WHERE id = ?",
    )
    .bind(crate::common::enums::TaskStatus::Success.as_str())
    .bind(conclusion)
    .bind(duration_ms)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(task_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 更新动作执行日志（重试后回写状态与响应）。
pub async fn update_action_retry(
    state: &AppState,
    action_exec_id: u64,
    status: &str,
    response: Option<&Value>,
    duration_ms: Option<i32>,
    error_message: Option<&str>,
    retry_count: i32,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE action_exec_log
            SET status = ?,
                response_json = COALESCE(?, response_json),
                duration_ms = COALESCE(?, duration_ms),
                error_message = ?,
                retry_count = ?
          WHERE id = ?",
    )
    .bind(status)
    .bind(response)
    .bind(duration_ms)
    .bind(error_message)
    .bind(retry_count)
    .bind(action_exec_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 取审核定义的编码（入队时要拼队列名）。
pub async fn find_audit_code(state: &AppState, audit_id: u64) -> Result<Option<String>, ApiError> {
    let row = sqlx::query(
        "SELECT code FROM audit_definition WHERE id = ? AND deleted_at IS NULL LIMIT 1",
    )
    .bind(audit_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|item| item.get::<String, _>("code")))
}

/// 取项目名称。
pub async fn find_project_name(
    state: &AppState,
    project_id: u64,
) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT name FROM project WHERE id = ? LIMIT 1")
        .bind(project_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|item| item.get::<String, _>("name")))
}

/// 取审核定义名称。
pub async fn find_audit_name(state: &AppState, audit_id: u64) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT name FROM audit_definition WHERE id = ? LIMIT 1")
        .bind(audit_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|item| item.get::<String, _>("name")))
}

/// 取审核在某个结论下的结果路由。
pub async fn find_result_route(
    state: &AppState,
    audit_id: u64,
    result_type: &str,
) -> Result<Option<ResultRouteRow>, ApiError> {
    let row = sqlx::query_as::<_, ResultRouteRow>(
        "SELECT id, project_id, audit_id, result_type, exec_mode, on_error, actions_json,
                status, deleted_at, updated_at
           FROM result_route
          WHERE audit_id = ? AND result_type = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(audit_id)
    .bind(result_type)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// 把结果路由行转成可直接执行的动作视图。
pub fn to_route_view(row: ResultRouteRow) -> Result<ResultRouteView, ApiError> {
    let actions = if row.actions_json.is_null() {
        Vec::new()
    } else {
        serde_json::from_value::<Vec<crate::models::rule::ActionSpec>>(row.actions_json.clone())
            .map_err(|err| ApiError::internal(format!("结果路由动作解析失败：{err}")))?
    };
    Ok(ResultRouteView {
        id: Some(row.id),
        result_type: row.result_type,
        exec_mode: row.exec_mode,
        on_error: row.on_error,
        actions,
        status: Some(row.status),
    })
}

/// 建一条导出任务（状态 `PENDING`）。
pub async fn insert_export_task(
    state: &AppState,
    export_id: u64,
    project_id: Option<u64>,
    requested_by: u64,
    page_key: &str,
    filters: Option<&Value>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO export_task
            (id, project_id, requested_by, page_key, filters_json, format, status, total_rows,
             created_at)
         VALUES (?, ?, ?, ?, ?, 'CSV', 'PENDING', 0, ?)",
    )
    .bind(export_id)
    .bind(project_id)
    .bind(requested_by)
    .bind(page_key)
    .bind(filters)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 回写导出任务的结果。
pub async fn finish_export_task(
    state: &AppState,
    export_id: u64,
    total_rows: i32,
    file_path: &str,
    error_message: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE export_task
            SET status = 'DONE',
                total_rows = ?,
                file_path = ?,
                error_message = ?,
                finished_at = ?
          WHERE id = ?",
    )
    .bind(total_rows)
    .bind(file_path)
    .bind(error_message)
    .bind(chrono::Utc::now().naive_utc())
    .bind(export_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 把任务重新投递到 Redis Stream 队列 `audit:{pid}:queue:{audit_code}`。
///
/// Redis 不可用时只记日志：任务仍停在 `QUEUED`，由调度器兜底。
pub async fn enqueue_task(
    state: &AppState,
    project_id: u64,
    audit_code: &str,
    message: &Value,
) -> Result<(), ApiError> {
    let queue_key = format!("audit:{project_id}:queue:{audit_code}");
    let Some(mut conn) = state.redis.clone() else {
        tracing::warn!(queue = %queue_key, "Redis 不可用，重试任务仅落库不入队");
        return Ok(());
    };

    let payload_text = serde_json::to_string(message)?;
    let added = redis::cmd("XADD")
        .arg(&queue_key)
        .arg("*")
        .arg("payload")
        .arg(&payload_text)
        .query_async::<String>(&mut conn)
        .await;
    if let Err(err) = added {
        tracing::error!(error = %err, queue = %queue_key, "重试任务入队失败");
        return Err(ApiError::downstream(format!("重试任务入队失败：{err}")));
    }
    Ok(())
}
