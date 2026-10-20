//! 任务域的业务编排：列表、详情、重试、停止、人工复核、批量重试、导出。
//!
//! 状态流转与校验都在这里，SQL 与 Redis 交互下沉到 `repositories.rs`。

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::db::AppState;
use crate::engine::action;
use crate::engine::template::TemplateContext;
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::common::{MediaItem, TaskPayload};
use crate::models::rule::RuleGroupTrace;
use crate::models::task::{
    ActionExecRow, ActionExecView, AuditTaskRow, BatchRetryRequest, MediaAssetRow, ReviewRequest,
    TaskDetail, TaskEventRow, TaskEventView, TaskListItem,
};
use crate::response::{ListQuery, Page};

use super::repositories as repo;

/// 人工复核的固定原因码。
const REASON_CODES: &[&str] = &[
    "POLICY_VIOLATION",
    "ADVERTISEMENT",
    "PORN",
    "TERROR",
    "OTHER",
];

/// 批量重试的单次上限。
const BATCH_RETRY_MAX: usize = 100;

/// 导出的行数上限。
const EXPORT_MAX_ROWS: usize = 10_000;

/// 任务列表。
pub async fn list_tasks(
    state: &AppState,
    ctx: &AuthContext,
    query: &ListQuery,
) -> Result<Page<TaskListItem>, ApiError> {
    let filter = build_filter(query, ctx, false);
    let (rows, total) = repo::list_tasks(state, &filter).await?;
    let items = rows.iter().map(|row| to_list_item(row, None)).collect();

    // 数据权限：逐个项目校验可见性。
    for project_id in distinct_projects(&rows) {
        ctx.require_project(project_id)?;
    }

    Ok(Page::new(items, total, query.page(), query.page_size()))
}

/// 任务详情。
pub async fn get_task(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
) -> Result<TaskDetail, ApiError> {
    let task = load_task(state, task_id).await?;
    ctx.require_project(task.project_id)?;
    build_detail(state, task).await
}

/// 重试任务：状态回到 `QUEUED`，重新入队。
pub async fn retry_task(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
) -> Result<Value, ApiError> {
    let task = load_task(state, task_id).await?;
    ctx.require_project(task.project_id)?;

    repo::reset_task_for_retry(state, task_id).await?;
    repo::insert_task_event(
        state,
        task_id,
        task.project_id,
        Some(task.status.as_str()),
        crate::common::TaskStatus::Queued.as_str(),
        Some("任务已重新入队"),
        None,
    )
    .await?;

    // 重新入队到 Redis Stream：audit:{pid}:queue:{audit_code}
    match repo::find_audit_code(state, task.audit_id).await? {
        Some(audit_code) => {
            let message = build_queue_message(&task);
            repo::enqueue_task(state, task.project_id, &audit_code, &message).await?;
        }
        None => {
            tracing::warn!(
                task_id,
                audit_id = task.audit_id,
                "审核定义不存在，重试任务仅落库不入队"
            );
        }
    }

    let retry_count = task.retry_count + 1;
    write_audit(
        state,
        ctx,
        &task,
        "TASK_RETRY",
        json!({ "retry_count": retry_count, "previous_status": task.status }),
    )
    .await?;
    state.metrics.inc(
        "audit_task_retry_total",
        vec![("project".to_string(), task.project_id.to_string())],
    );

    Ok(json!({
        "task_id": task_id,
        "status": crate::common::TaskStatus::Queued.as_str(),
        "retry_count": retry_count,
    }))
}

/// 重试单个动作。
///
/// 简化实现：动作日志里的 `request_json` 存的是已渲染的请求，
/// 这里直接按这份快照重发一次（仅 HTTP / WEBHOOK 适用），
/// 其余动作类型只做记账，不重复触发副作用。
pub async fn retry_action(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
    action_exec_id: u64,
) -> Result<Value, ApiError> {
    let task = load_task(state, task_id).await?;
    ctx.require_project(task.project_id)?;

    let action = repo::find_action_exec(state, task_id, action_exec_id)
        .await?
        .ok_or_else(|| ApiError::not_found("动作执行日志不存在"))?;

    let (status, response, duration_ms, error_message) = replay_action(&action).await;
    let retry_count = action.retry_count + 1;
    repo::update_action_retry(
        state,
        action_exec_id,
        &status,
        Some(&response),
        duration_ms,
        error_message.as_deref(),
        retry_count,
    )
    .await?;

    write_audit(
        state,
        ctx,
        &task,
        "ACTION_RETRY",
        json!({
            "action_exec_id": action_exec_id,
            "action_id": action.action_id,
            "action_type": action.action_type,
            "status": status,
            "retry_count": retry_count,
        }),
    )
    .await?;
    state.metrics.inc(
        "audit_action_retry_total",
        vec![("project".to_string(), task.project_id.to_string())],
    );

    Ok(json!({
        "task_id": task_id,
        "action_exec_id": action_exec_id,
        "status": status,
        "retry_count": retry_count,
        "response": response,
    }))
}

/// 强制停止任务：仅运行中的任务可停。
pub async fn stop_task(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
) -> Result<Value, ApiError> {
    let task = load_task(state, task_id).await?;
    ctx.require_project(task.project_id)?;

    let status = crate::common::TaskStatus::parse(&task.status);
    let running = status.map(|value| value.is_running()).unwrap_or(false);
    if !running {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("任务当前状态（{}）不可停止", task.status),
        ));
    }

    repo::mark_task_failed(state, task_id, "STOPPED_BY_USER", "任务被管理员强制停止").await?;
    repo::insert_task_event(
        state,
        task_id,
        task.project_id,
        Some(task.status.as_str()),
        crate::common::TaskStatus::Failed.as_str(),
        Some("任务被强制停止"),
        None,
    )
    .await?;

    write_audit(
        state,
        ctx,
        &task,
        "TASK_STOP",
        json!({ "previous_status": task.status }),
    )
    .await?;
    state.metrics.inc(
        "audit_task_stop_total",
        vec![("project".to_string(), task.project_id.to_string())],
    );

    Ok(json!({
        "task_id": task_id,
        "status": crate::common::TaskStatus::Failed.as_str(),
        "error_code": "STOPPED_BY_USER",
    }))
}

/// 人工复核：写复核意见 → 走对应结论的结果路由 → 收尾任务。
pub async fn review_task(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
    request: ReviewRequest,
) -> Result<TaskDetail, ApiError> {
    // 1. 参数校验。
    let conclusion = request.conclusion.trim().to_ascii_uppercase();
    if !matches!(conclusion.as_str(), "PASS" | "REJECT") {
        return Err(ApiError::invalid_param(
            "复核结论只能是 PASS 或 REJECT",
            vec![FieldError::new("conclusion", "只允许 PASS 或 REJECT")],
        ));
    }
    let reason_code = request
        .reason_code
        .as_deref()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty());
    let Some(reason_code) = reason_code else {
        return Err(ApiError::invalid_param(
            "复核原因码必填",
            vec![FieldError::new("reason_code", "必填，且只能取固定枚举值")],
        ));
    };
    if !REASON_CODES.contains(&reason_code.as_str()) {
        return Err(ApiError::invalid_param(
            "复核原因码非法",
            vec![FieldError::new(
                "reason_code",
                format!("只允许 {}", REASON_CODES.join(" / ")),
            )],
        ));
    }

    let task = load_task(state, task_id).await?;
    ctx.require_project(task.project_id)?;

    // 2. 同一个任务只能复核一次（唯一索引兜底）。
    if repo::find_review_opinion(state, task_id).await?.is_some() {
        return Err(ApiError::conflict(
            "VERSION_CONFLICT",
            "该任务已完成人工复核",
        ));
    }
    repo::insert_review_opinion(
        state,
        task_id,
        task.project_id,
        ctx.user_id,
        &conclusion,
        Some(&reason_code),
        request.remark.as_deref(),
    )
    .await?;

    // 3. 按结论走对应结果路由的动作。
    let mut failed_actions = 0_u32;
    if let Some(row) = repo::find_result_route(state, task.audit_id, &conclusion).await? {
        let route = repo::to_route_view(row)?;
        let context = build_template_context(&task, &conclusion);
        let outcomes = action::execute_route(
            state,
            task.project_id,
            task_id,
            &conclusion,
            &route.actions,
            &context,
        )
        .await;
        failed_actions = outcomes
            .iter()
            .filter(|item| item.status == "FAILED")
            .count() as u32;
    }

    // 4. 收尾：任务置成功并写入结论。
    let duration_ms = (chrono::Utc::now().naive_utc() - task.created_at)
        .num_milliseconds()
        .max(0) as i32;
    repo::finish_task_with_conclusion(state, task_id, &conclusion, Some(duration_ms)).await?;
    repo::insert_task_event(
        state,
        task_id,
        task.project_id,
        Some(task.status.as_str()),
        crate::common::TaskStatus::Success.as_str(),
        Some("人工复核完成"),
        Some(duration_ms),
    )
    .await?;

    write_audit(
        state,
        ctx,
        &task,
        "TASK_REVIEW",
        json!({
            "conclusion": conclusion,
            "reason_code": reason_code,
            "remark": request.remark,
            "failed_actions": failed_actions,
        }),
    )
    .await?;
    state.metrics.inc(
        "audit_task_review_total",
        vec![("project".to_string(), task.project_id.to_string())],
    );

    let task = load_task(state, task_id).await?;
    build_detail(state, task).await
}

/// 批量重试：逐个执行，单条失败不影响其它任务。
pub async fn batch_retry(
    state: &AppState,
    ctx: &AuthContext,
    request: BatchRetryRequest,
) -> Result<Value, ApiError> {
    if request.task_ids.is_empty() {
        return Err(ApiError::invalid_param(
            "任务 ID 列表不能为空",
            vec![FieldError::new("task_ids", "至少要有一个任务 ID")],
        ));
    }
    if request.task_ids.len() > BATCH_RETRY_MAX {
        return Err(ApiError::invalid_param(
            format!("单次批量重试最多 {BATCH_RETRY_MAX} 条"),
            vec![FieldError::new(
                "task_ids",
                format!(
                    "最多 {BATCH_RETRY_MAX} 条，当前 {} 条",
                    request.task_ids.len()
                ),
            )],
        ));
    }

    let mut succeeded: Vec<u64> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for task_id in request.task_ids {
        match retry_task(state, ctx, task_id).await {
            Ok(_) => succeeded.push(task_id),
            Err(err) => failed.push(json!({ "task_id": task_id, "reason": err.to_string() })),
        }
    }

    Ok(json!({ "succeeded": succeeded, "failed": failed }))
}

/// 导出任务列表：生成 CSV 文件并登记导出任务。
pub async fn export_tasks(
    state: &AppState,
    ctx: &AuthContext,
    request: ExportTasksRequest,
) -> Result<Value, ApiError> {
    let filter = build_filter_from_request(&request.filters, ctx)?;

    // 1. 登记导出任务。
    let export_id = state.ids.next_id();
    repo::insert_export_task(
        state,
        export_id,
        filter.project_id,
        ctx.user_id,
        "tasks",
        Some(&serde_json::to_value(&request.filters)?),
    )
    .await?;

    // 2. 取数并写 CSV（多取一行用于判断是否超限）。
    let rows = repo::list_tasks_for_export(state, &filter, EXPORT_MAX_ROWS as u64 + 1).await?;
    let truncated = rows.len() > EXPORT_MAX_ROWS;
    let exported = rows.len().min(EXPORT_MAX_ROWS);
    let file_path = write_export_csv(export_id, &rows[..exported])?;

    // 3. 回写导出结果。
    let error_message = if truncated {
        Some(format!(
            "匹配行数超过上限 {EXPORT_MAX_ROWS}，仅导出前 {EXPORT_MAX_ROWS} 行"
        ))
    } else {
        None
    };
    repo::finish_export_task(
        state,
        export_id,
        exported as i32,
        &file_path,
        error_message.as_deref(),
    )
    .await?;

    Ok(json!({
        "export_id": export_id,
        "status": "DONE",
        "total_rows": exported,
        "file_path": file_path,
    }))
}

/// 待议复核队列：等待越久的排前面。
pub async fn list_reviews(
    state: &AppState,
    ctx: &AuthContext,
    query: &ListQuery,
) -> Result<Page<TaskListItem>, ApiError> {
    let filter = build_filter(query, ctx, true);
    let (rows, total) = repo::list_tasks(state, &filter).await?;

    let now_ms = crate::common::now_ms();
    let items = rows
        .iter()
        .map(|row| {
            let waiting_ms = (now_ms - row.created_at.and_utc().timestamp_millis()).max(0);
            to_list_item(row, Some(waiting_ms))
        })
        .collect();

    for project_id in distinct_projects(&rows) {
        ctx.require_project(project_id)?;
    }

    Ok(Page::new(items, total, query.page(), query.page_size()))
}

/// 待议复核详情：与任务详情同构。
pub async fn get_review(
    state: &AppState,
    ctx: &AuthContext,
    task_id: u64,
) -> Result<TaskDetail, ApiError> {
    get_task(state, ctx, task_id).await
}

// ---------------------------------------------------------------------------
// 入参结构
// ---------------------------------------------------------------------------

/// 导出入参：`filters` 与任务列表的筛选结构一致。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExportTasksRequest {
    #[serde(default)]
    pub filters: TaskFilterRequest,
}

/// 任务筛选条件（导出用）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TaskFilterRequest {
    pub project_id: Option<u64>,
    pub audit_id: Option<u64>,
    #[serde(default)]
    pub source_type: Vec<String>,
    #[serde(default)]
    pub result: Vec<String>,
    #[serde(default)]
    pub status: Vec<String>,
    #[serde(default)]
    pub dedupe_flag: Vec<String>,
    pub duration_min: Option<i64>,
    pub duration_max: Option<i64>,
    pub created_at_from: Option<String>,
    pub created_at_to: Option<String>,
    pub keyword: Option<String>,
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 取任务，不存在返回 404。
async fn load_task(state: &AppState, task_id: u64) -> Result<AuditTaskRow, ApiError> {
    repo::find_task(state, task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("审核任务不存在"))
}

/// 组装任务详情。
async fn build_detail(state: &AppState, task: AuditTaskRow) -> Result<TaskDetail, ApiError> {
    let media_rows = repo::list_media(state, task.id).await?;
    let event_rows = repo::list_events(state, task.id).await?;
    let action_rows = repo::list_actions(state, task.id).await?;

    let media: Vec<MediaItem> = media_rows.iter().map(to_media_item).collect();
    let events: Vec<TaskEventView> = event_rows.iter().map(to_event_view).collect();
    let actions: Vec<ActionExecView> = action_rows.iter().map(to_action_view).collect();
    let rule_hit = parse_rule_hit(task.rule_hit_json.as_ref());
    let reasons = build_reasons(task.rule_hit_json.as_ref(), task.model_result_json.as_ref());
    let payload = parse_payload(task.payload_json.as_ref());
    let ext = payload.ext.clone();
    let project_name = repo::find_project_name(state, task.project_id).await?;
    let audit_name = repo::find_audit_name(state, task.audit_id).await?;

    Ok(TaskDetail {
        id: task.id,
        task_no: task.task_no.clone(),
        project_id: task.project_id,
        project_name,
        audit_id: task.audit_id,
        audit_name,
        source_type: task.source_type.clone(),
        biz_key: task.biz_key.clone(),
        media_type: task.media_type.clone(),
        status: task.status.clone(),
        result: task.result.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        dedupe_flag: task
            .dedupe_flag
            .clone()
            .unwrap_or_else(|| "NORMAL".to_string()),
        retry_count: task.retry_count,
        duration_ms: task.duration_ms,
        error_code: task.error_code.clone(),
        error_message: task.error_message.clone(),
        media,
        ext,
        reasons,
        rule_hit,
        actions,
        events,
        payload,
        trace_id: task.trace_id.clone(),
        created_at: crate::common::format_datetime(task.created_at),
        finished_at: task.finished_at.map(crate::common::format_datetime),
    })
}

/// 构造列表筛选条件。
fn build_filter(
    query: &ListQuery,
    ctx: &AuthContext,
    review_pending_only: bool,
) -> repo::TaskListFilter {
    // 待议队列默认按创建时间升序：等待越久的越靠前。
    let default_sort = if review_pending_only {
        ("created_at", false)
    } else {
        ("created_at", true)
    };
    let (sort_field, sort_desc) = query.sort_field(
        &[
            "created_at",
            "finished_at",
            "duration_ms",
            "result",
            "status",
        ],
        default_sort,
    );

    repo::TaskListFilter {
        project_id: query
            .filter("project_id")
            .and_then(|value| value.parse().ok()),
        audit_id: query
            .filter("audit_id")
            .and_then(|value| value.parse().ok()),
        source_types: query.filter_list("source_type"),
        results: query.filter_list("result"),
        statuses: query.filter_list("status"),
        dedupe_flags: query.filter_list("dedupe_flag"),
        duration_min: query
            .filter("duration_min")
            .and_then(|value| value.parse().ok()),
        duration_max: query
            .filter("duration_max")
            .and_then(|value| value.parse().ok()),
        created_at_from: query
            .filter("created_at_from")
            .and_then(crate::common::parse_datetime)
            .map(|value| value.naive_utc()),
        created_at_to: query
            .filter("created_at_to")
            .and_then(crate::common::parse_datetime)
            .map(|value| value.naive_utc()),
        keyword: query
            .keyword
            .clone()
            .filter(|value| !value.trim().is_empty()),
        visible_projects: ctx.visible_projects().map(|ids| ids.to_vec()),
        sort_field,
        sort_desc,
        page: query.page(),
        page_size: query.page_size(),
        offset: query.offset(),
        review_pending_only,
    }
}

/// 构造导出用的筛选条件。
fn build_filter_from_request(
    request: &TaskFilterRequest,
    ctx: &AuthContext,
) -> Result<repo::TaskListFilter, ApiError> {
    let created_at_from =
        parse_optional_datetime(request.created_at_from.as_deref(), "created_at_from")?;
    let created_at_to = parse_optional_datetime(request.created_at_to.as_deref(), "created_at_to")?;

    Ok(repo::TaskListFilter {
        project_id: request.project_id,
        audit_id: request.audit_id,
        source_types: request.source_type.clone(),
        results: request.result.clone(),
        statuses: request.status.clone(),
        dedupe_flags: request.dedupe_flag.clone(),
        duration_min: request.duration_min,
        duration_max: request.duration_max,
        created_at_from,
        created_at_to,
        keyword: request
            .keyword
            .clone()
            .filter(|value| !value.trim().is_empty()),
        visible_projects: ctx.visible_projects().map(|ids| ids.to_vec()),
        sort_field: "created_at".to_string(),
        sort_desc: true,
        page: 1,
        page_size: 100,
        offset: 0,
        review_pending_only: false,
    })
}

/// 解析可选时间参数。
fn parse_optional_datetime(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<chrono::NaiveDateTime>, ApiError> {
    let Some(raw) = raw
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    match crate::common::parse_datetime(raw) {
        Some(value) => Ok(Some(value.naive_utc())),
        None => Err(ApiError::invalid_param(
            "时间格式不正确",
            vec![FieldError::new(
                field,
                "需为 ISO8601 或 `YYYY-MM-DD HH:MM:SS`",
            )],
        )),
    }
}

/// 结果里出现过的项目 ID（去重）。
fn distinct_projects(rows: &[repo::TaskJoinedRow]) -> HashSet<u64> {
    rows.iter().map(|row| row.project_id).collect()
}

/// JOIN 行转列表项。
fn to_list_item(row: &repo::TaskJoinedRow, waiting_ms: Option<i64>) -> TaskListItem {
    TaskListItem {
        id: row.id,
        task_no: row.task_no.clone(),
        project_id: row.project_id,
        project_name: row.project_name.clone(),
        audit_id: row.audit_id,
        audit_name: row.audit_name.clone(),
        source_type: row.source_type.clone(),
        biz_key: row.biz_key.clone(),
        media_type: row.media_type.clone(),
        status: row.status.clone(),
        result: row.result.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        dedupe_flag: row
            .dedupe_flag
            .clone()
            .unwrap_or_else(|| "NORMAL".to_string()),
        retry_count: row.retry_count,
        duration_ms: row.duration_ms,
        error_code: row.error_code.clone(),
        error_message: row.error_message.clone(),
        waiting_ms,
        reviewer_id: row.reviewer_id,
        reviewer_name: row.reviewer_name.clone(),
        created_at: crate::common::format_datetime(row.created_at),
        finished_at: row.finished_at.map(crate::common::format_datetime),
    }
}

/// 媒体资产行转媒体项。
fn to_media_item(row: &MediaAssetRow) -> MediaItem {
    let meta = row.meta_json.clone().unwrap_or(Value::Null);
    let content = meta
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let duration = meta.get("duration").and_then(Value::as_f64);
    MediaItem {
        media_type: row.r#type.clone(),
        content,
        url: row.url.clone(),
        duration,
        extra: meta,
    }
}

/// 事件行转对外结构。
fn to_event_view(row: &TaskEventRow) -> TaskEventView {
    TaskEventView {
        from_status: row.from_status.clone(),
        to_status: row.to_status.clone(),
        message: row.message.clone(),
        cost_ms: row.cost_ms,
        created_at: crate::common::format_datetime(row.created_at),
    }
}

/// 动作日志行转对外结构。
fn to_action_view(row: &ActionExecRow) -> ActionExecView {
    ActionExecView {
        id: row.id,
        route_type: row.route_type.clone(),
        action_id: row.action_id.clone(),
        action_type: row.action_type.clone(),
        action_name: row.action_name.clone(),
        status: row.status.clone(),
        retry_count: row.retry_count,
        duration_ms: row.duration_ms,
        request: row.request_json.clone().unwrap_or(Value::Null),
        response: row.response_json.clone().unwrap_or(Value::Null),
        error_message: row.error_message.clone(),
        created_at: crate::common::format_datetime(row.created_at),
    }
}

/// 解析规则命中轨迹。
fn parse_rule_hit(raw: Option<&Value>) -> Vec<RuleGroupTrace> {
    let Some(value) = raw.filter(|value| !value.is_null()) else {
        return Vec::new();
    };
    match serde_json::from_value::<Vec<RuleGroupTrace>>(value.clone()) {
        Ok(list) => list,
        Err(err) => {
            tracing::warn!(error = %err, "规则命中轨迹解析失败");
            Vec::new()
        }
    }
}

/// 解析任务载荷。
fn parse_payload(raw: Option<&Value>) -> TaskPayload {
    let Some(value) = raw.filter(|value| !value.is_null()) else {
        return TaskPayload::default();
    };
    match serde_json::from_value::<TaskPayload>(value.clone()) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(error = %err, "任务载荷解析失败");
            TaskPayload::default()
        }
    }
}

/// 汇总命中原因：规则命中 + 模型结论。
fn build_reasons(rule_hit: Option<&Value>, model_result: Option<&Value>) -> Vec<Value> {
    let mut reasons: Vec<Value> = Vec::new();

    if let Some(items) = rule_hit.and_then(|value| value.as_array()) {
        for item in items {
            let hit = item.get("hit").and_then(Value::as_bool).unwrap_or(false);
            if !hit {
                continue;
            }
            let rule = item
                .get("rule")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            reasons.push(json!({ "source": "rule", "rule": rule }));
        }
    }

    if let Some(model) = model_result {
        if let Some(label) = model.get("label").and_then(Value::as_str) {
            if !label.trim().is_empty() {
                let mut reason = json!({ "source": "model", "label": label });
                if let Some(score) = model.get("score").and_then(Value::as_f64) {
                    reason["score"] = json!(score);
                }
                reasons.push(reason);
            }
        }
    }

    reasons
}

/// 构造重新入队的队列消息。
fn build_queue_message(task: &AuditTaskRow) -> Value {
    let payload = parse_payload(task.payload_json.as_ref());
    json!({
        "msg_id": task.id.to_string(),
        "biz_key": task.biz_key,
        "media": payload.media,
        "ext": payload.ext,
        "callback": Value::Null,
        "submit_at": chrono::Utc::now().timestamp_millis(),
    })
}

/// 构造动作模板上下文。
fn build_template_context(task: &AuditTaskRow, conclusion: &str) -> TemplateContext {
    let payload = parse_payload(task.payload_json.as_ref());
    let media_url = payload
        .media
        .iter()
        .map(|item| item.url.clone())
        .find(|url| !url.is_empty())
        .unwrap_or_default();
    let media_text = payload
        .media
        .iter()
        .filter(|item| item.media_type == "text")
        .map(|item| item.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let ext = match payload.ext.clone() {
        Value::Object(fields) => fields,
        _ => serde_json::Map::new(),
    };

    TemplateContext {
        task_id: task.id,
        task_no: task.task_no.clone(),
        task_result: conclusion.to_string(),
        task_biz_key: task.biz_key.clone().unwrap_or_default(),
        media_url,
        media_text,
        model_label: String::new(),
        model_score: 0.0,
        ext,
        now_ms: crate::common::now_ms(),
        now: crate::common::time::now_iso8601(),
    }
}

/// 按日志里的请求快照重放一次动作。
///
/// 返回 `(状态, 响应体, 耗时毫秒, 错误信息)`。
async fn replay_action(action: &ActionExecRow) -> (String, Value, Option<i32>, Option<String>) {
    let request = action.request_json.clone().unwrap_or(Value::Null);
    let Some(url) = request.get("url").and_then(Value::as_str) else {
        return (
            "SKIPPED".to_string(),
            Value::Null,
            None,
            Some(format!("{} 动作没有可重放的请求快照", action.action_type)),
        );
    };
    if !matches!(action.action_type.as_str(), "HTTP" | "WEBHOOK") {
        return (
            "SKIPPED".to_string(),
            Value::Null,
            None,
            Some(format!("{} 动作暂不支持按快照重放", action.action_type)),
        );
    }

    // 与引擎一致：禁止指向内网。
    if let Ok(parsed) = reqwest::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            if crate::modules::audit::service::is_blocked_host(host) {
                return (
                    "FAILED".to_string(),
                    Value::Null,
                    None,
                    Some("目标地址不允许指向内网".to_string()),
                );
            }
        }
    }

    let method_text = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("POST")
        .to_ascii_uppercase();
    let method = match reqwest::Method::from_bytes(method_text.as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            return (
                "FAILED".to_string(),
                Value::Null,
                None,
                Some(format!("不支持的 HTTP 方法「{method_text}」")),
            );
        }
    };
    let body = request.get("body").cloned().unwrap_or(Value::Null);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(5000))
        .build()
    {
        Ok(value) => value,
        Err(err) => {
            return (
                "FAILED".to_string(),
                Value::Null,
                None,
                Some(format!("HTTP 客户端初始化失败：{err}")),
            );
        }
    };

    let started = std::time::Instant::now();
    let mut builder = client.request(method, url);
    if !body.is_null() {
        builder = builder.json(&body);
    }
    match builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();
            let cost = started.elapsed().as_millis() as i32;
            if (200..300).contains(&status) {
                (
                    "SUCCESS".to_string(),
                    json!({ "status": status, "body": text }),
                    Some(cost),
                    None,
                )
            } else {
                (
                    "FAILED".to_string(),
                    json!({ "status": status, "body": text }),
                    Some(cost),
                    Some(format!("目标返回状态码 {status}")),
                )
            }
        }
        Err(err) => (
            "FAILED".to_string(),
            Value::Null,
            Some(started.elapsed().as_millis() as i32),
            Some(format!("重放失败：{err}")),
        ),
    }
}

/// 写审计日志。
async fn write_audit(
    state: &AppState,
    ctx: &AuthContext,
    task: &AuditTaskRow,
    action: &str,
    detail: Value,
) -> Result<(), ApiError> {
    crate::modules::auth::repositories::write_audit_log(
        state,
        crate::models::ops::AuditLogEntry {
            project_id: Some(task.project_id),
            operator: ctx.username.clone(),
            operator_id: Some(ctx.user_id),
            operator_ip: None,
            action: action.to_string(),
            object_type: Some("TASK".to_string()),
            object_id: Some(task.id.to_string()),
            result: "SUCCESS".to_string(),
            detail: Some(detail),
            trace_id: Some(ctx.trace_id.clone()),
        },
    )
    .await
}

/// 写 CSV 文件，返回文件路径。
fn write_export_csv(export_id: u64, rows: &[repo::TaskJoinedRow]) -> Result<String, ApiError> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("exports");
    std::fs::create_dir_all(&dir)
        .map_err(|err| ApiError::internal(format!("创建导出目录失败：{err}")))?;
    let path = dir.join(format!("export_{export_id}.csv"));

    let mut buffer = String::new();
    buffer.push_str(
        "id,task_no,project_name,audit_name,source_type,biz_key,media_type,status,result,\
         dedupe_flag,retry_count,duration_ms,error_code,created_at,finished_at\n",
    );
    for row in rows {
        let cells = [
            row.id.to_string(),
            row.task_no.clone(),
            row.project_name.clone().unwrap_or_default(),
            row.audit_name.clone().unwrap_or_default(),
            row.source_type.clone(),
            row.biz_key.clone().unwrap_or_default(),
            row.media_type.clone(),
            row.status.clone(),
            row.result.clone().unwrap_or_default(),
            row.dedupe_flag.clone().unwrap_or_default(),
            row.retry_count.to_string(),
            row.duration_ms
                .map(|value| value.to_string())
                .unwrap_or_default(),
            row.error_code.clone().unwrap_or_default(),
            crate::common::format_datetime(row.created_at),
            row.finished_at
                .map(crate::common::format_datetime)
                .unwrap_or_default(),
        ];
        let line = cells
            .iter()
            .map(|cell| csv_cell(cell))
            .collect::<Vec<String>>()
            .join(",");
        buffer.push_str(&line);
        buffer.push('\n');
    }

    std::fs::write(&path, buffer)
        .map_err(|err| ApiError::internal(format!("写导出文件失败：{err}")))?;
    Ok(path.to_string_lossy().to_string())
}

/// CSV 单元格转义。
fn csv_cell(raw: &str) -> String {
    if raw.contains(',') || raw.contains('"') || raw.contains('\n') || raw.contains('\r') {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw.to_string()
    }
}
