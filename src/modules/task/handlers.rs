//! 任务域的 HTTP 层：参数解析、响应映射与权限判定。
//!
//! 业务校验与状态流转都在 `service.rs`，这里只做「取参数 → 判权限 → 调服务 → 包响应」。

use actix_web::web;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::task::{
    BatchRetryRequest, RetryActionRequest, ReviewRequest, TaskDetail, TaskListItem,
};
use crate::response::{ApiResult, ListQuery, Page, ok};

use super::service;

/// 任务列表。
pub async fn list_tasks(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<Page<TaskListItem>> {
    ctx.require_permission("task:read")?;
    let data = service::list_tasks(state.get_ref(), &ctx, &query).await?;
    ok(data)
}

/// 任务详情。
pub async fn get_task(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<TaskDetail> {
    ctx.require_permission("task:read")?;
    let task_id = path.into_inner();
    let data = service::get_task(state.get_ref(), &ctx, task_id).await?;
    ok(data)
}

/// 重试任务。
pub async fn retry_task(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("task:retry")?;
    let task_id = path.into_inner();
    let data = service::retry_task(state.get_ref(), &ctx, task_id).await?;
    ok(data)
}

/// 重试单个动作。
pub async fn retry_action(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<RetryActionRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("task:retry")?;
    let task_id = path.into_inner();
    let request = body.into_inner();
    let data =
        service::retry_action(state.get_ref(), &ctx, task_id, request.action_exec_id).await?;
    ok(data)
}

/// 强制停止任务。
pub async fn stop_task(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("task:stop")?;
    let task_id = path.into_inner();
    let data = service::stop_task(state.get_ref(), &ctx, task_id).await?;
    ok(data)
}

/// 人工复核。
pub async fn review_task(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<ReviewRequest>,
) -> ApiResult<TaskDetail> {
    ctx.require_permission("task:review")?;
    let task_id = path.into_inner();
    let request = body.into_inner();
    let data = service::review_task(state.get_ref(), &ctx, task_id, request).await?;
    ok(data)
}

/// 批量重试。
pub async fn batch_retry(
    ctx: AuthContext,
    state: web::Data<AppState>,
    body: web::Json<BatchRetryRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("task:retry")?;
    let request = body.into_inner();
    let data = service::batch_retry(state.get_ref(), &ctx, request).await?;
    ok(data)
}

/// 导出任务列表。
pub async fn export_tasks(
    ctx: AuthContext,
    state: web::Data<AppState>,
    body: web::Json<service::ExportTasksRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("task:read")?;
    let request = body.into_inner();
    let data = service::export_tasks(state.get_ref(), &ctx, request).await?;
    ok(data)
}

/// 待议复核队列。
pub async fn list_reviews(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<Page<TaskListItem>> {
    ctx.require_permission("task:read")?;
    let data = service::list_reviews(state.get_ref(), &ctx, &query).await?;
    ok(data)
}

/// 待议复核详情。
pub async fn get_review(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<TaskDetail> {
    ctx.require_permission("task:read")?;
    let task_id = path.into_inner();
    let data = service::get_review(state.get_ref(), &ctx, task_id).await?;
    ok(data)
}
