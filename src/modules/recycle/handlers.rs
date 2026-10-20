//! 回收站接口。

use actix_web::web;

use crate::db::AppState;
use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::models::ops::{BatchPurgeRequest, PurgeRequest, RestoreRequest};
use crate::modules::recycle::service;
use crate::response::{ApiResult, ListQuery, ok};

/// `GET /api/admin/v1/recycle-bin`
pub async fn list(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<crate::response::Page<crate::models::ops::RecycleBinView>> {
    ctx.require_permission("recycle:read")?;
    let (items, total) = service::list(&state, &query, ctx.visible_projects()).await?;
    ok(crate::response::Page::new(items, total, query.page(), query.page_size()))
}

/// `POST /api/admin/v1/recycle-bin/{id}/restore`
pub async fn restore(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    _body: Option<web::Json<RestoreRequest>>,
) -> ApiResult<crate::models::ops::RecycleBinView> {
    ctx.require_permission("recycle:restore")?;
    let id = path.into_inner();
    let item = service::restore(&state, id, ctx.user_id).await?;
    ctx.require_project(item.project_id)?;
    ok(item)
}

/// `DELETE /api/admin/v1/recycle-bin/{id}/purge`
pub async fn purge(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<PurgeRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("recycle:purge")?;
    let id = path.into_inner();
    let result = service::purge(&state, id, &body.confirm_name, ctx.user_id).await?;
    ok(result)
}

/// `POST /api/admin/v1/recycle-bin/batch-purge`
pub async fn batch_purge(
    ctx: AuthContext,
    state: web::Data<AppState>,
    body: web::Json<BatchPurgeRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("recycle:purge")?;
    if body.ids.is_empty() {
        return Err(ApiError::bad_request("请先选择要永久删除的对象"));
    }
    if body.ids.len() > 50 {
        return Err(ApiError::bad_request("单次最多永久删除 50 条"));
    }
    let result = service::batch_purge(&state, &body.ids, ctx.user_id).await?;
    ok(result)
}

/// `GET /api/admin/v1/cleanup-tasks`
pub async fn list_cleanup_tasks(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<crate::response::Page<crate::models::ops::CleanupTaskRow>> {
    ctx.require_permission("recycle:read")?;
    let (items, total) =
        crate::modules::recycle::repositories::list_cleanup_tasks(&state, query.offset(), query.page_size())
            .await?;
    ok(crate::response::Page::new(items, total, query.page(), query.page_size()))
}
