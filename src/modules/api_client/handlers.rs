//! 开放 API 客户端域的 HTTP 层：参数解析、响应映射与权限判定。

use actix_web::web;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::project::{
    ApiClientView, CreateApiClientRequest, UpdateApiClientRequest,
};
use crate::response::{ApiResult, Page, ok};

use super::service;
use super::service::ApiClientCreated;

/// 客户端列表。
pub async fn list_clients(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<Page<ApiClientView>> {
    ctx.require_permission("apiclient:read")?;
    let project_id = path.into_inner();
    let data = service::list_clients(state.get_ref(), &ctx, project_id).await?;
    ok(data)
}

/// 新建客户端（明文密钥只在响应里返回一次）。
pub async fn create_client(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<CreateApiClientRequest>,
) -> ApiResult<ApiClientCreated> {
    ctx.require_permission("apiclient:write")?;
    let project_id = path.into_inner();
    let data = service::create_client(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 更新客户端。
pub async fn update_client(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdateApiClientRequest>,
) -> ApiResult<ApiClientView> {
    ctx.require_permission("apiclient:write")?;
    let client_id = path.into_inner();
    let data = service::update_client(state.get_ref(), &ctx, client_id, body.into_inner()).await?;
    ok(data)
}

/// 轮换密钥（明文密钥只在响应里返回一次）。
pub async fn rotate_secret(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<ApiClientCreated> {
    ctx.require_permission("apiclient:write")?;
    let client_id = path.into_inner();
    let data = service::rotate_secret(state.get_ref(), &ctx, client_id).await?;
    ok(data)
}

/// 删除客户端。
pub async fn delete_client(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("apiclient:write")?;
    let client_id = path.into_inner();
    let data = service::delete_client(state.get_ref(), &ctx, client_id).await?;
    ok(data)
}
