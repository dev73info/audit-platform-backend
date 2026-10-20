//! 项目连接配置域的 HTTP 层：参数解析、响应映射与权限判定。

use actix_web::web;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::project::{
    ConnectionTestResult, ProjectConfigView, SaveConfigRequest, TestConfigRequest,
};
use crate::response::{ApiResult, Page, ok};

use super::service;
use super::service::{ConfigVersionItem, RevealRequest, RollbackRequest};

/// 连接配置列表。
pub async fn list_configs(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<Page<ProjectConfigView>> {
    ctx.require_permission("project:config:read")?;
    let project_id = path.into_inner();
    let data = service::list_configs(state.get_ref(), &ctx, project_id).await?;
    ok(data)
}

/// 连接配置详情。
pub async fn get_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> ApiResult<ProjectConfigView> {
    ctx.require_permission("project:config:read")?;
    let (project_id, config_id) = path.into_inner();
    let data = service::get_config(state.get_ref(), &ctx, project_id, config_id).await?;
    ok(data)
}

/// 新建连接配置。
pub async fn create_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SaveConfigRequest>,
) -> ApiResult<ProjectConfigView> {
    ctx.require_permission("project:config:write")?;
    let project_id = path.into_inner();
    let data = service::create_config(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 更新连接配置。
pub async fn update_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    body: web::Json<SaveConfigRequest>,
) -> ApiResult<ProjectConfigView> {
    ctx.require_permission("project:config:write")?;
    let (project_id, config_id) = path.into_inner();
    let data =
        service::update_config(state.get_ref(), &ctx, project_id, config_id, body.into_inner())
            .await?;
    ok(data)
}

/// 删除连接配置。
pub async fn delete_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("project:config:write")?;
    let (project_id, config_id) = path.into_inner();
    let data = service::delete_config(state.get_ref(), &ctx, project_id, config_id).await?;
    ok(data)
}

/// 连接测试（不落库）。
pub async fn test_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<TestConfigRequest>,
) -> ApiResult<ConnectionTestResult> {
    ctx.require_permission("project:config:write")?;
    let project_id = path.into_inner();
    let data = service::test_config(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 回滚到历史版本。
pub async fn rollback_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    body: web::Json<RollbackRequest>,
) -> ApiResult<ProjectConfigView> {
    ctx.require_permission("project:config:write")?;
    let (project_id, config_id) = path.into_inner();
    let version = body.into_inner().version;
    let data =
        service::rollback_config(state.get_ref(), &ctx, project_id, config_id, version).await?;
    ok(data)
}

/// 版本历史列表。
pub async fn list_versions(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> ApiResult<Vec<ConfigVersionItem>> {
    ctx.require_permission("project:config:read")?;
    let (project_id, config_id) = path.into_inner();
    let data = service::list_versions(state.get_ref(), &ctx, project_id, config_id).await?;
    ok(data)
}

/// 查看明文配置（二次确认口令）。
pub async fn reveal_config(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    body: web::Json<RevealRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("project:config:reveal")?;
    let (project_id, config_id) = path.into_inner();
    let password = body.into_inner().password;
    let data =
        service::reveal_config(state.get_ref(), &ctx, project_id, config_id, password).await?;
    ok(data)
}
