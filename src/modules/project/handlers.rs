//! 项目域的 HTTP 层：参数解析、响应映射与权限判定。
//!
//! 业务校验与事务都在 `service.rs`，这里只做「取参数 → 判权限 → 调服务 → 包响应」。

use actix_web::web;
use serde::Deserialize;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::project::{
    CreateProjectRequest, ProjectListItem, UpdateProjectRequest, UpdateQuotaRequest,
};
use crate::response::{ApiResult, ListQuery, Page, ok};

use super::service;

/// 删除项目入参：`?force=true` 表示强制删除（忽略运行中的任务）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DeleteProjectQuery {
    #[serde(default)]
    pub force: bool,
}

/// 项目列表。
pub async fn list_projects(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<Page<ProjectListItem>> {
    ctx.require_permission("project:read")?;
    let data = service::list_projects(state.get_ref(), &ctx, &query).await?;
    ok(data)
}

/// 新建项目。
pub async fn create_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    body: web::Json<CreateProjectRequest>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:write")?;
    let data = service::create_project(state.get_ref(), &ctx, body.into_inner()).await?;
    ok(data)
}

/// 项目详情。
pub async fn get_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:read")?;
    let project_id = path.into_inner();
    let data = service::get_project(state.get_ref(), &ctx, project_id).await?;
    ok(data)
}

/// 更新项目。
pub async fn update_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdateProjectRequest>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:write")?;
    let project_id = path.into_inner();
    let data = service::update_project(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 启用项目。
pub async fn enable_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:write")?;
    let project_id = path.into_inner();
    let data = service::enable_project(state.get_ref(), &ctx, project_id).await?;
    ok(data)
}

/// 暂停项目。
pub async fn pause_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: Option<web::Json<service::PauseProjectRequest>>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:write")?;
    let project_id = path.into_inner();
    let reason = body.and_then(|payload| payload.into_inner().reason);
    let data = service::pause_project(state.get_ref(), &ctx, project_id, reason).await?;
    ok(data)
}

/// 更新项目配额。
pub async fn update_quota(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdateQuotaRequest>,
) -> ApiResult<ProjectListItem> {
    ctx.require_permission("project:write")?;
    let project_id = path.into_inner();
    let data = service::update_quota(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 删除项目。
pub async fn delete_project(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    query: web::Query<DeleteProjectQuery>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("project:delete")?;
    let project_id = path.into_inner();
    let force = query.force;
    let data = service::delete_project(state.get_ref(), &ctx, project_id, force).await?;
    ok(data)
}
