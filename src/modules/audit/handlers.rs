//! 审核配置域的 HTTP 层：参数解析、响应映射与权限判定。
//!
//! 业务校验与事务都在 `service.rs`，这里只做「取参数 → 判权限 → 调服务 → 包响应」。

use actix_web::web;
use serde::Deserialize;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::audit::{
    AuditRuleView, AuditView, ResultRouteView, SaveAuditRequest, SaveRuleRequest,
};
use crate::response::{ApiResult, ListQuery, Page, ok};

use super::service;

/// 审核列表。
pub async fn list_audits(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    query: web::Query<ListQuery>,
) -> ApiResult<Page<AuditView>> {
    ctx.require_permission("audit:read")?;
    let project_id = path.into_inner();
    let data = service::list_audits(state.get_ref(), &ctx, project_id, &query).await?;
    ok(data)
}

/// 新建审核。
pub async fn create_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SaveAuditRequest>,
) -> ApiResult<AuditView> {
    ctx.require_permission("audit:write")?;
    let project_id = path.into_inner();
    let data = service::create_audit(state.get_ref(), &ctx, project_id, body.into_inner()).await?;
    ok(data)
}

/// 审核详情。
pub async fn get_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<service::AuditDetail> {
    ctx.require_permission("audit:read")?;
    let audit_id = path.into_inner();
    let data = service::get_audit(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 更新审核。
pub async fn update_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SaveAuditRequest>,
) -> ApiResult<AuditView> {
    ctx.require_permission("audit:write")?;
    let audit_id = path.into_inner();
    let data = service::update_audit(state.get_ref(), &ctx, audit_id, body.into_inner()).await?;
    ok(data)
}

/// 删除审核。
pub async fn delete_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("audit:delete")?;
    let audit_id = path.into_inner();
    let data = service::delete_audit(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 启用审核。
pub async fn enable_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<AuditView> {
    ctx.require_permission("audit:write")?;
    let audit_id = path.into_inner();
    let data = service::enable_audit(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 暂停审核。
pub async fn pause_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<AuditView> {
    ctx.require_permission("audit:write")?;
    let audit_id = path.into_inner();
    let data = service::pause_audit(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 克隆审核。
pub async fn clone_audit(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<AuditView> {
    ctx.require_permission("audit:write")?;
    let audit_id = path.into_inner();
    let data = service::clone_audit(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 审核下的规则组列表。
pub async fn list_rules(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<crate::response::Page<AuditRuleView>> {
    ctx.require_permission("rule:read")?;
    let audit_id = path.into_inner();
    let data = service::list_rules(state.get_ref(), &ctx, audit_id).await?;
    let total = data.len() as u64;
    ok(crate::response::Page::new(data, total, 1, total.max(1)))
}

/// 新建规则组。
pub async fn create_rule(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SaveRuleRequest>,
) -> ApiResult<AuditRuleView> {
    ctx.require_permission("rule:write")?;
    let audit_id = path.into_inner();
    let data = service::create_rule(state.get_ref(), &ctx, audit_id, body.into_inner()).await?;
    ok(data)
}

/// 规则组详情。
pub async fn get_rule(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<AuditRuleView> {
    ctx.require_permission("rule:read")?;
    let rule_id = path.into_inner();
    let data = service::get_rule(state.get_ref(), &ctx, rule_id).await?;
    ok(data)
}

/// 更新规则组。
pub async fn update_rule(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SaveRuleRequest>,
) -> ApiResult<AuditRuleView> {
    ctx.require_permission("rule:write")?;
    let rule_id = path.into_inner();
    let data = service::update_rule(state.get_ref(), &ctx, rule_id, body.into_inner()).await?;
    ok(data)
}

/// 删除规则组。
pub async fn delete_rule(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("rule:write")?;
    let rule_id = path.into_inner();
    let data = service::delete_rule(state.get_ref(), &ctx, rule_id).await?;
    ok(data)
}

/// 规则试跑。
pub async fn dry_run(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<service::DryRunRequest>,
) -> ApiResult<crate::models::rule::DryRunResult> {
    ctx.require_permission("rule:read")?;
    let audit_id = path.into_inner();
    let request = body.into_inner();
    let data = service::dry_run(state.get_ref(), &ctx, audit_id, request.sample).await?;
    ok(data)
}

/// 审核下的结果路由。
pub async fn list_routes(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<std::collections::HashMap<String, ResultRouteView>> {
    ctx.require_permission("route:read")?;
    let audit_id = path.into_inner();
    let data = service::list_routes(state.get_ref(), &ctx, audit_id).await?;
    ok(data)
}

/// 结果路由路径参数。
#[derive(Debug, Deserialize)]
pub struct RoutePath {
    pub aid: u64,
    pub rtype: String,
}

/// 保存单条结果路由。
pub async fn put_route(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<RoutePath>,
    body: web::Json<ResultRouteView>,
) -> ApiResult<ResultRouteView> {
    ctx.require_permission("route:write")?;
    let route_path = path.into_inner();
    let data = service::put_route(
        state.get_ref(),
        &ctx,
        route_path.aid,
        &route_path.rtype,
        body.into_inner(),
    )
    .await?;
    ok(data)
}

/// 应用路由模板。
pub async fn apply_route_template(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<service::ApplyRouteTemplateRequest>,
) -> ApiResult<std::collections::HashMap<String, ResultRouteView>> {
    ctx.require_permission("route:write")?;
    let audit_id = path.into_inner();
    let data =
        service::apply_route_template(state.get_ref(), &ctx, audit_id, body.into_inner()).await?;
    ok(data)
}

/// 预览路由渲染结果。
pub async fn preview_route(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<service::PreviewRouteRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("route:read")?;
    let audit_id = path.into_inner();
    let data = service::preview_route(state.get_ref(), &ctx, audit_id, body.into_inner()).await?;
    ok(data)
}
