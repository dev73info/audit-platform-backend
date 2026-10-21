//! 业务模块集合。路由装配集中在这里，各模块自己的路由在自己的 `routes.rs` 里。

pub mod api_client;
pub mod audit;
pub mod audit_log;
pub mod auth;
pub mod bootstrap;
pub mod metrics;
pub mod openapi;
pub mod project;
pub mod project_config;
pub mod recycle;
pub mod task;
pub mod trigger;
pub mod user;

use actix_web::web;

/// 管理端 API 前缀。
pub const ADMIN_API_PREFIX: &str = "/api/admin/v1";
/// 开放 API 前缀。
pub const OPEN_API_PREFIX: &str = "/open/v1";

/// 装配全部路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope(ADMIN_API_PREFIX).configure(admin_routes));
    cfg.service(web::scope(OPEN_API_PREFIX).configure(openapi::routes::configure));
}

/// 管理端路由。
///
/// **装配顺序不能随意改**：actix 的 `web::scope` 是前缀匹配，
/// 同一 ResourceMap 节点上的多个 scope 命中时按注册先后决定。
/// 例如 `scope("/projects")` 是 `scope("/projects/{pid}/audits")` 的前缀，
/// 谁先注册谁优先命中。所以这里按「**路径越具体越先注册**」排列：
///
/// | 顺序 | scope | 所属节点 |
/// |---|---|---|
/// | 1 | `/projects/{pid}/configs` | projects |
/// | 2 | `/projects/{pid}/api-clients` | projects |
/// | 3 | `/projects/{pid}/audits` | projects |
/// | 4 | `/audits/{aid}/trigger-sources` | audits |
/// | 5 | `/audits/{aid}` | audits |
/// | 6 | `/projects` | projects |
///
/// 新增 scope 时按这个表插入，别直接追加到末尾。
fn admin_routes(cfg: &mut web::ServiceConfig) {
    // —— projects 节点：先深后浅 ——
    project_config::routes::configure(cfg);
    api_client::routes::configure(cfg);
    audit::routes::configure(cfg);

    // —— audits 节点：先深后浅 ——
    trigger::routes::configure(cfg);
    audit::routes::configure_audit_scope(cfg);

    // —— projects 节点的宽 scope（必须在前面的深 scope 之后）——
    project::routes::configure(cfg);

    // —— 其它互不冲突的 scope ——
    auth::routes::configure(cfg);
    task::routes::configure(cfg);
    recycle::routes::configure(cfg);
    audit_log::routes::configure(cfg);
    metrics::routes::configure(cfg);
    user::routes::configure(cfg);
}
