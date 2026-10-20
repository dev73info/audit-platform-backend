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
fn admin_routes(cfg: &mut web::ServiceConfig) {
    auth::routes::configure(cfg);
    project::routes::configure(cfg);
    project_config::routes::configure(cfg);
    api_client::routes::configure(cfg);
    audit::routes::configure(cfg);
    trigger::routes::configure(cfg);
    task::routes::configure(cfg);
    recycle::routes::configure(cfg);
    audit_log::routes::configure(cfg);
    metrics::routes::configure(cfg);
    user::routes::configure(cfg);
}
