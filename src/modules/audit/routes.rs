//! 审核配置域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。
//!
//! **注册顺序有讲究**：actix 的 `web::scope` 是**前缀匹配**，
//! 同一个 ResourceMap 节点上多个 scope 命中时按注册先后决定，
//! 后注册的宽 scope（`/audits/{aid}`）会吃掉先注册的深 scope
//! （`/audits/{aid}/trigger-sources`）。
//! 所以本模块把 scope 拆成两个注册入口，由 `modules::admin_routes` 按
//! 「深路径先、宽路径后」装配。

use actix_web::web;

use super::handlers;

/// 装配审核配置域的**深路径**路由。
///
/// 这些 scope 的路径比 `/audits/{aid}` 更具体，必须先于宽 scope 注册。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects/{pid}/audits")
            .route("", web::get().to(handlers::list_audits))
            .route("", web::post().to(handlers::create_audit)),
    );
    cfg.service(
        web::scope("/rules/{rid}")
            .route("", web::get().to(handlers::get_rule))
            .route("", web::put().to(handlers::update_rule))
            .route("", web::delete().to(handlers::delete_rule)),
    );
}

/// 装配审核配置域的**宽路径**路由（`/audits/{aid}`）。
///
/// 必须在所有以 `/audits/{aid}/` 开头的深 scope 之后注册。
pub fn configure_audit_scope(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/audits/{aid}")
            .route("", web::get().to(handlers::get_audit))
            .route("", web::put().to(handlers::update_audit))
            .route("", web::delete().to(handlers::delete_audit))
            .route("/enable", web::post().to(handlers::enable_audit))
            .route("/pause", web::post().to(handlers::pause_audit))
            .route("/clone", web::post().to(handlers::clone_audit))
            .route("/rules", web::get().to(handlers::list_rules))
            .route("/rules", web::post().to(handlers::create_rule))
            .route("/rules/dry-run", web::post().to(handlers::dry_run))
            .route("/routes", web::get().to(handlers::list_routes))
            .route("/routes/{rtype}", web::put().to(handlers::put_route))
            .route(
                "/routes/apply-template",
                web::post().to(handlers::apply_route_template),
            )
            .route("/routes/preview", web::post().to(handlers::preview_route)),
    );
}
