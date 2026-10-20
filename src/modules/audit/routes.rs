//! 审核配置域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。

use actix_web::web;

use super::handlers;

/// 装配审核配置域路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects/{pid}/audits")
            .route("", web::get().to(handlers::list_audits))
            .route("", web::post().to(handlers::create_audit)),
    );
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
    cfg.service(
        web::scope("/rules/{rid}")
            .route("", web::get().to(handlers::get_rule))
            .route("", web::put().to(handlers::update_rule))
            .route("", web::delete().to(handlers::delete_rule)),
    );
}
