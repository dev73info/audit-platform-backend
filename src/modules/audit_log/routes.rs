use actix_web::web;

use crate::modules::audit_log::handlers;

/// 注册审计日志路由（相对管理端 scope `/api/admin/v1`）。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/audit-logs")
            .route("", web::get().to(handlers::list))
            .route("/export", web::post().to(handlers::export)),
    );
}
