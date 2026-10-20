use actix_web::web;

use crate::modules::metrics::handlers;

/// 注册监控与通知路由（相对管理端 scope `/api/admin/v1`）。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/metrics")
            .route("/overview", web::get().to(handlers::overview))
            .route("/alerts", web::get().to(handlers::alerts)),
    );
    cfg.service(
        web::scope("/notifications")
            .route("", web::get().to(handlers::notifications))
            .route("/read-all", web::post().to(handlers::read_all))
            .route("/{id}/read", web::post().to(handlers::read_notification)),
    );
}
