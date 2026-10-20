//! 认证路由（挂在管理端 `/api/admin/v1` 下）。

use actix_web::web;

use crate::modules::auth::handlers;

/// 注册认证路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(handlers::login))
            .route("/refresh", web::post().to(handlers::refresh))
            .route("/logout", web::post().to(handlers::logout))
            .route("/me", web::get().to(handlers::me)),
    );
}
