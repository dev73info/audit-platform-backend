//! 开放 API 客户端域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。

use actix_web::web;

use super::handlers;

/// 装配开放 API 客户端域路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects/{pid}/api-clients")
            .route("", web::get().to(handlers::list_clients))
            .route("", web::post().to(handlers::create_client)),
    );
    cfg.service(
        web::scope("/api-clients/{cid}")
            .route("", web::put().to(handlers::update_client))
            .route("", web::delete().to(handlers::delete_client))
            .route("/rotate-secret", web::post().to(handlers::rotate_secret)),
    );
}
