//! 项目域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。

use actix_web::web;

use super::handlers;

/// 装配项目域路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects")
            .route("", web::get().to(handlers::list_projects))
            .route("", web::post().to(handlers::create_project))
            .route("/{id}", web::get().to(handlers::get_project))
            .route("/{id}", web::put().to(handlers::update_project))
            .route("/{id}", web::delete().to(handlers::delete_project))
            .route("/{id}/enable", web::post().to(handlers::enable_project))
            .route("/{id}/pause", web::post().to(handlers::pause_project))
            .route("/{id}/quota", web::post().to(handlers::update_quota)),
    );
}
