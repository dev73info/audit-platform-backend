//! 任务域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。

use actix_web::web;

use super::handlers;

/// 装配任务域路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tasks")
            .route("", web::get().to(handlers::list_tasks))
            .route("/batch-retry", web::post().to(handlers::batch_retry))
            .route("/export", web::post().to(handlers::export_tasks))
            .route("/{id}", web::get().to(handlers::get_task))
            .route("/{id}/retry", web::post().to(handlers::retry_task))
            .route("/{id}/retry-action", web::post().to(handlers::retry_action))
            .route("/{id}/stop", web::post().to(handlers::stop_task))
            .route("/{id}/review", web::post().to(handlers::review_task)),
    );
    cfg.service(
        web::scope("/reviews")
            .route("", web::get().to(handlers::list_reviews))
            .route("/{task_id}", web::get().to(handlers::get_review)),
    );
}
