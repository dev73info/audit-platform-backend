use actix_web::web;

use crate::modules::recycle::handlers;

/// 注册回收站路由（相对管理端 scope `/api/admin/v1`）。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recycle-bin")
            .route("", web::get().to(handlers::list))
            .route("/batch-purge", web::post().to(handlers::batch_purge))
            .route("/{id}/restore", web::post().to(handlers::restore))
            .route("/{id}/purge", web::delete().to(handlers::purge)),
    );
    cfg.service(web::scope("/cleanup-tasks").route("", web::get().to(handlers::list_cleanup_tasks)));
}
