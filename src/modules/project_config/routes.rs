//! 项目连接配置域的路由表。
//!
//! 路径是相对管理端 scope（`/api/admin/v1`）的相对路径。

use actix_web::web;

use super::handlers;

/// 装配项目连接配置域路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects/{pid}/configs")
            .route("", web::get().to(handlers::list_configs))
            .route("", web::post().to(handlers::create_config))
            .route("/test", web::post().to(handlers::test_config))
            .route("/{cid}", web::get().to(handlers::get_config))
            .route("/{cid}", web::put().to(handlers::update_config))
            .route("/{cid}", web::delete().to(handlers::delete_config))
            .route("/{cid}/rollback", web::post().to(handlers::rollback_config))
            .route("/{cid}/versions", web::get().to(handlers::list_versions))
            .route("/{cid}/reveal", web::post().to(handlers::reveal_config)),
    );
}
