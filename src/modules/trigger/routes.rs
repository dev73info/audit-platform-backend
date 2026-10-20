//! 触发源的路由注册。
//!
//! 端点见 `doc/API.md` 2.5。

use actix_web::web;

use crate::modules::trigger::handlers;

/// 注册本模块的路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/audits/{aid}/trigger-sources")
            .route("", web::get().to(handlers::list_triggers))
            .route("", web::post().to(handlers::create_trigger)),
    )
    .service(
        web::scope("/trigger-sources/{tid}")
            .route("", web::get().to(handlers::get_trigger))
            .route("", web::put().to(handlers::update_trigger))
            .route("", web::delete().to(handlers::delete_trigger))
            .route("/enable", web::post().to(handlers::enable_trigger))
            .route("/pause", web::post().to(handlers::pause_trigger))
            .route("/test", web::post().to(handlers::test_trigger))
            .route("/recent", web::get().to(handlers::recent_logs)),
    );
}
