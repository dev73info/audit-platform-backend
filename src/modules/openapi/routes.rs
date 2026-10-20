use actix_web::web;

use crate::modules::openapi::handlers;

/// 注册开放 API 路由（挂在 `/open/v1` scope 下）。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/projects/{pid}/audits/{aid}")
            .route("/submit", web::post().to(handlers::submit))
            .route("/poll", web::get().to(handlers::poll)),
    );
    cfg.service(
        web::scope("/projects/{pid}/tasks/{task_id}").route("", web::get().to(handlers::get_task)),
    );
    cfg.service(web::scope("/callbacks").route("/register", web::post().to(handlers::register_callback)));
    cfg.service(
        web::scope("/ws/projects/{pid}/audits/{aid}").route("", web::get().to(handlers::websocket)),
    );
}
