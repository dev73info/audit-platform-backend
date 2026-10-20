//! 用户路由（挂在管理端 `/api/admin/v1` 下）。

use actix_web::web;

use crate::modules::user::handlers;

/// 注册用户路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("", web::get().to(handlers::list_users))
            .route("", web::post().to(handlers::create_user))
            .route("/{id}", web::get().to(handlers::get_user))
            .route("/{id}", web::put().to(handlers::update_user))
            .route(
                "/{id}/reset-password",
                web::post().to(handlers::reset_password),
            )
            .route(
                "/{id}/projects",
                web::get().to(handlers::list_user_projects),
            )
            .route("/{id}/projects", web::put().to(handlers::set_user_projects)),
    );
}
