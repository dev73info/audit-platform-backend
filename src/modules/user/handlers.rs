//! 用户接口：列表、新建、详情、修改、重置口令、项目授权。

use actix_web::web;
use serde::Deserialize;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::modules::user::repositories::UserFilters;
use crate::modules::user::service::{self, CreateUserInput, UpdateUserInput, UserView};
use crate::response::{ApiResult, ListQuery, Page, ok};

/// 新建账号入参。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    pub role_code: String,
    #[serde(default)]
    pub project_ids: Vec<u64>,
}

/// 修改账号入参。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role_code: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// 重置口令入参。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResetPasswordRequest {
    #[serde(default)]
    pub password: Option<String>,
}

/// 设置项目授权入参。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SetUserProjectsRequest {
    #[serde(default)]
    pub project_ids: Vec<u64>,
}

/// 用户列表。
pub async fn list_users(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<Page<UserView>> {
    ctx.require_permission("user:read")?;

    let filters = UserFilters {
        role: query.filter("role").map(|v| v.to_string()),
        status: query.filter("status").map(|v| v.to_string()),
        keyword: query.keyword.clone(),
    };
    let page = query.page();
    let page_size = query.page_size();

    let (items, total) = service::list_users(state.get_ref(), filters, page, page_size).await?;
    ok(Page::new(items, total, page, page_size))
}

/// 新建用户。
pub async fn create_user(
    ctx: AuthContext,
    state: web::Data<AppState>,
    body: web::Json<CreateUserRequest>,
) -> ApiResult<UserView> {
    ctx.require_permission("user:write")?;

    let input = CreateUserInput {
        username: body.username.clone(),
        password: body.password.clone(),
        display_name: body.display_name.clone(),
        email: body.email.clone(),
        role_code: body.role_code.clone(),
        project_ids: body.project_ids.clone(),
    };
    let view =
        service::create_user(state.get_ref(), input, &ctx.username, Some(ctx.user_id)).await?;
    ok(view)
}

/// 用户详情。
pub async fn get_user(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<UserView> {
    ctx.require_permission("user:read")?;
    let view = service::get_user(state.get_ref(), *path).await?;
    ok(view)
}

/// 修改用户。
pub async fn update_user(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdateUserRequest>,
) -> ApiResult<UserView> {
    ctx.require_permission("user:write")?;

    let input = UpdateUserInput {
        display_name: body.display_name.clone(),
        email: body.email.clone(),
        role_code: body.role_code.clone(),
        status: body.status.clone(),
    };
    let view = service::update_user(
        state.get_ref(),
        *path,
        input,
        &ctx.username,
        Some(ctx.user_id),
    )
    .await?;
    ok(view)
}

/// 重置口令。
pub async fn reset_password(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<ResetPasswordRequest>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("user:write")?;

    let data = service::reset_password(
        state.get_ref(),
        *path,
        body.password.as_deref(),
        &ctx.username,
        Some(ctx.user_id),
    )
    .await?;
    ok(data)
}

/// 用户被授权的项目 ID。
pub async fn list_user_projects(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<Vec<u64>> {
    ctx.require_permission("user:read")?;
    let ids = service::list_user_projects(state.get_ref(), *path).await?;
    ok(ids)
}

/// 设置用户的项目授权。
pub async fn set_user_projects(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<SetUserProjectsRequest>,
) -> ApiResult<Vec<u64>> {
    ctx.require_permission("user:write")?;

    let ids = service::set_user_projects(
        state.get_ref(),
        *path,
        body.project_ids.clone(),
        &ctx.username,
        Some(ctx.user_id),
    )
    .await?;
    ok(ids)
}
