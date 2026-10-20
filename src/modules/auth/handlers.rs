//! 认证接口：登录、刷新、登出、当前用户。

use actix_web::{HttpRequest, web};
use serde::Deserialize;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::modules::auth::service::{self, AuthTokenView, Operator, UserProfileView};
use crate::response::{ApiResult, ok};

/// 登录入参。
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub captcha: Option<String>,
    #[serde(default)]
    pub mfa_code: Option<String>,
}

/// 刷新入参。`refresh_token` 可缺省：缺省时按当前登录身份轮换最近的刷新令牌。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RefreshRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// 登出入参。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogoutRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// 登录。
pub async fn login(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> ApiResult<AuthTokenView> {
    let operator = Operator {
        name: body.username.trim().to_string(),
        id: None,
        ip: client_ip(&req),
    };
    let view = service::login(
        state.get_ref(),
        &body.username,
        &body.password,
        body.captcha.as_deref(),
        body.mfa_code.as_deref(),
        &operator,
    )
    .await?;
    ok(view)
}

/// 刷新令牌。
pub async fn refresh(
    state: web::Data<AppState>,
    body: Option<web::Json<RefreshRequest>>,
    ctx: Option<AuthContext>,
) -> ApiResult<AuthTokenView> {
    let token = body.and_then(|b| b.refresh_token.clone());
    let view = service::refresh(
        state.get_ref(),
        token.as_deref(),
        ctx.as_ref().map(|c| c.user_id),
    )
    .await?;
    ok(view)
}

/// 登出：撤销刷新令牌。
pub async fn logout(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: Option<web::Json<LogoutRequest>>,
    ctx: Option<AuthContext>,
) -> ApiResult<serde_json::Value> {
    let token = body.and_then(|b| b.refresh_token.clone());
    let operator = Operator {
        name: ctx
            .as_ref()
            .map(|c| c.username.clone())
            .unwrap_or_else(|| "anonymous".to_string()),
        id: ctx.as_ref().map(|c| c.user_id),
        ip: client_ip(&req),
    };
    service::logout(state.get_ref(), token.as_deref(), &operator).await?;
    ok(serde_json::json!({ "success": true }))
}

/// 当前登录用户。
pub async fn me(state: web::Data<AppState>, ctx: AuthContext) -> ApiResult<UserProfileView> {
    let view = service::me(state.get_ref(), ctx.user_id).await?;
    ok(view)
}

/// 取客户端 IP（优先真实远端地址）。
fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|value| value.to_string())
}
