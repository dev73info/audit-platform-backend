//! 认证业务编排：登录校验、令牌签发与轮换、登出。
//!
//! 校验顺序见 `doc/API.md` 2.1：账号存在 → 账号状态 → 口令 → 验证码 → 二次验证。

use chrono::Duration;
use serde::Serialize;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AuditLogEntry;
use crate::modules::auth::repositories::{self, AdminUserRow};
use crate::security::{jwt, password};

/// 访问令牌有效期（秒）：2 小时。
pub const ACCESS_TOKEN_TTL: i64 = 7200;
/// 刷新令牌有效期（秒）：7 天。
pub const REFRESH_TOKEN_TTL: i64 = 60 * 60 * 24 * 7;

/// 图形验证码的临时固定值。
/// TODO: 接入真实验证码（图片验证码 + 会话存储）后替换本常量。
const CAPTCHA_FALLBACK: &str = "1234";

/// 操作者信息（写审计日志用）。
#[derive(Debug, Clone, Default)]
pub struct Operator {
    pub name: String,
    pub id: Option<u64>,
    pub ip: Option<String>,
}

/// 用户档案（登录与 `/auth/me` 共用）。
#[derive(Debug, Clone, Serialize)]
pub struct UserProfileView {
    pub id: u64,
    pub username: String,
    pub display_name: Option<String>,
    pub role: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub projects: Vec<u64>,
}

/// 登录 / 刷新响应体。
#[derive(Debug, Clone, Serialize)]
pub struct AuthTokenView {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserProfileView,
}

/// 登录。
pub async fn login(
    state: &AppState,
    username: &str,
    password_plain: &str,
    captcha: Option<&str>,
    mfa_code: Option<&str>,
    operator: &Operator,
) -> Result<AuthTokenView, ApiError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(ApiError::invalid_param(
            "登录参数不合法",
            vec![crate::error::FieldError::new("username", "用户名不能为空")],
        ));
    }
    if password_plain.is_empty() {
        return Err(ApiError::invalid_param(
            "登录参数不合法",
            vec![crate::error::FieldError::new("password", "密码不能为空")],
        ));
    }

    let Some(user) = repositories::find_user_by_username(state, username).await? else {
        write_login_failed(state, operator, username, "账号不存在").await;
        return Err(ApiError::unauthorized("UNAUTHORIZED", "用户名或密码错误"));
    };

    // 账号状态：锁定未过期直接拒绝；锁定已过期视为正常，继续校验口令。
    match user.status.as_str() {
        "ACTIVE" => {}
        "LOCKED" => {
            let now = chrono::Utc::now().naive_utc();
            let lock_expired = user.locked_until.map(|until| until <= now).unwrap_or(true);
            if !lock_expired {
                write_login_failed(state, operator, username, "账号已锁定").await;
                return Err(ApiError::unauthorized(
                    "ACCOUNT_LOCKED",
                    "账号已被锁定，请稍后再试",
                ));
            }
        }
        _ => {
            write_login_failed(state, operator, username, "账号已禁用").await;
            return Err(ApiError::unauthorized("UNAUTHORIZED", "账号已被禁用"));
        }
    }

    // 口令校验。
    if !password::verify_password(password_plain, &user.password_hash) {
        return Err(record_login_failure(state, &user, operator).await);
    }

    // 连续失败达到阈值后要求图形验证码。
    let captcha_after = state.settings.security.captcha_after_failures;
    if captcha_after > 0 && user.fail_count >= captcha_after {
        let captcha = captcha.unwrap_or("").trim();
        if captcha.is_empty() {
            return Err(ApiError::BadRequest {
                code: "CAPTCHA_REQUIRED",
                message: "连续登录失败次数过多，请输入图形验证码".to_string(),
                field_errors: Vec::new(),
            });
        }
        if captcha != CAPTCHA_FALLBACK {
            return Err(ApiError::bad_request("图形验证码不正确"));
        }
    }

    // 开启二次验证的账号必须带动态验证码。
    // TODO: 接入真实 TOTP 校验（当前只校验非空）。
    if user.mfa_enabled != 0 {
        let code = mfa_code.unwrap_or("").trim();
        if code.is_empty() {
            return Err(ApiError::unauthorized("MFA_REQUIRED", "请输入动态验证码"));
        }
    }

    // 登录成功：清零失败次数、记录登录信息。
    repositories::mark_login_success(state, user.id, operator.ip.as_deref()).await?;
    // 顺手清理过期的刷新令牌。
    if let Err(err) = repositories::delete_expired_refresh_tokens(state).await {
        tracing::warn!(error = %err, "清理过期刷新令牌失败");
    }

    let view = issue_tokens(state, &user).await?;

    // 审计日志：登录成功。
    let _ = repositories::write_audit_log(
        state,
        AuditLogEntry {
            operator: user.username.clone(),
            operator_id: Some(user.id),
            operator_ip: operator.ip.clone(),
            action: "LOGIN".to_string(),
            object_type: Some("USER".to_string()),
            object_id: Some(user.id.to_string()),
            result: "SUCCESS".to_string(),
            detail: Some(serde_json::json!({ "role": user.role_code })),
            trace_id: Some(crate::trace::current_trace_id()),
            ..Default::default()
        },
    )
    .await;

    Ok(view)
}

/// 刷新令牌：轮换（撤销旧的、发新的）。
pub async fn refresh(
    state: &AppState,
    refresh_token: Option<&str>,
    fallback_user_id: Option<u64>,
) -> Result<AuthTokenView, ApiError> {
    let now = chrono::Utc::now().naive_utc();

    let row = match refresh_token.map(str::trim).filter(|v| !v.is_empty()) {
        Some(plain) => {
            let hash = crate::security::signature::sha256_hex(plain.as_bytes());
            repositories::find_refresh_token(state, &hash).await?
        }
        // 没有传刷新令牌时，退化为「用当前登录身份轮换最近一条有效的刷新令牌」。
        None => match fallback_user_id {
            Some(user_id) => repositories::find_latest_active_refresh_token(state, user_id).await?,
            None => None,
        },
    };

    let Some(row) = row else {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "刷新令牌无效"));
    };
    if row.revoked_at.is_some() {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "刷新令牌已失效"));
    }
    if row.expires_at <= now {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "刷新令牌已过期"));
    }

    let Some(user) = repositories::find_user_by_id(state, row.user_id).await? else {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "账号不存在"));
    };
    if user.status != "ACTIVE" {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "账号已被禁用"));
    }

    // 轮换：撤销旧的，写入新的。
    repositories::revoke_refresh_token(state, &row.token_hash).await?;
    let view = issue_tokens(state, &user).await?;
    Ok(view)
}

/// 登出：撤销刷新令牌。
pub async fn logout(
    state: &AppState,
    refresh_token: Option<&str>,
    operator: &Operator,
) -> Result<(), ApiError> {
    match refresh_token.map(str::trim).filter(|v| !v.is_empty()) {
        Some(plain) => {
            let hash = crate::security::signature::sha256_hex(plain.as_bytes());
            repositories::revoke_refresh_token(state, &hash).await?;
        }
        // 没带刷新令牌时，撤销该用户全部未撤销的刷新令牌。
        None => {
            if let Some(user_id) = operator.id {
                repositories::revoke_user_refresh_tokens(state, user_id).await?;
            }
        }
    }

    let _ = repositories::write_audit_log(
        state,
        AuditLogEntry {
            operator: operator.name.clone(),
            operator_id: operator.id,
            operator_ip: operator.ip.clone(),
            action: "LOGOUT".to_string(),
            object_type: Some("USER".to_string()),
            object_id: operator.id.map(|id| id.to_string()),
            result: "SUCCESS".to_string(),
            detail: None,
            trace_id: Some(crate::trace::current_trace_id()),
            ..Default::default()
        },
    )
    .await;

    Ok(())
}

/// 当前登录用户的信息。
pub async fn me(state: &AppState, user_id: u64) -> Result<UserProfileView, ApiError> {
    let user = repositories::find_user_by_id(state, user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("UNAUTHORIZED", "账号不存在"))?;
    build_profile(state, &user).await
}

/// 组装用户档案：权限码 + 项目授权。
async fn build_profile(state: &AppState, user: &AdminUserRow) -> Result<UserProfileView, ApiError> {
    let permissions = repositories::list_role_permissions(state, &user.role_code).await?;
    let projects = if user.role_code == crate::common::RoleCode::SuperAdmin.as_str() {
        // 超级管理员可见全部在用项目。
        repositories::list_active_project_ids(state).await?
    } else {
        repositories::list_user_project_ids(state, user.id).await?
    };

    Ok(UserProfileView {
        id: user.id,
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        role: user.role_code.clone(),
        roles: vec![user.role_code.clone()],
        permissions,
        projects,
    })
}

/// 签发访问令牌 + 刷新令牌，并返回完整响应体。
async fn issue_tokens(state: &AppState, user: &AdminUserRow) -> Result<AuthTokenView, ApiError> {
    let secret = state.settings.security.jwt_secret.clone();
    let access_token = jwt::encode_access_token(
        &secret,
        user.id,
        &user.username,
        &user.role_code,
        ACCESS_TOKEN_TTL,
    )?;

    let refresh_plain = generate_refresh_token();
    let refresh_hash = crate::security::signature::sha256_hex(refresh_plain.as_bytes());
    let expires_at = chrono::Utc::now().naive_utc() + Duration::seconds(REFRESH_TOKEN_TTL);
    repositories::insert_refresh_token(state, user.id, &refresh_hash, expires_at).await?;

    let user_view = build_profile(state, user).await?;

    Ok(AuthTokenView {
        access_token,
        refresh_token: refresh_plain,
        expires_in: ACCESS_TOKEN_TTL,
        user: user_view,
    })
}

/// 生成 32 字节随机刷新令牌（base64 串）。
fn generate_refresh_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 记录一次登录失败：累加失败次数、达到阈值则锁定，并返回要抛出的错误。
async fn record_login_failure(
    state: &AppState,
    user: &AdminUserRow,
    operator: &Operator,
) -> ApiError {
    let fail_count = user.fail_count + 1;
    let lock_after = state.settings.security.lock_after_failures;
    let lock_minutes = state.settings.security.lock_minutes;

    let locked_until = if lock_after > 0 && fail_count >= lock_after {
        Some(chrono::Utc::now().naive_utc() + Duration::minutes(lock_minutes.max(1)))
    } else {
        None
    };

    if let Err(err) =
        repositories::increase_fail_count(state, user.id, fail_count, locked_until).await
    {
        tracing::error!(error = %err, "更新登录失败次数失败");
    }

    write_login_failed(
        state,
        operator,
        &user.username,
        if locked_until.is_some() {
            "口令错误，账号已被锁定"
        } else {
            "口令错误"
        },
    )
    .await;

    if locked_until.is_some() {
        ApiError::unauthorized("ACCOUNT_LOCKED", "连续登录失败次数过多，账号已被锁定")
    } else {
        ApiError::unauthorized("UNAUTHORIZED", "用户名或密码错误")
    }
}

/// 写登录失败审计日志（失败本身不再抛错，避免掩盖真正的错误）。
async fn write_login_failed(state: &AppState, operator: &Operator, username: &str, reason: &str) {
    let mut entry = AuditLogEntry {
        operator: username.to_string(),
        operator_id: operator.id,
        operator_ip: operator.ip.clone(),
        action: "LOGIN_FAILED".to_string(),
        object_type: Some("USER".to_string()),
        result: "FAIL".to_string(),
        detail: Some(serde_json::json!({ "reason": reason })),
        trace_id: Some(crate::trace::current_trace_id()),
        ..Default::default()
    };
    if entry.operator.is_empty() {
        entry.operator = "anonymous".to_string();
    }
    if let Err(err) = repositories::write_audit_log(state, entry).await {
        tracing::error!(error = %err, "写登录失败审计日志失败");
    }
}
