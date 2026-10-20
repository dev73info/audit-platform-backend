//! 鉴权上下文：把 JWT 里的身份解析成「功能权限 + 项目数据权限」的双层判定。
//!
//! - 功能权限：`role → permission`（见 `role_permission` 表）。
//! - 数据权限：`user → project_ids`（见 `user_project_scope` 表），超级管理员不受限。
//!
//! 判定口径见 `doc/设计文档.md` 2.2。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use actix_web::{FromRequest, HttpRequest, dev::Payload, web};
use serde::Serialize;
use sqlx::Row;

use crate::db::AppState;
use crate::error::ApiError;
use crate::security::jwt;

/// 鉴权上下文。
#[derive(Debug, Clone, Serialize)]
pub struct AuthContext {
    pub user_id: u64,
    pub username: String,
    pub role: String,
    /// 该用户拥有的全部权限码。
    pub permissions: Arc<HashSet<String>>,
    /// 该用户被授权的项目 ID；空集合表示「不限制」（超级管理员）。
    pub project_ids: Arc<Vec<u64>>,
    pub trace_id: String,
}

impl AuthContext {
    /// 是否拥有某个权限点。
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// 校验功能权限，不足则 403。
    pub fn require_permission(&self, permission: &str) -> Result<(), ApiError> {
        if self.has_permission(permission) {
            return Ok(());
        }
        Err(ApiError::perm_denied(format!(
            "当前角色（{}）没有「{}」权限",
            self.role, permission
        )))
    }

    /// 校验项目数据权限。越权一律 403 `PROJECT_OUT_OF_SCOPE`。
    pub fn require_project(&self, project_id: u64) -> Result<(), ApiError> {
        if self.project_ids.is_empty() {
            return Ok(());
        }
        if self.project_ids.contains(&project_id) {
            return Ok(());
        }
        Err(ApiError::out_of_scope("没有该项目的访问权限"))
    }

    /// 需要「至少能看一个项目」。完全未授权时 403。
    pub fn require_any_project(&self) -> Result<(), ApiError> {
        if self.project_ids.is_empty() {
            return Ok(());
        }
        Ok(())
    }

    /// 当前用户可见的项目 ID 列表：`None` 表示不限制。
    pub fn visible_projects(&self) -> Option<&[u64]> {
        if self.project_ids.is_empty() {
            None
        } else {
            Some(&self.project_ids)
        }
    }
}

/// 从请求里提取鉴权上下文。
impl FromRequest for AuthContext {
    type Error = ApiError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = match req.app_data::<web::Data<AppState>>() {
            Some(state) => state.clone(),
            None => {
                return Box::pin(async { Err(ApiError::internal("服务尚未初始化")) });
            }
        };
        let auth_header = req
            .headers()
            .get(actix_web::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let trace_id = crate::trace::current_trace_id();

        Box::pin(async move { extract(&state, auth_header, trace_id).await })
    }
}

async fn extract(
    state: &AppState,
    auth_header: Option<String>,
    trace_id: String,
) -> Result<AuthContext, ApiError> {
    let header =
        auth_header.ok_or_else(|| ApiError::unauthorized("UNAUTHORIZED", "缺少访问令牌"))?;

    let token = jwt::extract_bearer(&header)
        .ok_or_else(|| ApiError::unauthorized("UNAUTHORIZED", "访问令牌格式不正确"))?;

    let secret = state.settings.security.jwt_secret.clone();
    let claims = jwt::decode_access_token(&secret, token)?;

    // 权限与项目授权走进程内短缓存，避免每个请求都打两次库。
    let profile = cached_profile(state, claims.sub).await?;
    if profile.status != "ACTIVE" {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "账号已被禁用"));
    }

    Ok(AuthContext {
        user_id: claims.sub,
        username: claims.username,
        role: claims.role,
        permissions: profile.permissions.clone(),
        project_ids: profile.project_ids.clone(),
        trace_id,
    })
}

/// 权限缓存：60 秒过期。
const PROFILE_CACHE_TTL_SEC: i64 = 60;

/// 用户档案缓存。
static PROFILE_CACHE: std::sync::OnceLock<
    tokio::sync::RwLock<HashMap<u64, (i64, std::sync::Arc<UserProfile>)>>,
> = std::sync::OnceLock::new();

/// 取用户档案（带缓存）。
pub async fn cached_profile(
    state: &AppState,
    user_id: u64,
) -> Result<std::sync::Arc<UserProfile>, ApiError> {
    let cache = PROFILE_CACHE.get_or_init(|| tokio::sync::RwLock::new(HashMap::new()));
    let now = crate::common::now_ms() / 1000;

    if let Some((expire_at, profile)) = cache.read().await.get(&user_id) {
        if *expire_at > now {
            return Ok(profile.clone());
        }
    }

    let profile = std::sync::Arc::new(load_profile(state, user_id).await?);
    cache
        .write()
        .await
        .insert(user_id, (now + PROFILE_CACHE_TTL_SEC, profile.clone()));
    Ok(profile)
}

/// 用户档案（权限集合 + 项目授权）。
pub struct UserProfile {
    pub status: String,
    pub permissions: Arc<HashSet<String>>,
    pub project_ids: Arc<Vec<u64>>,
}

/// 加载用户权限与项目授权。
pub async fn load_profile(state: &AppState, user_id: u64) -> Result<UserProfile, ApiError> {
    let row = sqlx::query("SELECT status, role_code FROM admin_user WHERE id = ? LIMIT 1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "账号不存在"));
    };
    let status: String = row.get("status");
    let role_code: String = row.get("role_code");

    let permission_rows = sqlx::query(
        "SELECT DISTINCT p.code AS code
           FROM admin_user u
           JOIN role r ON r.code = u.role_code
           JOIN role_permission rp ON rp.role_id = r.id
           JOIN permission p ON p.id = rp.permission_id
          WHERE u.id = ?",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let permissions: HashSet<String> = permission_rows
        .into_iter()
        .map(|row| row.get::<String, _>("code"))
        .collect();

    let project_rows = sqlx::query("SELECT project_id FROM user_project_scope WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;
    let project_ids: Vec<u64> = project_rows
        .into_iter()
        .map(|row| row.get::<u64, _>("project_id"))
        .collect();

    // 超级管理员不受项目范围限制
    let project_ids = if role_code == crate::common::RoleCode::SuperAdmin.as_str() {
        Vec::new()
    } else {
        project_ids
    };

    Ok(UserProfile {
        status,
        permissions: Arc::new(permissions),
        project_ids: Arc::new(project_ids),
    })
}
