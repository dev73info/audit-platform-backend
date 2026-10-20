//! 认证模块的数据访问层：账号、角色权限、刷新令牌、审计日志。
//!
//! SQL 只出现在本文件；上层（service / handlers）不直接碰数据库。

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AuditLogEntry;

/// `admin_user` 的列清单。
const USER_COLUMNS: &str = "id, username, password_hash, mfa_enabled, email, display_name, \
     role_code, status, fail_count, locked_until, last_login_at, last_login_ip, created_at";

/// 账号行。
#[derive(Debug, Clone, FromRow)]
pub struct AdminUserRow {
    pub id: u64,
    pub username: String,
    /// Argon2id 哈希串。
    pub password_hash: String,
    /// 是否开启二次验证（0 / 1）。
    pub mfa_enabled: i32,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub role_code: String,
    /// `ACTIVE` / `LOCKED` / `DISABLED`。
    pub status: String,
    pub fail_count: i32,
    pub locked_until: Option<NaiveDateTime>,
    pub last_login_at: Option<NaiveDateTime>,
    pub last_login_ip: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 刷新令牌行。
#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenRow {
    pub id: u64,
    pub user_id: u64,
    /// sha256 十六进制摘要。
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// 权限码行。
#[derive(Debug, Clone, FromRow)]
pub struct PermissionCodeRow {
    pub code: String,
}

/// 项目 ID 行。
#[derive(Debug, Clone, FromRow)]
pub struct IdRow {
    pub id: u64,
}

/// 按用户名查账号。
pub async fn find_user_by_username(
    state: &AppState,
    username: &str,
) -> Result<Option<AdminUserRow>, ApiError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM admin_user WHERE username = ? LIMIT 1");
    Ok(sqlx::query_as::<_, AdminUserRow>(&sql)
        .bind(username)
        .fetch_optional(&state.db)
        .await?)
}

/// 按 ID 查账号。
pub async fn find_user_by_id(
    state: &AppState,
    user_id: u64,
) -> Result<Option<AdminUserRow>, ApiError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM admin_user WHERE id = ? LIMIT 1");
    Ok(sqlx::query_as::<_, AdminUserRow>(&sql)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?)
}

/// 查角色对应的全部权限码（`role` → `role_permission` → `permission`）。
pub async fn list_role_permissions(
    state: &AppState,
    role_code: &str,
) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query_as::<_, PermissionCodeRow>(
        "SELECT DISTINCT p.code AS code
           FROM role r
           JOIN role_permission rp ON rp.role_id = r.id
           JOIN permission p ON p.id = rp.permission_id
          WHERE r.code = ?
          ORDER BY p.code",
    )
    .bind(role_code)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|row| row.code).collect())
}

/// 查用户被授权的项目 ID。
pub async fn list_user_project_ids(state: &AppState, user_id: u64) -> Result<Vec<u64>, ApiError> {
    let rows = sqlx::query_as::<_, IdRow>(
        "SELECT project_id AS id FROM user_project_scope WHERE user_id = ? ORDER BY project_id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

/// 查全部在用（ACTIVE 且未删除）的项目 ID。
pub async fn list_active_project_ids(state: &AppState) -> Result<Vec<u64>, ApiError> {
    let rows = sqlx::query_as::<_, IdRow>(
        "SELECT id FROM project WHERE status = 'ACTIVE' AND deleted_at IS NULL ORDER BY id",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

/// 累加登录失败次数；`locked_until` 非空时同时写入锁定时间。
pub async fn increase_fail_count(
    state: &AppState,
    user_id: u64,
    fail_count: i32,
    locked_until: Option<NaiveDateTime>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE admin_user
            SET fail_count = ?,
                locked_until = COALESCE(?, locked_until)
          WHERE id = ?",
    )
    .bind(fail_count)
    .bind(locked_until)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 登录成功：清零失败次数、解除锁定、记录登录时间与来源 IP。
pub async fn mark_login_success(
    state: &AppState,
    user_id: u64,
    client_ip: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE admin_user
            SET fail_count = 0,
                locked_until = NULL,
                status = 'ACTIVE',
                last_login_at = ?,
                last_login_ip = ?
          WHERE id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(client_ip)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 写入一条刷新令牌（只存 sha256 摘要）。
pub async fn insert_refresh_token(
    state: &AppState,
    user_id: u64,
    token_hash: &str,
    expires_at: NaiveDateTime,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO refresh_token (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 按摘要查刷新令牌。
pub async fn find_refresh_token(
    state: &AppState,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, ApiError> {
    Ok(sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
           FROM refresh_token
          WHERE token_hash = ?
          LIMIT 1",
    )
    .bind(token_hash)
    .fetch_optional(&state.db)
    .await?)
}

/// 查某个用户最近一条未撤销且未过期的刷新令牌。
pub async fn find_latest_active_refresh_token(
    state: &AppState,
    user_id: u64,
) -> Result<Option<RefreshTokenRow>, ApiError> {
    Ok(sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
           FROM refresh_token
          WHERE user_id = ?
            AND revoked_at IS NULL
            AND expires_at > ?
          ORDER BY id DESC
          LIMIT 1",
    )
    .bind(user_id)
    .bind(chrono::Utc::now().naive_utc())
    .fetch_optional(&state.db)
    .await?)
}

/// 撤销指定摘要的刷新令牌。
pub async fn revoke_refresh_token(state: &AppState, token_hash: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE refresh_token SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(token_hash)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 撤销某个用户全部未撤销的刷新令牌。
pub async fn revoke_user_refresh_tokens(state: &AppState, user_id: u64) -> Result<(), ApiError> {
    sqlx::query("UPDATE refresh_token SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(chrono::Utc::now().naive_utc())
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 清理已过期的刷新令牌。
pub async fn delete_expired_refresh_tokens(state: &AppState) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM refresh_token WHERE expires_at < ?")
        .bind(chrono::Utc::now().naive_utc())
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 写审计日志（各模块共用）。
pub async fn write_audit_log(state: &AppState, entry: AuditLogEntry) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_log (id, project_id, operator, operator_id, operator_ip, action,
                                object_type, object_id, result, detail_json, trace_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(entry.project_id)
    .bind(entry.operator)
    .bind(entry.operator_id)
    .bind(entry.operator_ip)
    .bind(entry.action)
    .bind(entry.object_type)
    .bind(entry.object_id)
    .bind(entry.result)
    .bind(entry.detail)
    .bind(entry.trace_id)
    .execute(&state.db)
    .await?;
    Ok(())
}
