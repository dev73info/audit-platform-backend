//! 用户模块的数据访问层：账号查询、创建、修改、项目授权。
//!
//! SQL 只出现在本文件；上层（service / handlers）不直接碰数据库。

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::db::AppState;
use crate::error::ApiError;

/// `admin_user` 的列清单。
const USER_COLUMNS: &str = "id, username, display_name, email, role_code, status, fail_count, \
     locked_until, last_login_at, last_login_ip, created_at";

/// 列表筛选条件。
#[derive(Debug, Clone, Default)]
pub struct UserFilters {
    /// 角色编码。
    pub role: Option<String>,
    /// 账号状态。
    pub status: Option<String>,
    /// 关键字：匹配用户名 / 姓名 / 邮箱。
    pub keyword: Option<String>,
}

/// 账号行。
#[derive(Debug, Clone, FromRow)]
pub struct AdminUserRow {
    pub id: u64,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role_code: String,
    pub status: String,
    pub fail_count: i32,
    pub locked_until: Option<NaiveDateTime>,
    pub last_login_at: Option<NaiveDateTime>,
    pub last_login_ip: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 用户项目授权行。
#[derive(Debug, Clone, FromRow)]
pub struct UserScopeRow {
    pub user_id: u64,
    pub project_id: u64,
}

/// 项目 ID 行。
#[derive(Debug, Clone, FromRow)]
pub struct IdRow {
    pub id: u64,
}

/// 列表筛选条件（拼在 `admin_user u` 之后）。
const FILTER_WHERE: &str = "(? IS NULL OR u.role_code = ?) \
     AND (? IS NULL OR u.status = ?) \
     AND (? IS NULL OR u.username LIKE ? OR u.display_name LIKE ? OR u.email LIKE ?)";

/// 统计符合条件的账号数。
pub async fn count_users(state: &AppState, filters: &UserFilters) -> Result<u64, ApiError> {
    let sql = format!("SELECT COUNT(*) AS total FROM admin_user u WHERE {FILTER_WHERE}");
    let (role, status, keyword, pattern) = filter_values(filters);
    let total: i64 = sqlx::query_scalar(&sql)
        .bind(role.clone())
        .bind(role)
        .bind(status.clone())
        .bind(status)
        .bind(keyword.clone())
        .bind(pattern.clone())
        .bind(pattern.clone())
        .bind(pattern)
        .fetch_one(&state.db)
        .await?;
    Ok(total.max(0) as u64)
}

/// 查一页账号。
pub async fn list_users(
    state: &AppState,
    filters: &UserFilters,
    limit: u64,
    offset: u64,
) -> Result<Vec<AdminUserRow>, ApiError> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM admin_user u WHERE {FILTER_WHERE} \
         ORDER BY u.created_at DESC, u.id DESC LIMIT ? OFFSET ?"
    );
    let (role, status, keyword, pattern) = filter_values(filters);
    let rows = sqlx::query_as::<_, AdminUserRow>(&sql)
        .bind(role.clone())
        .bind(role)
        .bind(status.clone())
        .bind(status)
        .bind(keyword.clone())
        .bind(pattern.clone())
        .bind(pattern.clone())
        .bind(pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
    Ok(rows)
}

/// 查一批用户的项目授权。
pub async fn list_scope_rows(
    state: &AppState,
    user_ids: &[u64],
) -> Result<Vec<UserScopeRow>, ApiError> {
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT user_id, project_id FROM user_project_scope WHERE user_id IN ({}) \
         ORDER BY user_id, project_id",
        placeholders(user_ids.len())
    );
    let mut query = sqlx::query_as::<_, UserScopeRow>(&sql);
    for id in user_ids {
        query = query.bind(*id);
    }
    Ok(query.fetch_all(&state.db).await?)
}

/// 按 ID 查账号。
pub async fn find_user_by_id(
    state: &AppState,
    user_id: u64,
) -> Result<Option<AdminUserRow>, ApiError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM admin_user u WHERE u.id = ? LIMIT 1");
    Ok(sqlx::query_as::<_, AdminUserRow>(&sql)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?)
}

/// 按用户名查账号。
pub async fn find_user_by_username(
    state: &AppState,
    username: &str,
) -> Result<Option<AdminUserRow>, ApiError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM admin_user u WHERE u.username = ? LIMIT 1");
    Ok(sqlx::query_as::<_, AdminUserRow>(&sql)
        .bind(username)
        .fetch_optional(&state.db)
        .await?)
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

/// 新建账号。
pub async fn insert_user(
    state: &AppState,
    username: &str,
    password_hash: &str,
    display_name: Option<&str>,
    email: Option<&str>,
    role_code: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO admin_user (id, username, password_hash, display_name, email, role_code, status)
         VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
    )
    .bind(state.ids.next_id())
    .bind(username)
    .bind(password_hash)
    .bind(display_name)
    .bind(email)
    .bind(role_code)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 修改账号（只更新传入的字段；未传的字段保持原值）。
pub async fn update_user(
    state: &AppState,
    user_id: u64,
    display_name: Option<&str>,
    email: Option<&str>,
    role_code: Option<&str>,
    status: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE admin_user
            SET display_name = COALESCE(?, display_name),
                email = COALESCE(?, email),
                role_code = COALESCE(?, role_code),
                status = COALESCE(?, status)
          WHERE id = ?",
    )
    .bind(display_name)
    .bind(email)
    .bind(role_code)
    .bind(status)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 重置口令：写入新哈希，并清零失败次数与锁定状态。
pub async fn update_password(
    state: &AppState,
    user_id: u64,
    password_hash: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE admin_user
            SET password_hash = ?,
                fail_count = 0,
                locked_until = NULL
          WHERE id = ?",
    )
    .bind(password_hash)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 全量替换用户的项目授权：先删后插，放在一个事务里。
pub async fn replace_user_projects(
    state: &AppState,
    user_id: u64,
    project_ids: &[u64],
) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM user_project_scope WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for project_id in project_ids {
        sqlx::query("INSERT INTO user_project_scope (id, user_id, project_id) VALUES (?, ?, ?)")
            .bind(state.ids.next_id())
            .bind(user_id)
            .bind(*project_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// 查出一批 ID 中真实存在的项目 ID（不含已删除项目）。
pub async fn existing_project_ids(
    state: &AppState,
    project_ids: &[u64],
) -> Result<Vec<u64>, ApiError> {
    if project_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT id FROM project WHERE id IN ({}) AND deleted_at IS NULL",
        placeholders(project_ids.len())
    );
    let mut query = sqlx::query_as::<_, IdRow>(&sql);
    for id in project_ids {
        query = query.bind(*id);
    }
    let rows = query.fetch_all(&state.db).await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

/// 筛选条件对应的绑定值：角色、状态、关键字、关键字模糊匹配串。
fn filter_values(
    filters: &UserFilters,
) -> (Option<String>, Option<String>, Option<String>, String) {
    let role = filters
        .role
        .as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let status = filters
        .status
        .as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let keyword = filters
        .keyword
        .as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let pattern = match &keyword {
        Some(value) => format!("%{value}%"),
        None => "%".to_string(),
    };
    (role, status, keyword, pattern)
}

/// 生成 `?` 占位符列表。
fn placeholders(count: usize) -> String {
    std::iter::repeat("?")
        .take(count)
        .collect::<Vec<_>>()
        .join(", ")
}
