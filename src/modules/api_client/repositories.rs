//! 开放 API 客户端域的数据访问层：客户端凭据与状态。
//!
//! 所有 SQL 走运行时查询（`query_as` + `bind`），不使用 `query!` 宏。
//! 行结构复用 `src/models/project.rs` 里已定义的结构体。

use sqlx::{MySql, Transaction};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::project::ApiClientRow;

/// 客户端表列清单。
const CLIENT_COLUMNS: &str = "id, project_id, app_key, secret_encrypted, name, status, \
     rate_limit_json, allow_ips, callback_url, callback_secret_encrypted, last_used_at, \
     created_at, updated_at";

/// 项目下的客户端列表。
pub async fn list_clients(
    state: &AppState,
    project_id: u64,
) -> Result<Vec<ApiClientRow>, ApiError> {
    let sql = format!(
        "SELECT {CLIENT_COLUMNS} FROM api_client WHERE project_id = ? ORDER BY created_at DESC"
    );
    Ok(sqlx::query_as::<_, ApiClientRow>(&sql)
        .bind(project_id)
        .fetch_all(&state.db)
        .await?)
}

/// 取单个客户端。
pub async fn find_client(
    state: &AppState,
    client_id: u64,
) -> Result<Option<ApiClientRow>, ApiError> {
    let sql = format!("SELECT {CLIENT_COLUMNS} FROM api_client WHERE id = ? LIMIT 1");
    Ok(sqlx::query_as::<_, ApiClientRow>(&sql)
        .bind(client_id)
        .fetch_optional(&state.db)
        .await?)
}

/// 新建客户端。
#[allow(clippy::too_many_arguments)]
pub async fn insert_client(
    tx: &mut Transaction<'_, MySql>,
    id: u64,
    project_id: u64,
    app_key: &str,
    secret_encrypted: &[u8],
    name: &str,
    rate_limit: Option<&serde_json::Value>,
    allow_ips: Option<&serde_json::Value>,
    callback_url: Option<&str>,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO api_client
            (id, project_id, app_key, secret_encrypted, name, status, rate_limit_json,
             allow_ips, callback_url, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(app_key)
    .bind(secret_encrypted)
    .bind(name)
    .bind(rate_limit)
    .bind(allow_ips)
    .bind(callback_url)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 更新客户端基础信息。
pub async fn update_client(
    tx: &mut Transaction<'_, MySql>,
    client_id: u64,
    name: &str,
    status: &str,
    rate_limit: Option<&serde_json::Value>,
    allow_ips: Option<&serde_json::Value>,
    callback_url: Option<&str>,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE api_client
            SET name = ?, status = ?, rate_limit_json = ?, allow_ips = ?, callback_url = ?
          WHERE id = ?",
    )
    .bind(name)
    .bind(status)
    .bind(rate_limit)
    .bind(allow_ips)
    .bind(callback_url)
    .bind(client_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// 轮换密钥。
pub async fn update_secret(
    tx: &mut Transaction<'_, MySql>,
    client_id: u64,
    secret_encrypted: &[u8],
) -> Result<u64, ApiError> {
    let result = sqlx::query("UPDATE api_client SET secret_encrypted = ? WHERE id = ?")
        .bind(secret_encrypted)
        .bind(client_id)
        .execute(&mut **tx)
        .await?;
    Ok(result.rows_affected())
}

/// 删除客户端。
pub async fn delete_client(tx: &mut Transaction<'_, MySql>, client_id: u64) -> Result<u64, ApiError> {
    let result = sqlx::query("DELETE FROM api_client WHERE id = ?")
        .bind(client_id)
        .execute(&mut **tx)
        .await?;
    Ok(result.rows_affected())
}
