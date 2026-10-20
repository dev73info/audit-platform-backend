//! 项目连接配置域的数据访问层：连接配置、版本历史与测试结果。
//!
//! 所有 SQL 走运行时查询（`query_as` + `bind`），不使用 `query!` 宏。
//! 行结构复用 `src/models/project.rs` 里已定义的结构体。

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, Transaction};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::project::{ConfigHistoryRow, ProjectConfigRow};

/// 连接配置表列清单。
const CONFIG_COLUMNS: &str = "id, project_id, type, name, config_encrypted, pool_json, tags, \
     version, test_status, test_message, tested_at, deleted_at, created_at, updated_at";

/// 版本历史表列清单。
const HISTORY_COLUMNS: &str = "id, project_id, config_id, version, config_encrypted, pool_json, \
     operator_id, change_note, created_at";

/// 用户名。
#[derive(Debug, Clone, FromRow)]
pub struct UserNameRow {
    pub id: u64,
    pub name: String,
}

/// 项目下的连接配置列表。
pub async fn list_configs(
    state: &AppState,
    project_id: u64,
) -> Result<Vec<ProjectConfigRow>, ApiError> {
    let sql = format!(
        "SELECT {CONFIG_COLUMNS} FROM project_config
          WHERE project_id = ? AND deleted_at IS NULL
          ORDER BY type, name"
    );
    Ok(sqlx::query_as::<_, ProjectConfigRow>(&sql)
        .bind(project_id)
        .fetch_all(&state.db)
        .await?)
}

/// 取单条连接配置。
pub async fn find_config(
    state: &AppState,
    project_id: u64,
    config_id: u64,
) -> Result<Option<ProjectConfigRow>, ApiError> {
    let sql = format!(
        "SELECT {CONFIG_COLUMNS} FROM project_config
          WHERE id = ? AND project_id = ? AND deleted_at IS NULL
          LIMIT 1"
    );
    Ok(sqlx::query_as::<_, ProjectConfigRow>(&sql)
        .bind(config_id)
        .bind(project_id)
        .fetch_optional(&state.db)
        .await?)
}

/// 同项目同类型下按名称查配置（唯一键校验）。
pub async fn find_config_by_name(
    state: &AppState,
    project_id: u64,
    config_type: &str,
    name: &str,
) -> Result<Option<ProjectConfigRow>, ApiError> {
    let sql = format!(
        "SELECT {CONFIG_COLUMNS} FROM project_config
          WHERE project_id = ? AND type = ? AND name = ? AND deleted_at IS NULL
          LIMIT 1"
    );
    Ok(sqlx::query_as::<_, ProjectConfigRow>(&sql)
        .bind(project_id)
        .bind(config_type)
        .bind(name)
        .fetch_optional(&state.db)
        .await?)
}

/// 新建连接配置。
#[allow(clippy::too_many_arguments)]
pub async fn insert_config(
    tx: &mut Transaction<'_, MySql>,
    id: u64,
    project_id: u64,
    config_type: &str,
    name: &str,
    config_encrypted: &[u8],
    pool_json: Option<&serde_json::Value>,
    tags: Option<&serde_json::Value>,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO project_config
            (id, project_id, type, name, config_encrypted, pool_json, tags, version,
             test_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'UNTESTED', ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(config_type)
    .bind(name)
    .bind(config_encrypted)
    .bind(pool_json)
    .bind(tags)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 更新连接配置（版本号由调用方给出）。
#[allow(clippy::too_many_arguments)]
pub async fn update_config(
    tx: &mut Transaction<'_, MySql>,
    config_id: u64,
    config_type: &str,
    name: &str,
    config_encrypted: &[u8],
    pool_json: Option<&serde_json::Value>,
    tags: Option<&serde_json::Value>,
    version: i32,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE project_config
            SET type = ?, name = ?, config_encrypted = ?, pool_json = ?, tags = ?, version = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(config_type)
    .bind(name)
    .bind(config_encrypted)
    .bind(pool_json)
    .bind(tags)
    .bind(version)
    .bind(config_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// 软删连接配置。
pub async fn soft_delete_config(
    tx: &mut Transaction<'_, MySql>,
    config_id: u64,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE project_config SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(config_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// 写版本历史。
#[allow(clippy::too_many_arguments)]
pub async fn insert_history(
    tx: &mut Transaction<'_, MySql>,
    id: u64,
    project_id: u64,
    config_id: u64,
    version: i32,
    config_encrypted: &[u8],
    pool_json: Option<&serde_json::Value>,
    operator_id: u64,
    change_note: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO project_config_history
            (id, project_id, config_id, version, config_encrypted, pool_json, operator_id,
             change_note, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(config_id)
    .bind(version)
    .bind(config_encrypted)
    .bind(pool_json)
    .bind(operator_id)
    .bind(change_note)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 版本历史列表（按版本倒序）。
pub async fn list_history(
    state: &AppState,
    config_id: u64,
) -> Result<Vec<ConfigHistoryRow>, ApiError> {
    let sql = format!(
        "SELECT {HISTORY_COLUMNS} FROM project_config_history
          WHERE config_id = ?
          ORDER BY version DESC"
    );
    Ok(sqlx::query_as::<_, ConfigHistoryRow>(&sql)
        .bind(config_id)
        .fetch_all(&state.db)
        .await?)
}

/// 取指定版本的历史记录。
pub async fn find_history(
    state: &AppState,
    config_id: u64,
    version: i32,
) -> Result<Option<ConfigHistoryRow>, ApiError> {
    let sql = format!(
        "SELECT {HISTORY_COLUMNS} FROM project_config_history
          WHERE config_id = ? AND version = ?
          LIMIT 1"
    );
    Ok(sqlx::query_as::<_, ConfigHistoryRow>(&sql)
        .bind(config_id)
        .bind(version)
        .fetch_optional(&state.db)
        .await?)
}

/// 写回连接测试结果。
pub async fn update_test_result(
    tx: &mut Transaction<'_, MySql>,
    config_id: u64,
    test_status: &str,
    test_message: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE project_config
            SET test_status = ?, test_message = ?, tested_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(test_status)
    .bind(test_message)
    .bind(chrono::Utc::now().naive_utc())
    .bind(config_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 批量取用户名（版本历史的操作人）。
pub async fn load_user_names(
    state: &AppState,
    user_ids: &[u64],
) -> Result<std::collections::HashMap<u64, String>, ApiError> {
    let mut result: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    if user_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = sqlx::QueryBuilder::new(
        "SELECT id, COALESCE(display_name, username) AS name FROM admin_user WHERE id IN (",
    );
    let mut separated = builder.separated(", ");
    for id in user_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let rows = builder
        .build_query_as::<UserNameRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.insert(row.id, row.name);
    }
    Ok(result)
}

/// 导出版本历史的操作时间，便于统一格式化。
pub fn format_created_at(value: NaiveDateTime) -> String {
    crate::common::format_datetime(value)
}
