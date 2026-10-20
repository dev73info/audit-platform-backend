//! 触发源的数据访问层：触发源 CRUD、启停与消费记录。
//!
//! SQL 走运行时查询（`query_as` + `bind`），行结构用 `src/models/` 里已定义的结构。
//! 触发源属于触发源模块自己的数据访问范围，这里不依赖审核模块的仓储实现。

use chrono::NaiveDateTime;
use sqlx::{MySql, QueryBuilder, Transaction};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::audit::TriggerSourceRow;

/// 触发源落库参数。
#[derive(Debug, Clone)]
pub struct TriggerInsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_type: String,
    pub name: String,
    pub config_json: serde_json::Value,
    pub priority: i32,
    pub status: String,
}

/// 触发源更新参数。
#[derive(Debug, Clone)]
pub struct TriggerUpdate {
    pub trigger_type: String,
    pub name: String,
    pub config_json: serde_json::Value,
    pub priority: i32,
    pub status: String,
}

/// 触发源消费记录行。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsumeLogRow {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_id: u64,
    pub message_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 触发源消费记录落库参数。
#[derive(Debug, Clone)]
pub struct ConsumeLogInsert {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub trigger_id: u64,
    pub message_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
}

/// 取审核下的触发源。
pub async fn list_triggers(
    state: &AppState,
    audit_id: u64,
) -> Result<Vec<TriggerSourceRow>, ApiError> {
    let rows = sqlx::query_as::<_, TriggerSourceRow>(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE audit_id = ? AND deleted_at IS NULL
          ORDER BY priority ASC, id ASC",
    )
    .bind(audit_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// 批量取多个审核的触发源，按审核 ID 分组。
pub async fn list_triggers_for_audits(
    state: &AppState,
    audit_ids: &[u64],
) -> Result<std::collections::HashMap<u64, Vec<TriggerSourceRow>>, ApiError> {
    let mut result: std::collections::HashMap<u64, Vec<TriggerSourceRow>> =
        std::collections::HashMap::new();
    if audit_ids.is_empty() {
        return Ok(result);
    }

    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE deleted_at IS NULL AND audit_id IN (",
    );
    for (index, id) in audit_ids.iter().enumerate() {
        if index > 0 {
            builder.push(", ");
        }
        builder.push_bind(*id);
    }
    builder.push(") ORDER BY priority ASC, id ASC");

    let rows = builder
        .build_query_as::<TriggerSourceRow>()
        .fetch_all(&state.db)
        .await?;
    for row in rows {
        result.entry(row.audit_id).or_default().push(row);
    }
    Ok(result)
}

/// 取单个触发源。
pub async fn find_trigger(
    state: &AppState,
    trigger_id: u64,
) -> Result<TriggerSourceRow, ApiError> {
    let row = sqlx::query_as::<_, TriggerSourceRow>(
        "SELECT id, project_id, audit_id, type, name, config_json, priority, status,
                last_error, last_consume_at, success_count, fail_count, deleted_at,
                created_at, updated_at
           FROM trigger_source
          WHERE id = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(trigger_id)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("触发源不存在"))
}

/// 插入触发源。
pub async fn insert_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger: &TriggerInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO trigger_source
            (id, project_id, audit_id, type, name, config_json, priority, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(trigger.id)
    .bind(trigger.project_id)
    .bind(trigger.audit_id)
    .bind(&trigger.trigger_type)
    .bind(&trigger.name)
    .bind(&trigger.config_json)
    .bind(trigger.priority)
    .bind(&trigger.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(trigger.id)
}

/// 更新触发源。
pub async fn update_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
    trigger: &TriggerUpdate,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source
            SET type = ?, name = ?, config_json = ?, priority = ?, status = ?, updated_at = ?
          WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&trigger.trigger_type)
    .bind(&trigger.name)
    .bind(&trigger.config_json)
    .bind(trigger.priority)
    .bind(&trigger.status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(trigger_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 改触发源状态。
pub async fn set_trigger_status(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
    status: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE trigger_source SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(chrono::Utc::now().naive_utc())
        .bind(trigger_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 软删除触发源。
pub async fn soft_delete_trigger(
    tx: &mut Transaction<'_, MySql>,
    trigger_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(trigger_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 软删除某审核下的全部触发源。
pub async fn soft_delete_triggers_of_audit(
    tx: &mut Transaction<'_, MySql>,
    audit_id: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE trigger_source SET status = 'PAUSED', deleted_at = ?, updated_at = ? WHERE audit_id = ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(audit_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 写触发源消费记录。
pub async fn insert_consume_log(
    tx: &mut Transaction<'_, MySql>,
    entry: &ConsumeLogInsert,
) -> Result<u64, ApiError> {
    sqlx::query(
        "INSERT INTO trigger_consume_log
            (id, project_id, audit_id, trigger_id, message_id, status, duration_ms, error_message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.id)
    .bind(entry.project_id)
    .bind(entry.audit_id)
    .bind(entry.trigger_id)
    .bind(&entry.message_id)
    .bind(&entry.status)
    .bind(entry.duration_ms)
    .bind(&entry.error_message)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;
    Ok(entry.id)
}

/// 取审核所属的项目 ID。审核不存在时返回 `None`。
pub async fn find_audit_project(
    state: &AppState,
    audit_id: u64,
) -> Result<Option<u64>, ApiError> {
    let project_id: Option<u64> =
        sqlx::query_scalar("SELECT project_id FROM audit_definition WHERE id = ? AND deleted_at IS NULL LIMIT 1")
            .bind(audit_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(project_id)
}

/// 取项目状态。用于判断项目是否可写。
pub async fn find_project_status(
    state: &AppState,
    project_id: u64,
) -> Result<Option<String>, ApiError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM project WHERE id = ? LIMIT 1")
            .bind(project_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(status)
}

/// 取触发源最近的消费记录。
pub async fn list_consume_logs(
    state: &AppState,
    trigger_id: u64,
    limit: i64,
) -> Result<Vec<ConsumeLogRow>, ApiError> {
    let rows = sqlx::query_as::<_, ConsumeLogRow>(
        "SELECT id, project_id, audit_id, trigger_id, message_id, status, duration_ms,
                error_message, created_at
           FROM trigger_consume_log
          WHERE trigger_id = ?
          ORDER BY created_at DESC, id DESC
          LIMIT ?",
    )
    .bind(trigger_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}
