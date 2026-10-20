//! 回收站的数据访问层。

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::Row;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::RecycleBinRow;

/// 回收站条目（含联表信息）。
#[derive(Debug, Clone)]
pub struct RecycleBinItem {
    pub row: RecycleBinRow,
    pub project_name: Option<String>,
    pub deleted_by_name: Option<String>,
    pub children_count: i64,
}

/// 列出回收站条目。
pub async fn list(
    state: &AppState,
    object_type: Option<&str>,
    project_id: Option<u64>,
    keyword: Option<&str>,
    offset: u64,
    limit: u64,
) -> Result<(Vec<RecycleBinItem>, u64), ApiError> {
    let mut conditions = vec!["1 = 1".to_string()];
    if object_type.is_some() {
        conditions.push("r.object_type = ?".to_string());
    }
    if project_id.is_some() {
        conditions.push("r.project_id = ?".to_string());
    }
    if keyword.is_some_and(|text| !text.trim().is_empty()) {
        conditions.push("(r.object_name LIKE ? OR r.object_code LIKE ?)".to_string());
    }
    let where_sql = conditions.join(" AND ");

    let count_sql = format!("SELECT COUNT(*) FROM recycle_bin r WHERE {where_sql}");
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(value) = object_type {
        count_query = count_query.bind(value);
    }
    if let Some(value) = project_id {
        count_query = count_query.bind(value);
    }
    if let Some(value) = keyword.filter(|text| !text.trim().is_empty()) {
        count_query = count_query.bind(format!("%{value}%")).bind(format!("%{value}%"));
    }
    let total = count_query.fetch_one(&state.db).await?;

    let list_sql = format!(
        "SELECT r.id, r.project_id, r.object_type, r.object_id, r.object_name, r.object_code,
                r.snapshot_json, r.deleted_by, r.deleted_at, r.expire_at, r.purge_status,
                r.purge_message,
                p.name AS project_name, u.display_name AS deleted_by_name,
                (SELECT COUNT(*) FROM audit_definition a
                  WHERE a.project_id = r.project_id
                    AND a.deleted_at IS NOT NULL
                    AND r.object_type = 'PROJECT'
                    AND a.deleted_at >= r.deleted_at) AS children_count
           FROM recycle_bin r
           LEFT JOIN project p ON p.id = r.project_id
           LEFT JOIN admin_user u ON u.id = r.deleted_by
          WHERE {where_sql}
          ORDER BY r.deleted_at DESC
          LIMIT ? OFFSET ?"
    );
    let mut list_query = sqlx::query(&list_sql);
    if let Some(value) = object_type {
        list_query = list_query.bind(value);
    }
    if let Some(value) = project_id {
        list_query = list_query.bind(value);
    }
    if let Some(value) = keyword.filter(|text| !text.trim().is_empty()) {
        list_query = list_query.bind(format!("%{value}%")).bind(format!("%{value}%"));
    }
    let rows = list_query.bind(limit).bind(offset).fetch_all(&state.db).await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(RecycleBinItem {
            row: RecycleBinRow {
                id: row.get("id"),
                project_id: row.get("project_id"),
                object_type: row.get("object_type"),
                object_id: row.get("object_id"),
                object_name: row.get("object_name"),
                object_code: row.get("object_code"),
                snapshot_json: row.get("snapshot_json"),
                deleted_by: row.get("deleted_by"),
                deleted_at: row.get("deleted_at"),
                expire_at: row.get("expire_at"),
                purge_status: row.get("purge_status"),
                purge_message: row.get("purge_message"),
            },
            project_name: row.get("project_name"),
            deleted_by_name: row.get("deleted_by_name"),
            children_count: row.get("children_count"),
        });
    }

    Ok((items, total as u64))
}

/// 按 ID 取回收站条目。
pub async fn find(state: &AppState, id: u64) -> Result<Option<RecycleBinRow>, ApiError> {
    let row = sqlx::query(
        "SELECT id, project_id, object_type, object_id, object_name, object_code, snapshot_json,
                deleted_by, deleted_at, expire_at, purge_status, purge_message
           FROM recycle_bin WHERE id = ? LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;

    Ok(row.map(|row| RecycleBinRow {
        id: row.get("id"),
        project_id: row.get("project_id"),
        object_type: row.get("object_type"),
        object_id: row.get("object_id"),
        object_name: row.get("object_name"),
        object_code: row.get("object_code"),
        snapshot_json: row.get("snapshot_json"),
        deleted_by: row.get("deleted_by"),
        deleted_at: row.get("deleted_at"),
        expire_at: row.get("expire_at"),
        purge_status: row.get("purge_status"),
        purge_message: row.get("purge_message"),
    }))
}

/// 标记清理状态。
pub async fn set_purge_status(
    state: &AppState,
    id: u64,
    status: &str,
    message: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE recycle_bin SET purge_status = ?, purge_message = ? WHERE id = ?")
        .bind(status)
        .bind(message)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 删除回收站记录。
pub async fn remove(state: &AppState, id: u64) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM recycle_bin WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 列出已过期且未清理的条目。
pub async fn list_expired(state: &AppState, limit: i64) -> Result<Vec<RecycleBinRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, project_id, object_type, object_id, object_name, object_code, snapshot_json,
                deleted_by, deleted_at, expire_at, purge_status, purge_message
           FROM recycle_bin
          WHERE expire_at < ? AND (purge_status IS NULL OR purge_status = 'NONE')
          ORDER BY expire_at ASC
          LIMIT ?",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| RecycleBinRow {
            id: row.get("id"),
            project_id: row.get("project_id"),
            object_type: row.get("object_type"),
            object_id: row.get("object_id"),
            object_name: row.get("object_name"),
            object_code: row.get("object_code"),
            snapshot_json: row.get("snapshot_json"),
            deleted_by: row.get("deleted_by"),
            deleted_at: row.get("deleted_at"),
            expire_at: row.get("expire_at"),
            purge_status: row.get("purge_status"),
            purge_message: row.get("purge_message"),
        })
        .collect())
}

/// 查清理任务。
pub async fn list_cleanup_tasks(
    state: &AppState,
    offset: u64,
    limit: u64,
) -> Result<(Vec<crate::models::ops::CleanupTaskRow>, u64), ApiError> {
    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cleanup_task")
        .fetch_one(&state.db)
        .await?;

    let rows = sqlx::query(
        "SELECT id, recycle_id, object_type, object_id, object_name, status, progress, step,
                error_message, created_by, created_at, finished_at
           FROM cleanup_task ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let items = rows
        .into_iter()
        .map(|row| crate::models::ops::CleanupTaskRow {
            id: row.get("id"),
            recycle_id: row.get("recycle_id"),
            object_type: row.get("object_type"),
            object_id: row.get("object_id"),
            object_name: row.get("object_name"),
            status: row.get("status"),
            progress: row.get("progress"),
            step: row.get("step"),
            error_message: row.get("error_message"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            finished_at: row.get("finished_at"),
        })
        .collect();

    Ok((items, total as u64))
}

/// 建一个清理任务。
pub async fn insert_cleanup_task(
    state: &AppState,
    recycle_id: Option<u64>,
    object_type: &str,
    object_id: u64,
    object_name: &str,
    created_by: u64,
) -> Result<u64, ApiError> {
    let id = state.ids.next_id();
    sqlx::query(
        "INSERT INTO cleanup_task (id, recycle_id, object_type, object_id, object_name, status, created_by)
         VALUES (?, ?, ?, ?, ?, 'PENDING', ?)",
    )
    .bind(id)
    .bind(recycle_id)
    .bind(object_type)
    .bind(object_id)
    .bind(object_name)
    .bind(created_by)
    .execute(&state.db)
    .await?;
    Ok(id)
}

/// 更新清理任务状态。
pub async fn update_cleanup_task(
    state: &AppState,
    id: u64,
    status: &str,
    progress: i32,
    step: Option<&str>,
    error: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE cleanup_task
            SET status = ?, progress = ?, step = ?, error_message = ?,
                finished_at = CASE WHEN ? IN ('DONE', 'FAILED') THEN ? ELSE finished_at END
          WHERE id = ?",
    )
    .bind(status)
    .bind(progress)
    .bind(step)
    .bind(error)
    .bind(status)
    .bind(chrono::Utc::now().naive_utc())
    .bind(id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 取项目下已软删的审核 ID。
pub async fn list_deleted_audits(state: &AppState, project_id: u64) -> Result<Vec<u64>, ApiError> {
    let ids = sqlx::query_scalar::<_, u64>(
        "SELECT id FROM audit_definition WHERE project_id = ? AND deleted_at IS NOT NULL",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    Ok(ids)
}

/// 物理删除一个项目的关联数据（永久删除时用）。
pub async fn purge_project_data(state: &AppState, project_id: u64) -> Result<(), ApiError> {
    let audit_ids = list_deleted_audits(state, project_id).await?;
    for audit_id in &audit_ids {
        sqlx::query("DELETE FROM rule_item WHERE rule_id IN (SELECT id FROM audit_rule WHERE audit_id = ?)")
            .bind(audit_id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM audit_rule WHERE audit_id = ?")
            .bind(audit_id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM trigger_source WHERE audit_id = ?")
            .bind(audit_id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM result_route WHERE audit_id = ?")
            .bind(audit_id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM audit_definition WHERE id = ?")
            .bind(audit_id)
            .execute(&state.db)
            .await?;
    }

    sqlx::query("DELETE FROM action_exec_log WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM task_event WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM media_asset WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM review_opinion WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM idempotency_record WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM project_config_history WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM project_config WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM api_client WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM resource_quota WHERE project_id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM project WHERE id = ?")
        .bind(project_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 物理删除一个审核的关联数据。
pub async fn purge_audit_data(state: &AppState, audit_id: u64) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM rule_item WHERE rule_id IN (SELECT id FROM audit_rule WHERE audit_id = ?)")
        .bind(audit_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM audit_rule WHERE audit_id = ?")
        .bind(audit_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM trigger_source WHERE audit_id = ?")
        .bind(audit_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM result_route WHERE audit_id = ?")
        .bind(audit_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM audit_definition WHERE id = ?")
        .bind(audit_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 查回收站快照。
pub fn snapshot_of(row: &RecycleBinRow) -> Value {
    row.snapshot_json.clone()
}

/// 剩余保留天数。
pub fn remain_days(expire_at: NaiveDateTime) -> i64 {
    let now = chrono::Utc::now().naive_utc();
    let diff = expire_at - now;
    diff.num_seconds().div_euclid(86_400)
}
