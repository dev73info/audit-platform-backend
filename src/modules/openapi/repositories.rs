//! 开放 API 网关的数据访问层。

use std::collections::HashMap;

use serde_json::Value;
use sqlx::Row;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::audit::ResultRouteView;

/// 开放 API 客户端记录（密钥已解密）。
#[derive(Debug, Clone)]
pub struct ApiClientRecord {
    pub id: u64,
    pub project_id: u64,
    pub app_key: String,
    pub secret: String,
    pub name: String,
    pub status: String,
    pub allow_ips: Vec<String>,
    pub callback_url: Option<String>,
    pub callback_secret: Option<String>,
}

/// 开放 API 查询到的任务结果。
#[derive(Debug, Clone)]
pub struct TaskResultRow {
    pub id: u64,
    pub task_no: String,
    pub status: String,
    pub result: String,
    pub media_type: String,
    pub duration_ms: Option<i32>,
    pub finished_at: Option<String>,
    pub rule_hit_json: Option<Value>,
    pub model_result_json: Option<Value>,
    pub media: Vec<(String, String)>,
}

/// 按 AppKey 查客户端；密钥在服务层解密。
pub async fn find_client_by_app_key(
    state: &AppState,
    app_key: &str,
) -> Result<Option<ApiClientRecord>, ApiError> {
    let row = sqlx::query(
        "SELECT id, project_id, app_key, secret_encrypted, name, status, allow_ips,
                callback_url, callback_secret_encrypted
           FROM api_client
          WHERE app_key = ?
          LIMIT 1",
    )
    .bind(app_key)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let allow_ips: Vec<String> = row
        .get::<Option<Value>, _>("allow_ips")
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();

    Ok(Some(ApiClientRecord {
        id: row.get("id"),
        project_id: row.get("project_id"),
        app_key: row.get("app_key"),
        secret: String::new(),
        name: row.get("name"),
        status: row.get("status"),
        allow_ips,
        callback_url: row.get("callback_url"),
        callback_secret: None,
    }))
}

/// 取客户端密钥的密文。
pub async fn find_client_secret_cipher(
    state: &AppState,
    client_id: u64,
) -> Result<(Vec<u8>, Option<Vec<u8>>), ApiError> {
    let row = sqlx::query(
        "SELECT secret_encrypted, callback_secret_encrypted FROM api_client WHERE id = ? LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("开放 API 客户端不存在"))?;

    Ok((row.get("secret_encrypted"), row.get("callback_secret_encrypted")))
}

/// 更新客户端的回调地址与回调密钥。
pub async fn update_callback(
    state: &AppState,
    client_id: u64,
    callback_url: &str,
    callback_secret_cipher: Option<Vec<u8>>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE api_client SET callback_url = ?, callback_secret_encrypted = ? WHERE id = ?",
    )
    .bind(callback_url)
    .bind(callback_secret_cipher)
    .bind(client_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 记录客户端最近一次使用时间。
pub async fn touch_client(state: &AppState, client_id: u64) -> Result<(), ApiError> {
    sqlx::query("UPDATE api_client SET last_used_at = ? WHERE id = ?")
        .bind(chrono::Utc::now().naive_utc())
        .bind(client_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// 查项目状态（`ACTIVE` / `PAUSED` / `DISABLED` / `DELETED`）。
pub async fn find_project_status(
    state: &AppState,
    project_id: u64,
) -> Result<Option<String>, ApiError> {
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM project WHERE id = ? AND deleted_at IS NULL LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(status)
}

/// 按 ID 查任务。
pub async fn find_task(
    state: &AppState,
    project_id: u64,
    task_id: u64,
) -> Result<Option<TaskResultRow>, ApiError> {
    let row = sqlx::query(
        "SELECT id, task_no, status, result, media_type, duration_ms, finished_at,
                rule_hit_json, model_result_json
           FROM audit_task
          WHERE id = ? AND project_id = ?
          LIMIT 1",
    )
    .bind(task_id)
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let media = sqlx::query("SELECT type, url FROM media_asset WHERE task_id = ? ORDER BY id")
        .bind(task_id)
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|item| {
            (
                item.get::<String, _>("type"),
                item.get::<String, _>("url"),
            )
        })
        .collect();

    Ok(Some(TaskResultRow {
        id: row.get("id"),
        task_no: row.get("task_no"),
        status: row.get("status"),
        result: row.get::<Option<String>, _>("result").unwrap_or_else(|| "UNKNOWN".to_string()),
        media_type: row.get("media_type"),
        duration_ms: row.get("duration_ms"),
        finished_at: row
            .get::<Option<chrono::NaiveDateTime>, _>("finished_at")
            .map(|value| value.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        rule_hit_json: row.get("rule_hit_json"),
        model_result_json: row.get("model_result_json"),
        media,
    }))
}

/// 轮询：取该审核下已完成的任务（按 ID 升序）。
pub async fn poll_finished_tasks(
    state: &AppState,
    project_id: u64,
    audit_id: u64,
    after_id: u64,
    limit: i64,
) -> Result<Vec<TaskResultRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id FROM audit_task
          WHERE project_id = ? AND audit_id = ? AND id > ?
            AND status IN ('SUCCESS', 'FAILED', 'DEAD_LETTER', 'REVIEW_PENDING')
          ORDER BY id ASC
          LIMIT ?",
    )
    .bind(project_id)
    .bind(audit_id)
    .bind(after_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row.get::<u64, _>("id");
        if let Some(task) = find_task(state, project_id, id).await? {
            result.push(task);
        }
    }
    Ok(result)
}

/// 查项目的审核路由（供预览与回调使用）。
pub async fn load_routes(
    state: &AppState,
    audit_id: u64,
) -> Result<HashMap<String, ResultRouteView>, ApiError> {
    let rows = crate::modules::audit::repositories::list_routes(state, audit_id).await?;
    let mut result = HashMap::new();
    for row in rows {
        let view = crate::modules::task::repositories::to_route_view(row)?;
        result.insert(view.result_type.clone(), view);
    }
    Ok(result)
}
