//! 回收站、审计日志、告警。

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// 回收站条目行。
#[derive(Debug, Clone, FromRow)]
pub struct RecycleBinRow {
    pub id: u64,
    pub project_id: u64,
    pub object_type: String,
    pub object_id: u64,
    pub object_name: String,
    pub object_code: Option<String>,
    pub snapshot_json: serde_json::Value,
    pub deleted_by: u64,
    pub deleted_at: NaiveDateTime,
    pub expire_at: NaiveDateTime,
    pub purge_status: Option<String>,
    pub purge_message: Option<String>,
}

/// 回收站条目对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct RecycleBinView {
    pub id: u64,
    pub object_type: String,
    pub object_id: u64,
    pub object_name: String,
    pub object_code: Option<String>,
    pub project_id: u64,
    pub project_name: Option<String>,
    pub deleted_by: u64,
    pub deleted_by_name: Option<String>,
    pub deleted_at: String,
    pub expire_at: String,
    pub remain_days: i64,
    pub purge_status: String,
    pub purge_message: Option<String>,
    pub children_count: i64,
}

/// 恢复入参。
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreRequest {
    /// 恢复时如需改名可带上新名称。
    #[serde(default)]
    pub name: Option<String>,
}

/// 永久删除入参：必须与对象名称完全一致。
#[derive(Debug, Clone, Deserialize)]
pub struct PurgeRequest {
    pub confirm_name: String,
}

/// 批量永久删除入参。
#[derive(Debug, Clone, Deserialize)]
pub struct BatchPurgeRequest {
    pub ids: Vec<u64>,
    pub confirm_text: String,
}

/// 审计日志行。
#[derive(Debug, Clone, FromRow)]
pub struct AuditLogRow {
    pub id: u64,
    pub project_id: Option<u64>,
    pub operator: String,
    pub operator_id: Option<u64>,
    pub operator_ip: Option<String>,
    pub action: String,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
    pub result: String,
    pub detail_json: Option<serde_json::Value>,
    pub trace_id: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 审计日志对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogView {
    pub id: u64,
    pub project_id: Option<u64>,
    pub operator: String,
    pub operator_id: Option<u64>,
    pub operator_ip: Option<String>,
    pub action: String,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
    pub result: String,
    pub detail: serde_json::Value,
    pub trace_id: Option<String>,
    pub created_at: String,
}

/// 告警事件行。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertEventRow {
    pub id: u64,
    pub project_id: Option<u64>,
    pub rule_id: Option<u64>,
    pub name: String,
    pub level: String,
    pub status: String,
    pub message: Option<String>,
    pub value: Option<String>,
    pub started_at: NaiveDateTime,
    pub resolved_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// 清理任务行。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct CleanupTaskRow {
    pub id: u64,
    pub recycle_id: Option<u64>,
    pub object_type: String,
    pub object_id: u64,
    pub object_name: String,
    pub status: String,
    pub progress: i32,
    pub step: Option<String>,
    pub error_message: Option<String>,
    pub created_by: u64,
    pub created_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
}

/// 站内通知行。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct NotificationRow {
    pub id: u64,
    pub user_id: Option<u64>,
    pub project_id: Option<u64>,
    pub category: String,
    pub title: String,
    pub content: Option<String>,
    pub link: Option<String>,
    pub read_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// 写审计日志的入参。
#[derive(Debug, Clone, Default)]
pub struct AuditLogEntry {
    pub project_id: Option<u64>,
    pub operator: String,
    pub operator_id: Option<u64>,
    pub operator_ip: Option<String>,
    pub action: String,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
    /// `SUCCESS` / `FAIL`。
    pub result: String,
    pub detail: Option<serde_json::Value>,
    pub trace_id: Option<String>,
}
