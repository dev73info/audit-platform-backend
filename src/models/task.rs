//! 审核任务、事件流水、动作日志、媒体资产、复核意见。

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::common::{MediaItem, TaskPayload};

/// 审核任务行。
#[derive(Debug, Clone, FromRow)]
pub struct AuditTaskRow {
    pub id: u64,
    pub task_no: String,
    pub project_id: u64,
    pub audit_id: u64,
    pub source_type: String,
    pub source_id: Option<u64>,
    pub biz_key: Option<String>,
    pub dedupe_hash: Option<String>,
    pub media_type: String,
    pub status: String,
    pub result: Option<String>,
    pub dedupe_flag: Option<String>,
    pub payload_ref: Option<String>,
    pub payload_json: Option<serde_json::Value>,
    pub rule_hit_json: Option<serde_json::Value>,
    pub model_result_json: Option<serde_json::Value>,
    pub retry_count: i32,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
    pub trace_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
}

/// 任务列表项。
#[derive(Debug, Clone, Serialize)]
pub struct TaskListItem {
    pub id: u64,
    pub task_no: String,
    pub project_id: u64,
    pub project_name: Option<String>,
    pub audit_id: u64,
    pub audit_name: Option<String>,
    pub source_type: String,
    pub biz_key: Option<String>,
    pub media_type: String,
    pub status: String,
    pub result: String,
    pub dedupe_flag: String,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_name: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
}

/// 任务详情。
#[derive(Debug, Clone, Serialize)]
pub struct TaskDetail {
    pub id: u64,
    pub task_no: String,
    pub project_id: u64,
    pub project_name: Option<String>,
    pub audit_id: u64,
    pub audit_name: Option<String>,
    pub source_type: String,
    pub biz_key: Option<String>,
    pub media_type: String,
    pub status: String,
    pub result: String,
    pub dedupe_flag: String,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub media: Vec<MediaItem>,
    pub ext: serde_json::Value,
    pub reasons: Vec<serde_json::Value>,
    pub rule_hit: Vec<super::rule::RuleGroupTrace>,
    pub actions: Vec<ActionExecView>,
    pub events: Vec<TaskEventView>,
    pub payload: TaskPayload,
    pub trace_id: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
}

/// 任务事件流水。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct TaskEventRow {
    pub id: u64,
    pub task_id: u64,
    pub project_id: u64,
    pub from_status: Option<String>,
    pub to_status: String,
    pub message: Option<String>,
    pub cost_ms: Option<i32>,
    pub created_at: NaiveDateTime,
}

/// 任务事件对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct TaskEventView {
    pub from_status: Option<String>,
    pub to_status: String,
    pub message: Option<String>,
    pub cost_ms: Option<i32>,
    pub created_at: String,
}

/// 动作执行日志行。
#[derive(Debug, Clone, FromRow)]
pub struct ActionExecRow {
    pub id: u64,
    pub task_id: u64,
    pub project_id: u64,
    pub route_type: String,
    pub action_id: String,
    pub action_type: String,
    pub action_name: Option<String>,
    pub request_json: Option<serde_json::Value>,
    pub response_json: Option<serde_json::Value>,
    pub status: String,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 动作执行日志对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct ActionExecView {
    pub id: u64,
    pub route_type: String,
    pub action_id: String,
    pub action_type: String,
    pub action_name: Option<String>,
    pub status: String,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub request: serde_json::Value,
    pub response: serde_json::Value,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// 媒体资产行。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MediaAssetRow {
    pub id: u64,
    pub task_id: u64,
    pub project_id: u64,
    pub r#type: String,
    pub url: String,
    pub oss_key: Option<String>,
    pub hash: Option<String>,
    pub size_bytes: Option<i64>,
    pub meta_json: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

/// 人工复核意见行。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ReviewOpinionRow {
    pub id: u64,
    pub task_id: u64,
    pub project_id: u64,
    pub reviewer_id: u64,
    pub conclusion: String,
    pub reason_code: Option<String>,
    pub remark: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 人工复核入参。
#[derive(Debug, Clone, Deserialize)]
pub struct ReviewRequest {
    /// `PASS` 或 `REJECT`。
    pub conclusion: String,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
}

/// 批量重试入参。
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRetryRequest {
    pub task_ids: Vec<u64>,
}

/// 重试单个动作入参。
#[derive(Debug, Clone, Deserialize)]
pub struct RetryActionRequest {
    pub action_exec_id: u64,
}

/// 提交任务的内部命令：四种触发源统一适配后的形态。
#[derive(Debug, Clone)]
pub struct TaskCommand {
    pub project_id: u64,
    pub audit_id: u64,
    pub source_type: String,
    pub source_id: Option<u64>,
    pub biz_key: Option<String>,
    pub media: Vec<MediaItem>,
    pub ext: serde_json::Value,
    pub callback_url: Option<String>,
    pub dedupe_key: Option<String>,
    /// 同步模式的等待上限（毫秒）。
    pub sync_wait_ms: Option<i64>,
    pub trace_id: Option<String>,
}
