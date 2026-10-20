//! 项目、连接配置、配额、开放 API 客户端。

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::common::ProjectQuota;

/// 项目行。
#[derive(Debug, Clone, FromRow)]
pub struct ProjectRow {
    pub id: u64,
    pub name: String,
    pub code: String,
    pub env: String,
    pub status: String,
    pub owner_id: u64,
    pub quota_json: Option<serde_json::Value>,
    pub retain_days: i32,
    pub description: Option<String>,
    pub deleted_at: Option<NaiveDateTime>,
    pub deleted_by: Option<u64>,
    pub created_by: u64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 项目列表项。
#[derive(Debug, Clone, Serialize)]
pub struct ProjectListItem {
    pub id: u64,
    pub name: String,
    pub code: String,
    pub env: String,
    pub status: String,
    pub owner_id: u64,
    pub owner_name: Option<String>,
    pub description: Option<String>,
    pub retain_days: i32,
    pub quota: ProjectQuota,
    pub stats: ProjectStats,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// 项目统计。
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProjectStats {
    pub audit_count: i64,
    pub task_today: i64,
    pub task_total: i64,
    pub queue_backlog: i64,
}

/// 新建项目入参。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub code: String,
    pub env: String,
    pub owner_id: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
    /// 缺省时用系统默认配额模板。
    #[serde(default)]
    pub quota: Option<ProjectQuota>,
}

/// 更新项目入参。
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateProjectRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub owner_id: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
    /// 乐观锁版本号。
    #[serde(default)]
    pub version: Option<i64>,
}

/// 配额更新入参。
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateQuotaRequest {
    pub max_concurrency: i64,
    pub max_qps: i64,
    pub max_mysql_pool: i64,
    pub max_redis_conn: i64,
    pub max_media_size_mb: i64,
    #[serde(default)]
    pub max_daily_tasks: Option<i64>,
    #[serde(default)]
    pub max_api_call_per_task: Option<i64>,
}

/// 项目连接配置行。
#[derive(Debug, Clone, FromRow)]
pub struct ProjectConfigRow {
    pub id: u64,
    pub project_id: u64,
    pub r#type: String,
    pub name: String,
    pub config_encrypted: Vec<u8>,
    pub pool_json: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub version: i32,
    pub test_status: Option<String>,
    pub test_message: Option<String>,
    pub tested_at: Option<NaiveDateTime>,
    pub deleted_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 连接配置对外结构（密钥已脱敏）。
#[derive(Debug, Clone, Serialize)]
pub struct ProjectConfigView {
    pub id: u64,
    pub project_id: u64,
    #[serde(rename = "type")]
    pub config_type: String,
    pub name: String,
    pub version: i32,
    pub config: serde_json::Value,
    pub pool: serde_json::Value,
    pub tags: Vec<String>,
    pub test_status: String,
    pub test_message: Option<String>,
    pub tested_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 保存连接配置入参。
#[derive(Debug, Clone, Deserialize)]
pub struct SaveConfigRequest {
    #[serde(rename = "type")]
    pub config_type: String,
    pub name: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub pool: Option<serde_json::Value>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// 变更说明，写进版本历史。
    #[serde(default)]
    pub change_note: Option<String>,
}

/// 连接测试入参。
#[derive(Debug, Clone, Deserialize)]
pub struct TestConfigRequest {
    #[serde(rename = "type")]
    pub config_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub pool: Option<serde_json::Value>,
}

/// 连接测试结果。
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionTestResult {
    #[serde(rename = "type")]
    pub config_type: String,
    pub ok: bool,
    pub latency_ms: u64,
    pub server_info: Option<String>,
    pub max_connections: Option<i64>,
    pub current_used: Option<i64>,
    pub global_limit: Option<i64>,
    pub remain_for_project: Option<i64>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

/// 配置历史版本行。
#[derive(Debug, Clone, FromRow)]
pub struct ConfigHistoryRow {
    pub id: u64,
    pub project_id: u64,
    pub config_id: u64,
    pub version: i32,
    pub config_encrypted: Vec<u8>,
    pub pool_json: Option<serde_json::Value>,
    pub operator_id: u64,
    pub change_note: Option<String>,
    pub created_at: NaiveDateTime,
}

/// 开放 API 客户端行。
#[derive(Debug, Clone, FromRow)]
pub struct ApiClientRow {
    pub id: u64,
    pub project_id: u64,
    pub app_key: String,
    pub secret_encrypted: Vec<u8>,
    pub name: String,
    pub status: String,
    pub rate_limit_json: Option<serde_json::Value>,
    pub allow_ips: Option<serde_json::Value>,
    pub callback_url: Option<String>,
    pub callback_secret_encrypted: Option<Vec<u8>>,
    pub last_used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 开放 API 客户端对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct ApiClientView {
    pub id: u64,
    pub project_id: u64,
    pub app_key: String,
    pub name: String,
    pub status: String,
    pub secret_masked: String,
    pub rate_limit: serde_json::Value,
    pub allow_ips: Vec<String>,
    pub callback_url: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 新建开放 API 客户端入参。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiClientRequest {
    pub name: String,
    #[serde(default)]
    pub rate_limit: Option<serde_json::Value>,
    #[serde(default)]
    pub allow_ips: Option<Vec<String>>,
    #[serde(default)]
    pub callback_url: Option<String>,
    /// 明文密钥，仅在创建与轮换时返回一次。
    #[serde(default)]
    pub secret: Option<String>,
}

/// 更新开放 API 客户端入参。
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateApiClientRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<serde_json::Value>,
    #[serde(default)]
    pub allow_ips: Option<Vec<String>>,
    #[serde(default)]
    pub callback_url: Option<String>,
}
