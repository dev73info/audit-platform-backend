//! 审核定义、触发源、规则、结果路由。

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::common::ProjectQuota;

/// 审核定义行。
#[derive(Debug, Clone, FromRow)]
pub struct AuditDefinitionRow {
    pub id: u64,
    pub project_id: u64,
    pub name: String,
    pub code: String,
    pub media_types: serde_json::Value,
    pub status: String,
    pub concurrency: i32,
    pub timeout_ms: i32,
    pub retry_policy: Option<serde_json::Value>,
    pub dedupe_window_sec: i32,
    pub media_hash_in_key: bool,
    pub config_json: Option<serde_json::Value>,
    pub config_version: i32,
    pub description: Option<String>,
    pub deleted_at: Option<NaiveDateTime>,
    pub deleted_by: Option<u64>,
    pub created_by: u64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 审核定义对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct AuditView {
    pub id: u64,
    pub project_id: u64,
    pub project_name: Option<String>,
    pub name: String,
    pub code: String,
    pub media_types: Vec<String>,
    pub status: String,
    pub concurrency: i32,
    pub timeout_ms: i32,
    pub dedupe_window_sec: i32,
    pub media_hash_in_key: bool,
    pub retry_policy: serde_json::Value,
    pub default_result: String,
    pub on_model_fail: String,
    pub media_review: serde_json::Value,
    pub description: Option<String>,
    pub config_version: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// 触发源行。
#[derive(Debug, Clone, FromRow)]
pub struct TriggerSourceRow {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub r#type: String,
    pub name: String,
    pub config_json: serde_json::Value,
    pub priority: i32,
    pub status: String,
    pub last_error: Option<String>,
    pub last_consume_at: Option<NaiveDateTime>,
    pub success_count: i64,
    pub fail_count: i64,
    pub deleted_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 触发源对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct TriggerSourceView {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    #[serde(rename = "type")]
    pub trigger_type: String,
    pub name: String,
    pub priority: i32,
    pub status: String,
    pub config: serde_json::Value,
    pub success_count: i64,
    pub fail_count: i64,
    pub last_consume_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 规则组行。
#[derive(Debug, Clone, FromRow)]
pub struct AuditRuleRow {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub name: String,
    pub priority: i32,
    pub logic: String,
    pub stop_on_hit: bool,
    pub on_hit_result: String,
    pub status: String,
    pub deleted_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// 规则条件项行。
#[derive(Debug, Clone, FromRow)]
pub struct RuleItemRow {
    pub id: u64,
    pub rule_id: u64,
    pub field: String,
    pub operator: String,
    pub value_json: serde_json::Value,
    pub case_sensitive: bool,
    pub negate: bool,
    pub sort_order: i32,
}

/// 规则组对外结构（含条件项）。
#[derive(Debug, Clone, Serialize)]
pub struct AuditRuleView {
    pub id: u64,
    pub audit_id: u64,
    pub name: String,
    pub priority: i32,
    pub logic: String,
    pub stop_on_hit: bool,
    pub on_hit_result: String,
    pub status: String,
    pub items: Vec<RuleItemView>,
    pub created_at: String,
    pub updated_at: String,
}

/// 规则条件项对外结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleItemView {
    pub id: Option<u64>,
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub sort_order: i32,
}

/// 结果路由行。
#[derive(Debug, Clone, FromRow)]
pub struct ResultRouteRow {
    pub id: u64,
    pub project_id: u64,
    pub audit_id: u64,
    pub result_type: String,
    pub exec_mode: String,
    pub on_error: String,
    pub actions_json: serde_json::Value,
    pub status: String,
    pub deleted_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

/// 结果路由对外结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRouteView {
    #[serde(default)]
    pub id: Option<u64>,
    pub result_type: String,
    pub exec_mode: String,
    pub on_error: String,
    pub actions: Vec<super::rule::ActionSpec>,
    #[serde(default)]
    pub status: Option<String>,
}

/// 新建 / 更新审核定义入参。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SaveAuditRequest {
    pub name: String,
    pub code: String,
    #[serde(default)]
    pub media_types: Vec<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub concurrency: Option<i32>,
    #[serde(default)]
    pub timeout_ms: Option<i32>,
    #[serde(default)]
    pub dedupe_window_sec: Option<i32>,
    #[serde(default)]
    pub media_hash_in_key: Option<bool>,
    #[serde(default)]
    pub retry_policy: Option<serde_json::Value>,
    #[serde(default)]
    pub default_result: Option<String>,
    #[serde(default)]
    pub on_model_fail: Option<String>,
    #[serde(default)]
    pub media_review: Option<serde_json::Value>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub triggers: Option<Vec<SaveTriggerRequest>>,
    #[serde(default)]
    pub rules: Option<Vec<SaveRuleRequest>>,
    #[serde(default)]
    pub routes: Option<serde_json::Value>,
    /// 乐观锁版本号。
    #[serde(default)]
    pub config_version: Option<i32>,
}

/// 保存触发源入参。
#[derive(Debug, Clone, Deserialize)]
pub struct SaveTriggerRequest {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(rename = "type")]
    pub trigger_type: String,
    pub name: String,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub config: serde_json::Value,
}

/// 保存规则组入参。
#[derive(Debug, Clone, Deserialize)]
pub struct SaveRuleRequest {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub logic: Option<String>,
    #[serde(default)]
    pub stop_on_hit: Option<bool>,
    #[serde(default)]
    pub on_hit_result: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub items: Vec<RuleItemView>,
}

/// 审核配置快照（存 `config_json`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfigSnapshot {
    pub default_result: String,
    pub on_model_fail: String,
    #[serde(default)]
    pub media_review: serde_json::Value,
    #[serde(default)]
    pub rules: Vec<super::rule::RuleGroupSpec>,
    #[serde(default)]
    pub routes: serde_json::Value,
}

impl Default for AuditConfigSnapshot {
    fn default() -> Self {
        Self {
            default_result: "REVIEW".to_string(),
            on_model_fail: "REVIEW".to_string(),
            media_review: serde_json::json!({}),
            rules: Vec::new(),
            routes: serde_json::json!({}),
        }
    }
}

/// 配额视图（给前端用）。
pub type QuotaView = ProjectQuota;
