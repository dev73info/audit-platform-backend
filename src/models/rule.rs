//! 规则 DSL 与动作 DSL 的数据结构。
//!
//! 规则语义见 `doc/API.md` 第四章，动作语义见第五章。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 规则组。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroupSpec {
    #[serde(default)]
    pub id: Option<u64>,
    pub name: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_logic")]
    pub logic: String,
    #[serde(default = "default_true")]
    pub stop_on_hit: bool,
    #[serde(default = "default_review")]
    pub on_hit_result: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub items: Vec<RuleItemSpec>,
}

fn default_priority() -> i32 {
    100
}
fn default_logic() -> String {
    "AND".to_string()
}
fn default_true() -> bool {
    true
}
fn default_review() -> String {
    "REVIEW".to_string()
}

/// 规则条件项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleItemSpec {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub sort_order: i32,
}

/// 动作定义。不同类型用不同字段，未使用的字段留空。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub name: Option<String>,
    /// HTTP 动作引用的第三方 API 配置名。
    #[serde(default)]
    pub api_ref: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<Value>,
    #[serde(default)]
    pub body: Option<Value>,
    /// Redis 动作：命令、键、值、TTL。
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub ttl_sec: Option<i64>,
    /// MySQL 动作：数据源、SQL、参数。
    #[serde(default)]
    pub datasource: Option<String>,
    #[serde(default)]
    pub sql: Option<String>,
    #[serde(default)]
    pub params: Option<Vec<Value>>,
    /// Webhook 动作：地址与签名方式。
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub sign: Option<Value>,
    /// 消息队列动作：目标与主题。
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
    #[serde(default)]
    pub retry: Option<Value>,
    #[serde(default)]
    pub on_error: Option<String>,
}

impl ActionSpec {
    /// 动作的稳定标识：优先用显式 id，其次用类型 + 序号兜底。
    pub fn action_id(&self, index: usize) -> String {
        self.id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("{}_{}", self.action_type.to_ascii_lowercase(), index + 1))
    }
}

/// 规则求值上下文：把任务与模型结果摊平成可按路径取值的字段集合。
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub media_text: String,
    pub media_text_len: usize,
    pub media_count: usize,
    pub media_types: Vec<String>,
    pub media_size_bytes: i64,
    pub media_hash: String,
    pub ext: serde_json::Map<String, Value>,
    pub model_label: Option<String>,
    pub model_score: Option<f64>,
    pub model_risk_level: Option<String>,
    pub source_type: String,
    pub submit_hour: u32,
}

impl EvalContext {
    /// 按内置字段路径取值。未知路径返回 `None`。
    pub fn resolve(&self, field: &str) -> Option<Value> {
        match field {
            "media.text" => return Some(Value::String(self.media_text.clone())),
            "media.text_len" => return Some(Value::from(self.media_text_len)),
            "media.count" => return Some(Value::from(self.media_count)),
            "media.type" => {
                return Some(
                    serde_json::to_value(&self.media_types).unwrap_or(Value::Array(Vec::new())),
                );
            }
            "media.size_bytes" => return Some(Value::from(self.media_size_bytes)),
            "media.hash" => return Some(Value::String(self.media_hash.clone())),
            "model.label" => {
                return self
                    .model_label
                    .as_ref()
                    .map(|value| Value::String(value.clone()));
            }
            "model.score" => {
                return self.model_score.map(|value| Value::from(value));
            }
            "model.risk_level" => {
                return self
                    .model_risk_level
                    .as_ref()
                    .map(|value| Value::String(value.clone()));
            }
            "task.source_type" => return Some(Value::String(self.source_type.clone())),
            "task.submit_hour" => return Some(Value::from(self.submit_hour)),
            _ => {}
        }

        if let Some(rest) = field.strip_prefix("ext.") {
            return self.ext.get(rest).cloned();
        }
        None
    }
}

/// 规则组求值轨迹。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroupTrace {
    #[serde(default)]
    pub rule_id: Option<u64>,
    pub rule: String,
    pub logic: String,
    pub hit: bool,
    #[serde(default)]
    pub skipped: bool,
    #[serde(default)]
    pub items: Vec<RuleItemTrace>,
}

/// 条件项求值轨迹。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleItemTrace {
    pub field: String,
    pub operator: String,
    pub actual: Value,
    pub expected: Value,
    pub hit: bool,
}

/// 规则试跑结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    pub final_result: String,
    #[serde(default)]
    pub matched_rule: Option<String>,
    pub trace: Vec<RuleGroupTrace>,
}

/// 规则 DSL 与动作 DSL 里的操作符清单，供前端下拉使用。
pub const OPERATORS: &[&str] = &[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "between",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "contains_any",
    "contains_all",
    "starts_with",
    "ends_with",
    "regex",
    "length_gt",
    "length_lt",
    "is_null",
    "is_not_null",
    "is_empty",
    "is_not_empty",
    "score_gt",
    "score_lt",
    "label_in",
    "risk_in",
];

/// 内置字段清单，供前端字段选择器使用。
pub const BUILTIN_FIELDS: &[(&str, &str)] = &[
    ("media.text", "全部文本内容拼接"),
    ("media.text_len", "文本长度"),
    ("media.count", "媒体数量"),
    ("media.type", "媒体类型集合"),
    ("media.size_bytes", "媒体总大小"),
    ("media.hash", "媒体指纹"),
    ("model.label", "模型返回标签"),
    ("model.score", "模型置信度"),
    ("model.risk_level", "归一化风险等级"),
    ("task.source_type", "触发来源"),
    ("task.submit_hour", "提交小时"),
];

/// Redis 动作允许的命令白名单。
pub const REDIS_COMMAND_WHITELIST: &[&str] = &[
    "SET", "HSET", "LPUSH", "SADD", "ZADD", "PUBLISH", "EXPIRE", "DEL",
];
