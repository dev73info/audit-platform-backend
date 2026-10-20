//! 审核配置域的业务编排层：保存前校验、状态流转、事务边界与审计写入。
//!
//! 分层约定见 `doc/开发约定.md`：handler 只做参数解析与权限判定，
//! 业务校验、状态流转与事务都在这一层，SQL 在 `repositories.rs`。

use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::db::AppState;
use crate::engine::template::{TemplateContext, render_string, render_value, validate_template};
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::audit::{
    AuditConfigSnapshot, AuditDefinitionRow, AuditRuleRow, AuditRuleView, AuditView,
    ResultRouteRow, ResultRouteView, RuleItemView, SaveAuditRequest, SaveRuleRequest,
    SaveTriggerRequest, TriggerSourceRow, TriggerSourceView,
};
use crate::models::ops::AuditLogEntry;
use crate::models::rule::{
    ActionSpec, DryRunResult, EvalContext, REDIS_COMMAND_WHITELIST, RuleGroupSpec, RuleItemSpec,
};
use crate::response::{ListQuery, Page};

use super::repositories as repo;

/// 审核状态：草稿。
const STATUS_DRAFT: &str = "DRAFT";
/// 审核状态：启用。
const STATUS_ACTIVE: &str = "ACTIVE";
/// 审核状态：暂停。
const STATUS_PAUSED: &str = "PAUSED";

/// 回收站保留天数。
const RECYCLE_RETAIN_DAYS: i64 = 30;

/// 审核详情：审核本体 + 触发源 + 规则 + 结果路由 + 统计。
#[derive(Debug, Clone, Serialize)]
pub struct AuditDetail {
    #[serde(flatten)]
    pub base: AuditView,
    pub triggers: Vec<TriggerSourceView>,
    pub rules: Vec<AuditRuleView>,
    pub routes: HashMap<String, ResultRouteView>,
    pub stats: AuditStats,
}

/// 审核统计。
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditStats {
    pub task_total: u64,
    pub task_today: u64,
    pub pass_count: u64,
    /// 通过率（0~1）。
    pub pass_rate: f64,
}

/// 规则试跑入参。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DryRunRequest {
    #[serde(default)]
    pub sample: DryRunSample,
}

/// 规则试跑样例。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DryRunSample {
    #[serde(default)]
    pub media: Vec<SampleMedia>,
    #[serde(default)]
    pub ext: Value,
    #[serde(default)]
    pub model: Option<SampleModel>,
    #[serde(default)]
    pub task: Option<SampleTask>,
}

/// 样例媒体。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SampleMedia {
    /// `text` / `image` / `video` / `audio`。
    #[serde(rename = "type", default)]
    pub media_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub url: String,
}

/// 样例模型结果。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SampleModel {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub risk_level: Option<String>,
}

/// 样例任务信息。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SampleTask {
    #[serde(default)]
    pub task_id: Option<u64>,
    #[serde(default)]
    pub task_no: Option<String>,
    #[serde(default)]
    pub biz_key: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub submit_hour: Option<u32>,
}

/// 应用路由模板入参。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApplyRouteTemplateRequest {
    /// `reject_all_except_pass` / `same_actions_all` / `callback_only` / `pass_release_review_manual`。
    pub template: String,
    /// 模板要写入的动作。
    #[serde(default)]
    pub actions: Vec<ActionSpec>,
    /// `callback_only` 模板的回调地址。
    #[serde(default)]
    pub url: Option<String>,
}

/// 路由预览入参。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PreviewRouteRequest {
    pub result_type: String,
    #[serde(default)]
    pub sample: DryRunSample,
}

// ---------------------------------------------------------------------------
// SSRF 防护
// ---------------------------------------------------------------------------

/// 主机是否被禁止（内网 / 回环 / 链路本地）。
///
/// 空主机名视为禁止，避免「解析失败就放行」。
pub fn is_blocked_host(host: &str) -> bool {
    let normalized = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }

    // IPv6 回环。
    if normalized == "::1" || normalized == "0:0:0:0:0:0:0:1" {
        return true;
    }

    if let Some(octets) = parse_ipv4(&normalized) {
        return is_blocked_ipv4(octets);
    }

    false
}

/// 从 URL 里取主机名：去 scheme、去 userinfo、去端口。
fn host_of(url: &str) -> String {
    let raw = url.trim();
    if raw.is_empty() {
        return String::new();
    }

    let rest = match raw.find("://") {
        Some(index) => &raw[index + 3..],
        None => raw,
    };

    // 去 userinfo。
    let rest = match rest.rsplit_once('@') {
        Some((_, after)) => after,
        None => rest,
    };

    // 去路径、查询串与片段。
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");

    // IPv6 字面量：[::1]:8080。
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }

    // 去端口。
    match authority.rsplit_once(':') {
        Some((host, _port)) => host.to_string(),
        None => authority.to_string(),
    }
}

/// 解析 IPv4 四段地址。
fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        octets[index] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

/// IPv4 是否落在禁止网段。
fn is_blocked_ipv4(octets: [u8; 4]) -> bool {
    match octets[0] {
        10 => true,                            // 10.0.0.0/8
        172 => (16..=31).contains(&octets[1]), // 172.16.0.0/12
        192 => octets[1] == 168,               // 192.168.0.0/16
        127 => true,                           // 127.0.0.0/8
        169 => octets[1] == 254,               // 169.254.0.0/16
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 保存前校验
// ---------------------------------------------------------------------------

/// 校验一组动作：依赖存在性、SQL 安全、模板语法与 SSRF。
async fn validate_actions(
    state: &AppState,
    project_id: u64,
    actions: &[ActionSpec],
) -> Result<(), ApiError> {
    if actions.is_empty() {
        return Ok(());
    }

    let api_names = repo::list_config_names(state, project_id, "API").await?;
    let mysql_names = repo::list_config_names(state, project_id, "MYSQL").await?;

    for (index, action) in actions.iter().enumerate() {
        let action_type = action.action_type.trim().to_ascii_uppercase();
        let field = format!("actions[{index}]");

        match action_type.as_str() {
            "HTTP" => {
                let Some(api_ref) = action
                    .api_ref
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    return Err(ApiError::invalid_param(
                        "HTTP 动作必须指定 api_ref",
                        vec![FieldError::new(format!("{field}.api_ref"), "不能为空")],
                    ));
                };
                if !api_names.iter().any(|name| name == api_ref) {
                    return Err(ApiError::conflict_with(
                        "DEPENDENCY_MISSING",
                        format!("HTTP 动作引用的 API 配置「{api_ref}」不存在"),
                        json!({ "api_ref": api_ref }),
                    ));
                }
                if let Some(base_url) = api_base_url(state, project_id, api_ref).await {
                    if is_blocked_host(&host_of(&base_url)) {
                        return Err(ApiError::invalid_param(
                            format!("HTTP 动作引用的 API 配置「{api_ref}」指向内网地址，禁止使用"),
                            vec![FieldError::new(
                                format!("{field}.api_ref"),
                                "目标地址属于内网网段",
                            )],
                        ));
                    }
                }
            }
            "REDIS" => {
                let command = action
                    .command
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                if !REDIS_COMMAND_WHITELIST.contains(&command.as_str()) {
                    return Err(ApiError::invalid_param(
                        format!("Redis 动作的命令「{command}」不在白名单内"),
                        vec![FieldError::new(
                            format!("{field}.command"),
                            "只允许 SET/HSET/LPUSH/SADD/ZADD/PUBLISH/EXPIRE/DEL",
                        )],
                    ));
                }
            }
            "MYSQL" => {
                let datasource = action
                    .datasource
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                match datasource {
                    Some(name) => {
                        if !mysql_names.iter().any(|item| item == name) {
                            return Err(ApiError::conflict_with(
                                "DEPENDENCY_MISSING",
                                format!("MySQL 动作引用的数据源「{name}」不存在"),
                                json!({ "datasource": name }),
                            ));
                        }
                    }
                    None => {
                        if mysql_names.is_empty() {
                            return Err(ApiError::conflict_with(
                                "DEPENDENCY_MISSING",
                                "项目没有可用的 MySQL 连接配置",
                                json!({ "datasource": Value::Null }),
                            ));
                        }
                    }
                }

                let sql = action.sql.as_deref().unwrap_or_default();
                validate_sql(sql, action.params.as_ref(), &field)?;
            }
            "WEBHOOK" => {
                let Some(url) = action
                    .url
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    return Err(ApiError::invalid_param(
                        "Webhook 动作必须指定 url",
                        vec![FieldError::new(format!("{field}.url"), "不能为空")],
                    ));
                };
                if is_blocked_host(&host_of(url)) {
                    return Err(ApiError::invalid_param(
                        "Webhook 动作的目标地址属于内网网段，禁止使用",
                        vec![FieldError::new(
                            format!("{field}.url"),
                            "目标地址属于内网网段",
                        )],
                    ));
                }
            }
            "MQ" | "OSS" => {}
            other => {
                return Err(ApiError::invalid_param(
                    format!("不支持的动作类型「{other}」"),
                    vec![FieldError::new(format!("{field}.type"), "动作类型不合法")],
                ));
            }
        }

        validate_action_templates(action, &field)?;
    }

    Ok(())
}

/// 校验动作里的模板变量。
fn validate_action_templates(action: &ActionSpec, field: &str) -> Result<(), ApiError> {
    let check = |text: &str, name: &str| -> Result<(), ApiError> {
        if !text.contains("{{") {
            return Ok(());
        }
        validate_template(text).map_err(|reason| {
            ApiError::invalid_param(
                format!("模板变量校验失败：{reason}"),
                vec![FieldError::new(format!("{field}.{name}"), reason)],
            )
        })
    };

    if let Some(path) = action.path.as_deref() {
        check(path, "path")?;
    }
    if let Some(key) = action.key.as_deref() {
        check(key, "key")?;
    }
    if let Some(url) = action.url.as_deref() {
        check(url, "url")?;
    }
    if let Some(headers) = action.headers.as_ref() {
        validate_json_templates(headers, field, "headers")?;
    }
    if let Some(body) = action.body.as_ref() {
        validate_json_templates(body, field, "body")?;
    }
    if let Some(value) = action.value.as_ref() {
        validate_json_templates(value, field, "value")?;
    }
    Ok(())
}

/// 递归校验 JSON 里的模板变量。
fn validate_json_templates(value: &Value, field: &str, name: &str) -> Result<(), ApiError> {
    match value {
        Value::String(text) => {
            if !text.contains("{{") {
                return Ok(());
            }
            validate_template(text).map_err(|reason| {
                ApiError::invalid_param(
                    format!("模板变量校验失败：{reason}"),
                    vec![FieldError::new(format!("{field}.{name}"), reason)],
                )
            })
        }
        Value::Array(items) => {
            for item in items {
                validate_json_templates(item, field, name)?;
            }
            Ok(())
        }
        Value::Object(fields) => {
            for item in fields.values() {
                validate_json_templates(item, field, name)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// SQL 动作安全校验：只允许 INSERT / UPDATE。
fn validate_sql(sql: &str, params: Option<&Vec<Value>>, field: &str) -> Result<(), ApiError> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(ApiError::unprocessable("INVALID_SQL", "SQL 动作不能为空"));
    }

    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("INSERT") && !upper.starts_with("UPDATE") {
        return Err(ApiError::unprocessable(
            "INVALID_SQL",
            "SQL 动作只允许 INSERT 或 UPDATE 语句",
        ));
    }
    for banned in ["DROP", "ALTER", "TRUNCATE", "DELETE"] {
        if contains_word(&upper, banned) {
            return Err(ApiError::unprocessable(
                "INVALID_SQL",
                format!("SQL 中不允许出现 {banned} 关键字"),
            ));
        }
    }
    if upper.starts_with("UPDATE") && !upper.contains("WHERE") {
        return Err(ApiError::unprocessable(
            "INVALID_SQL",
            "UPDATE 语句必须带 WHERE 条件",
        ));
    }

    let placeholders = trimmed.chars().filter(|ch| *ch == '?').count();
    let param_count = params.map(|items| items.len()).unwrap_or(0);
    if placeholders != param_count {
        return Err(ApiError::unprocessable(
            "INVALID_SQL",
            format!("SQL 占位符数量（{placeholders}）与参数数量（{param_count}）不一致"),
        ));
    }
    let _ = field;
    Ok(())
}

/// 文本里是否出现独立单词。
fn contains_word(text: &str, word: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| token == word)
}

/// API 配置里的 BaseURL。取不到就返回 `None`（不阻断保存）。
async fn api_base_url(state: &AppState, project_id: u64, name: &str) -> Option<String> {
    let cipher = repo::find_config_cipher(state, project_id, "API", name)
        .await
        .ok()
        .flatten()?;
    let key = state.settings.master_key();
    match crate::security::encrypt::decrypt_json(&key, project_id, &cipher) {
        Ok(value) => base_url_of(&value),
        Err(err) => {
            tracing::warn!(error = %err, config = name, "API 配置解密失败，跳过地址校验");
            None
        }
    }
}

/// 从配置 JSON 里取 BaseURL。
fn base_url_of(value: &Value) -> Option<String> {
    let fields = value.as_object()?;
    for key in ["base_url", "baseUrl", "url", "host"] {
        if let Some(text) = fields.get(key).and_then(Value::as_str) {
            if !text.trim().is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

/// 审核并发是否超出项目配额。
async fn check_concurrency_quota(
    state: &AppState,
    project_id: u64,
    concurrency: i32,
) -> Result<(), ApiError> {
    let quota = repo::load_quota(state, project_id).await?;
    if concurrency as i64 > quota.max_concurrency {
        return Err(ApiError::forbidden(
            "QUOTA_EXCEEDED",
            format!(
                "审核并发数（{concurrency}）超过项目配额（{}）",
                quota.max_concurrency
            ),
        ));
    }
    Ok(())
}

/// 校验审核状态取值。
fn validate_status(status: &str, field: &str) -> Result<(), ApiError> {
    let upper = status.trim().to_ascii_uppercase();
    if matches!(upper.as_str(), STATUS_DRAFT | STATUS_ACTIVE | STATUS_PAUSED) {
        return Ok(());
    }
    Err(ApiError::invalid_param(
        format!("审核状态「{status}」不合法"),
        vec![FieldError::new(field, "只能是 DRAFT / ACTIVE / PAUSED")],
    ))
}

// ---------------------------------------------------------------------------
// 视图与快照
// ---------------------------------------------------------------------------

/// 取审核的配置快照。
fn snapshot_of(row: &AuditDefinitionRow) -> AuditConfigSnapshot {
    row.config_json
        .as_ref()
        .and_then(|value| serde_json::from_value::<AuditConfigSnapshot>(value.clone()).ok())
        .unwrap_or_default()
}

/// 解析路由集合。键是结果类型（PASS / REJECT / REVIEW）。
fn parse_routes(value: &Value) -> HashMap<String, ResultRouteView> {
    let mut routes = HashMap::new();
    let Some(fields) = value.as_object() else {
        return routes;
    };
    for (result_type, item) in fields {
        routes.insert(result_type.clone(), normalize_route(result_type, item));
    }
    routes
}

/// 归一化单条路由（缺省字段补默认值）。
fn normalize_route(result_type: &str, value: &Value) -> ResultRouteView {
    let fields = value.as_object();
    let exec_mode = fields
        .and_then(|item| item.get("exec_mode"))
        .and_then(Value::as_str)
        .unwrap_or("sequential")
        .to_string();
    let on_error = fields
        .and_then(|item| item.get("on_error"))
        .and_then(Value::as_str)
        .unwrap_or("to_review")
        .to_string();
    let actions = fields
        .and_then(|item| item.get("actions"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let actions: Vec<ActionSpec> = serde_json::from_value(actions).unwrap_or_default();
    let status = fields
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str)
        .map(|text| text.to_string());
    let id = fields
        .and_then(|item| item.get("id"))
        .and_then(Value::as_u64);

    ResultRouteView {
        id,
        result_type: result_type.to_string(),
        exec_mode,
        on_error,
        actions,
        status,
    }
}

/// 媒体类型数组。
fn to_media_types(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|text| text.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// 构造审核视图。
fn to_audit_view(row: &AuditDefinitionRow, project_name: Option<String>) -> AuditView {
    let snapshot = snapshot_of(row);
    AuditView {
        id: row.id,
        project_id: row.project_id,
        project_name,
        name: row.name.clone(),
        code: row.code.clone(),
        media_types: to_media_types(&row.media_types),
        status: row.status.clone(),
        concurrency: row.concurrency,
        timeout_ms: row.timeout_ms,
        dedupe_window_sec: row.dedupe_window_sec,
        media_hash_in_key: row.media_hash_in_key,
        retry_policy: row.retry_policy.clone().unwrap_or_else(|| json!({})),
        default_result: snapshot.default_result,
        on_model_fail: snapshot.on_model_fail,
        media_review: snapshot.media_review,
        description: row.description.clone(),
        config_version: row.config_version,
        created_at: crate::common::format_datetime(row.created_at),
        updated_at: crate::common::format_datetime(row.updated_at),
    }
}

/// 构造触发源视图。触发源模块也复用这个函数。
pub fn trigger_view(row: &TriggerSourceRow) -> TriggerSourceView {
    TriggerSourceView {
        id: row.id,
        project_id: row.project_id,
        audit_id: row.audit_id,
        trigger_type: row.r#type.clone(),
        name: row.name.clone(),
        priority: row.priority,
        status: row.status.clone(),
        config: row.config_json.clone(),
        success_count: row.success_count,
        fail_count: row.fail_count,
        last_consume_at: row.last_consume_at.map(crate::common::format_datetime),
        last_error: row.last_error.clone(),
        created_at: crate::common::format_datetime(row.created_at),
        updated_at: crate::common::format_datetime(row.updated_at),
    }
}

/// 构造规则视图。
fn to_rule_view(row: &AuditRuleRow, items: Vec<RuleItemView>) -> AuditRuleView {
    AuditRuleView {
        id: row.id,
        audit_id: row.audit_id,
        name: row.name.clone(),
        priority: row.priority,
        logic: row.logic.clone(),
        stop_on_hit: row.stop_on_hit,
        on_hit_result: row.on_hit_result.clone(),
        status: row.status.clone(),
        items,
        created_at: crate::common::format_datetime(row.created_at),
        updated_at: crate::common::format_datetime(row.updated_at),
    }
}

/// 构造规则项视图。
fn to_rule_item_view(row: &crate::models::audit::RuleItemRow) -> RuleItemView {
    RuleItemView {
        id: Some(row.id),
        field: row.field.clone(),
        operator: row.operator.clone(),
        value: row.value_json.clone(),
        case_sensitive: row.case_sensitive,
        negate: row.negate,
        sort_order: row.sort_order,
    }
}

/// 刷新审核的配置快照：触发源或规则变动后，把子表当前状态回写到 `config_json`。
///
/// 触发源模块在增删改触发源后调用，保持审核快照与子表一致。
pub async fn refresh_snapshot(state: &AppState, audit_id: u64) -> Result<(), ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    let snapshot = build_snapshot(state, &row).await?;

    let mut tx = state.db.begin().await?;
    repo::update_audit(
        &mut tx,
        audit_id,
        &repo::AuditUpdate {
            name: row.name.clone(),
            code: row.code.clone(),
            media_types: row.media_types.clone(),
            status: row.status.clone(),
            concurrency: row.concurrency,
            timeout_ms: row.timeout_ms,
            retry_policy: row.retry_policy.clone(),
            dedupe_window_sec: row.dedupe_window_sec,
            media_hash_in_key: row.media_hash_in_key,
            config_json: Some(serde_json::to_value(&snapshot)?),
            description: row.description.clone(),
            config_version: row.config_version,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 按子表当前状态构造配置快照。
async fn build_snapshot(
    state: &AppState,
    row: &AuditDefinitionRow,
) -> Result<AuditConfigSnapshot, ApiError> {
    let mut snapshot = snapshot_of(row);

    let rule_rows = repo::list_rules(state, row.id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;
    snapshot.rules = rule_rows
        .iter()
        .map(|item| RuleGroupSpec {
            id: Some(item.id),
            name: item.name.clone(),
            priority: item.priority,
            logic: item.logic.clone(),
            stop_on_hit: item.stop_on_hit,
            on_hit_result: item.on_hit_result.clone(),
            status: Some(item.status.clone()),
            items: item_map
                .get(&item.id)
                .map(|rows| {
                    rows.iter()
                        .map(|row| RuleItemSpec {
                            field: row.field.clone(),
                            operator: row.operator.clone(),
                            value: row.value_json.clone(),
                            case_sensitive: row.case_sensitive,
                            negate: row.negate,
                            sort_order: row.sort_order,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();

    let route_rows = repo::list_routes(state, row.id).await?;
    let mut routes = HashMap::new();
    for item in &route_rows {
        routes.insert(item.result_type.clone(), to_route_view(item));
    }
    snapshot.routes = serde_json::to_value(&routes).unwrap_or_else(|_| json!({}));

    Ok(snapshot)
}

/// 构造路由视图。
fn to_route_view(row: &ResultRouteRow) -> ResultRouteView {
    let actions: Vec<ActionSpec> =
        serde_json::from_value(row.actions_json.clone()).unwrap_or_default();
    ResultRouteView {
        id: Some(row.id),
        result_type: row.result_type.clone(),
        exec_mode: row.exec_mode.clone(),
        on_error: row.on_error.clone(),
        actions,
        status: Some(row.status.clone()),
    }
}

/// 规则组落库参数。
fn rule_spec(req: &SaveRuleRequest) -> RuleGroupSpec {
    RuleGroupSpec {
        id: req.id,
        name: req.name.clone(),
        priority: req.priority.unwrap_or(100),
        logic: req.logic.clone().unwrap_or_else(|| "AND".to_string()),
        stop_on_hit: req.stop_on_hit.unwrap_or(true),
        on_hit_result: req
            .on_hit_result
            .clone()
            .unwrap_or_else(|| "REVIEW".to_string()),
        status: req.status.clone(),
        items: req
            .items
            .iter()
            .map(|item| RuleItemSpec {
                field: item.field.clone(),
                operator: item.operator.clone(),
                value: item.value.clone(),
                case_sensitive: item.case_sensitive,
                negate: item.negate,
                sort_order: item.sort_order,
            })
            .collect(),
    }
}

/// 规则组状态默认值。
fn rule_status(req: &SaveRuleRequest) -> String {
    req.status
        .as_deref()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| STATUS_ACTIVE.to_string())
}

/// 审计日志条目。
fn audit_entry(
    ctx: &AuthContext,
    project_id: u64,
    action: &str,
    object_type: &str,
    object_id: u64,
    detail: Value,
) -> AuditLogEntry {
    AuditLogEntry {
        project_id: Some(project_id),
        operator: ctx.username.clone(),
        operator_id: Some(ctx.user_id),
        operator_ip: None,
        action: action.to_string(),
        object_type: Some(object_type.to_string()),
        object_id: Some(object_id.to_string()),
        result: "SUCCESS".to_string(),
        detail: Some(detail),
        trace_id: Some(ctx.trace_id.clone()),
    }
}

/// 今天的零点。
fn today_start() -> NaiveDateTime {
    let now = chrono::Utc::now().naive_utc();
    now.date().and_hms_opt(0, 0, 0).unwrap_or(now)
}

// ---------------------------------------------------------------------------
// 审核定义
// ---------------------------------------------------------------------------

/// 审核列表。
pub async fn list_audits(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    query: &ListQuery,
) -> Result<Page<AuditView>, ApiError> {
    ctx.require_project(project_id)?;

    let filter = build_filter(query);
    let (rows, total) = repo::list_audits(state, project_id, &filter).await?;
    let project_name = repo::find_project_name(state, project_id).await?;

    let items = rows
        .iter()
        .map(|row| to_audit_view(row, project_name.clone()))
        .collect();

    Ok(Page::new(items, total, query.page(), query.page_size()))
}

/// 构造审核列表筛选条件。
fn build_filter(query: &ListQuery) -> repo::AuditListFilter {
    let (sort_field, sort_desc) = query.sort_field(
        &[
            "name",
            "code",
            "status",
            "updated_at",
            "concurrency",
            "created_at",
        ],
        ("created_at", true),
    );
    repo::AuditListFilter {
        statuses: query.filter_list("status"),
        media_types: query.filter_list("media_type"),
        keyword: query
            .keyword
            .clone()
            .filter(|value| !value.trim().is_empty()),
        created_at_from: query
            .filter("created_at_from")
            .and_then(crate::common::parse_datetime)
            .map(|value| value.naive_utc()),
        created_at_to: query
            .filter("created_at_to")
            .and_then(crate::common::parse_datetime)
            .map(|value| value.naive_utc()),
        sort_field,
        sort_desc,
        offset: query.offset(),
        page_size: query.page_size(),
    }
}

/// 新建审核。
pub async fn create_audit(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: SaveAuditRequest,
) -> Result<AuditView, ApiError> {
    ctx.require_project(project_id)?;

    let name = req.name.trim().to_string();
    let code = req.code.trim().to_string();
    if name.is_empty() || code.is_empty() {
        return Err(ApiError::invalid_param(
            "审核名称与编码不能为空",
            vec![FieldError::new("name", "名称与编码不能为空")],
        ));
    }

    let status = req
        .status
        .as_deref()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| STATUS_DRAFT.to_string());
    validate_status(&status, "status")?;

    let concurrency = req.concurrency.unwrap_or(10);
    check_concurrency_quota(state, project_id, concurrency).await?;

    if repo::audit_code_exists(state, project_id, &code, 0).await? {
        return Err(ApiError::conflict("CODE_CONFLICT", "审核编码已存在"));
    }
    if repo::audit_name_exists(state, project_id, &name, 0).await? {
        return Err(ApiError::conflict("CODE_CONFLICT", "审核名称已存在"));
    }
    if repo::code_in_recycle_bin(state, project_id, &code).await? {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            "审核编码在回收站中已被占用",
        ));
    }

    let routes = req.routes.as_ref().map(parse_routes).unwrap_or_default();
    for route in routes.values() {
        validate_actions(state, project_id, &route.actions).await?;
    }

    let snapshot = AuditConfigSnapshot {
        default_result: req
            .default_result
            .clone()
            .unwrap_or_else(|| "REVIEW".to_string()),
        on_model_fail: req
            .on_model_fail
            .clone()
            .unwrap_or_else(|| "REVIEW".to_string()),
        media_review: req.media_review.clone().unwrap_or_else(|| json!({})),
        rules: req
            .rules
            .as_ref()
            .map(|rules| rules.iter().map(rule_spec).collect())
            .unwrap_or_default(),
        routes: serde_json::to_value(&routes).unwrap_or_else(|_| json!({})),
    };

    let audit_id = crate::common::ids::next_id();
    let mut tx = state.db.begin().await?;

    repo::insert_audit(
        &mut tx,
        &repo::AuditInsert {
            id: audit_id,
            project_id,
            name: name.clone(),
            code: code.clone(),
            media_types: json!(req.media_types),
            status: status.clone(),
            concurrency,
            timeout_ms: req.timeout_ms.unwrap_or(30000),
            retry_policy: req.retry_policy.clone(),
            dedupe_window_sec: req.dedupe_window_sec.unwrap_or(86400),
            media_hash_in_key: req.media_hash_in_key.unwrap_or(true),
            config_json: Some(serde_json::to_value(&snapshot)?),
            description: req.description.clone(),
            created_by: ctx.user_id,
        },
    )
    .await?;

    if let Some(triggers) = req.triggers.as_ref() {
        insert_triggers(&mut tx, project_id, audit_id, triggers).await?;
    }
    if let Some(rules) = req.rules.as_ref() {
        insert_rules(&mut tx, project_id, audit_id, rules).await?;
    }
    if !routes.is_empty() {
        upsert_routes(&mut tx, project_id, audit_id, &routes).await?;
    }

    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "AUDIT_CREATE",
            "AUDIT",
            audit_id,
            json!({ "name": name, "code": code }),
        ),
    )
    .await?;

    let row = repo::find_audit(state, audit_id).await?;
    let project_name = repo::find_project_name(state, project_id).await?;
    Ok(to_audit_view(&row, project_name))
}

/// 审核详情。
pub async fn get_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<AuditDetail, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;

    let project_name = repo::find_project_name(state, row.project_id).await?;
    let base = to_audit_view(&row, project_name);

    let trigger_rows = repo::list_triggers(state, audit_id).await?;
    let triggers = trigger_rows.iter().map(trigger_view).collect();

    let rule_rows = repo::list_rules(state, audit_id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;
    let rules = rule_rows
        .iter()
        .map(|item| {
            let items = item_map
                .get(&item.id)
                .map(|rows| rows.iter().map(to_rule_item_view).collect())
                .unwrap_or_default();
            to_rule_view(item, items)
        })
        .collect();

    let route_rows = repo::list_routes(state, audit_id).await?;
    let mut routes = HashMap::new();
    for item in &route_rows {
        routes.insert(item.result_type.clone(), to_route_view(item));
    }

    let stats_map = repo::load_task_stats(state, &[audit_id], today_start()).await?;
    let stats_raw = stats_map.get(&audit_id).copied().unwrap_or_default();
    let pass_rate = if stats_raw.task_total > 0 {
        stats_raw.pass_count as f64 / stats_raw.task_total as f64
    } else {
        0.0
    };

    Ok(AuditDetail {
        base,
        triggers,
        rules,
        routes,
        stats: AuditStats {
            task_total: stats_raw.task_total,
            task_today: stats_raw.task_today,
            pass_count: stats_raw.pass_count,
            pass_rate,
        },
    })
}

/// 更新审核。
pub async fn update_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    req: SaveAuditRequest,
) -> Result<AuditView, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    // 乐观锁：请求里的版本必须与当前一致。
    if let Some(version) = req.config_version {
        if version != row.config_version {
            return Err(ApiError::conflict_with(
                "VERSION_CONFLICT",
                "审核配置已被他人修改，请重新拉取后再保存",
                json!({ "current_version": row.config_version }),
            ));
        }
    }

    let name = if req.name.trim().is_empty() {
        row.name.clone()
    } else {
        req.name.trim().to_string()
    };
    let code = if req.code.trim().is_empty() {
        row.code.clone()
    } else {
        req.code.trim().to_string()
    };

    let status = match req.status.as_deref() {
        Some(value) if !value.trim().is_empty() => value.trim().to_ascii_uppercase(),
        _ => row.status.clone(),
    };
    validate_status(&status, "status")?;

    let concurrency = req.concurrency.unwrap_or(row.concurrency);
    check_concurrency_quota(state, project_id, concurrency).await?;

    if repo::audit_code_exists(state, project_id, &code, audit_id).await? {
        return Err(ApiError::conflict("CODE_CONFLICT", "审核编码已存在"));
    }
    if repo::audit_name_exists(state, project_id, &name, audit_id).await? {
        return Err(ApiError::conflict("CODE_CONFLICT", "审核名称已存在"));
    }

    let routes = req.routes.as_ref().map(parse_routes);
    if let Some(map) = routes.as_ref() {
        for route in map.values() {
            validate_actions(state, project_id, &route.actions).await?;
        }
    }

    let mut snapshot = snapshot_of(&row);
    if let Some(value) = req.default_result.as_ref() {
        snapshot.default_result = value.clone();
    }
    if let Some(value) = req.on_model_fail.as_ref() {
        snapshot.on_model_fail = value.clone();
    }
    if let Some(value) = req.media_review.as_ref() {
        snapshot.media_review = value.clone();
    }
    if let Some(rules) = req.rules.as_ref() {
        snapshot.rules = rules.iter().map(rule_spec).collect();
    }
    if let Some(map) = routes.as_ref() {
        snapshot.routes = serde_json::to_value(map).unwrap_or_else(|_| json!({}));
    }

    // 子表对账需要先读出现有数据（在事务外读，事务内只做写入）。
    let existing_triggers = if req.triggers.is_some() {
        repo::list_triggers(state, audit_id).await?
    } else {
        Vec::new()
    };
    let existing_rules = if req.rules.is_some() {
        repo::list_rules(state, audit_id).await?
    } else {
        Vec::new()
    };

    let mut tx = state.db.begin().await?;

    repo::update_audit(
        &mut tx,
        audit_id,
        &repo::AuditUpdate {
            name: name.clone(),
            code: code.clone(),
            media_types: if req.media_types.is_empty() {
                row.media_types.clone()
            } else {
                json!(req.media_types)
            },
            status: status.clone(),
            concurrency,
            timeout_ms: req.timeout_ms.unwrap_or(row.timeout_ms),
            retry_policy: req
                .retry_policy
                .clone()
                .or_else(|| row.retry_policy.clone()),
            dedupe_window_sec: req.dedupe_window_sec.unwrap_or(row.dedupe_window_sec),
            media_hash_in_key: req.media_hash_in_key.unwrap_or(row.media_hash_in_key),
            config_json: Some(serde_json::to_value(&snapshot)?),
            description: req.description.clone().or_else(|| row.description.clone()),
            config_version: row.config_version + 1,
        },
    )
    .await?;

    if let Some(triggers) = req.triggers.as_ref() {
        sync_triggers(&mut tx, project_id, audit_id, triggers, &existing_triggers).await?;
    }
    if let Some(rules) = req.rules.as_ref() {
        sync_rules(&mut tx, project_id, audit_id, rules, &existing_rules).await?;
    }
    if let Some(map) = routes.as_ref() {
        repo::soft_delete_routes_of_audit(&mut tx, audit_id).await?;
        upsert_routes(&mut tx, project_id, audit_id, map).await?;
    }

    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "AUDIT_UPDATE",
            "AUDIT",
            audit_id,
            json!({ "name": name, "code": code }),
        ),
    )
    .await?;

    let updated = repo::find_audit(state, audit_id).await?;
    let project_name = repo::find_project_name(state, project_id).await?;
    Ok(to_audit_view(&updated, project_name))
}

/// 删除审核（软删 + 写回收站）。
pub async fn delete_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<Value, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    let snapshot = build_snapshot_json(state, &row).await?;

    let mut tx = state.db.begin().await?;
    repo::soft_delete_audit(&mut tx, audit_id, ctx.user_id).await?;
    repo::soft_delete_triggers_of_audit(&mut tx, audit_id).await?;
    repo::soft_delete_rules_of_audit(&mut tx, audit_id).await?;
    repo::soft_delete_routes_of_audit(&mut tx, audit_id).await?;

    let expire_at = chrono::Utc::now().naive_utc() + chrono::Duration::days(RECYCLE_RETAIN_DAYS);
    let recycle_id = repo::insert_recycle_bin(
        &mut tx,
        &repo::RecycleBinInsert {
            id: crate::common::ids::next_id(),
            project_id,
            object_type: "AUDIT".to_string(),
            object_id: audit_id,
            object_name: row.name.clone(),
            object_code: Some(row.code.clone()),
            snapshot_json: snapshot,
            deleted_by: ctx.user_id,
            expire_at,
        },
    )
    .await?;

    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "AUDIT_DELETE",
            "AUDIT",
            audit_id,
            json!({ "name": row.name, "code": row.code, "recycle_id": recycle_id }),
        ),
    )
    .await?;

    Ok(json!({
        "recycle_id": recycle_id,
        "audit_id": audit_id,
        "expire_at": crate::common::format_datetime(expire_at),
    }))
}

/// 构造审核的完整快照（写回收站用）。
async fn build_snapshot_json(
    state: &AppState,
    row: &AuditDefinitionRow,
) -> Result<Value, ApiError> {
    let trigger_rows = repo::list_triggers(state, row.id).await?;
    let rule_rows = repo::list_rules(state, row.id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;
    let route_rows = repo::list_routes(state, row.id).await?;

    Ok(json!({
        "audit": row.config_json.clone().unwrap_or_else(|| json!({})),
        "base": {
            "id": row.id,
            "project_id": row.project_id,
            "name": row.name,
            "code": row.code,
            "media_types": row.media_types,
            "status": row.status,
            "concurrency": row.concurrency,
            "timeout_ms": row.timeout_ms,
            "retry_policy": row.retry_policy,
            "dedupe_window_sec": row.dedupe_window_sec,
            "media_hash_in_key": row.media_hash_in_key,
            "config_version": row.config_version,
            "description": row.description,
        },
        "triggers": trigger_rows
            .iter()
            .map(|item| json!({
                "type": item.r#type,
                "name": item.name,
                "priority": item.priority,
                "status": item.status,
                "config": item.config_json,
            }))
            .collect::<Vec<Value>>(),
        "rules": rule_rows
            .iter()
            .map(|item| json!({
                "id": item.id,
                "name": item.name,
                "priority": item.priority,
                "logic": item.logic,
                "stop_on_hit": item.stop_on_hit,
                "on_hit_result": item.on_hit_result,
                "status": item.status,
                "items": item_map
                    .get(&item.id)
                    .map(|rows| rows
                        .iter()
                        .map(|row| json!({
                            "field": row.field,
                            "operator": row.operator,
                            "value": row.value_json,
                            "case_sensitive": row.case_sensitive,
                            "negate": row.negate,
                            "sort_order": row.sort_order,
                        }))
                        .collect::<Vec<Value>>())
                    .unwrap_or_default(),
            }))
            .collect::<Vec<Value>>(),
        "routes": route_rows
            .iter()
            .map(|item| json!({
                "result_type": item.result_type,
                "exec_mode": item.exec_mode,
                "on_error": item.on_error,
                "actions": item.actions_json,
                "status": item.status,
            }))
            .collect::<Vec<Value>>(),
    }))
}

/// 启用审核。
pub async fn enable_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<AuditView, ApiError> {
    set_audit_status(state, ctx, audit_id, STATUS_ACTIVE, "AUDIT_ENABLE").await
}

/// 暂停审核。
pub async fn pause_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<AuditView, ApiError> {
    set_audit_status(state, ctx, audit_id, STATUS_PAUSED, "AUDIT_PAUSE").await
}

/// 改审核状态。
async fn set_audit_status(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    status: &str,
    action: &str,
) -> Result<AuditView, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    let mut tx = state.db.begin().await?;
    repo::set_audit_status(&mut tx, audit_id, status).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            action,
            "AUDIT",
            audit_id,
            json!({ "status": status }),
        ),
    )
    .await?;

    let updated = repo::find_audit(state, audit_id).await?;
    let project_name = repo::find_project_name(state, project_id).await?;
    Ok(to_audit_view(&updated, project_name))
}

/// 克隆审核。
pub async fn clone_audit(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<AuditView, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    let code = unique_code(state, project_id, &row.code).await?;
    let name = unique_name(state, project_id, &row.name).await?;

    let trigger_rows = repo::list_triggers(state, audit_id).await?;
    let rule_rows = repo::list_rules(state, audit_id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;
    let route_rows = repo::list_routes(state, audit_id).await?;

    let new_audit_id = crate::common::ids::next_id();
    let mut tx = state.db.begin().await?;

    repo::insert_audit(
        &mut tx,
        &repo::AuditInsert {
            id: new_audit_id,
            project_id,
            name: name.clone(),
            code: code.clone(),
            media_types: row.media_types.clone(),
            status: STATUS_DRAFT.to_string(),
            concurrency: row.concurrency,
            timeout_ms: row.timeout_ms,
            retry_policy: row.retry_policy.clone(),
            dedupe_window_sec: row.dedupe_window_sec,
            media_hash_in_key: row.media_hash_in_key,
            config_json: row.config_json.clone(),
            description: row.description.clone(),
            created_by: ctx.user_id,
        },
    )
    .await?;

    for item in &trigger_rows {
        repo::insert_trigger(
            &mut tx,
            &repo::TriggerInsert {
                id: crate::common::ids::next_id(),
                project_id,
                audit_id: new_audit_id,
                trigger_type: item.r#type.clone(),
                name: item.name.clone(),
                config_json: item.config_json.clone(),
                priority: item.priority,
                status: STATUS_PAUSED.to_string(),
            },
        )
        .await?;
    }

    for item in &rule_rows {
        let new_rule_id = crate::common::ids::next_id();
        repo::insert_rule(
            &mut tx,
            &repo::RuleInsert {
                id: new_rule_id,
                project_id,
                audit_id: new_audit_id,
                name: item.name.clone(),
                priority: item.priority,
                logic: item.logic.clone(),
                stop_on_hit: item.stop_on_hit,
                on_hit_result: item.on_hit_result.clone(),
                status: item.status.clone(),
            },
        )
        .await?;
        if let Some(items) = item_map.get(&item.id) {
            for row_item in items {
                repo::insert_rule_item(
                    &mut tx,
                    &repo::RuleItemInsert {
                        id: crate::common::ids::next_id(),
                        rule_id: new_rule_id,
                        field: row_item.field.clone(),
                        operator: row_item.operator.clone(),
                        value_json: row_item.value_json.clone(),
                        case_sensitive: row_item.case_sensitive,
                        negate: row_item.negate,
                        sort_order: row_item.sort_order,
                    },
                )
                .await?;
            }
        }
    }

    for item in &route_rows {
        repo::upsert_route(
            &mut tx,
            &repo::RouteUpsert {
                id: crate::common::ids::next_id(),
                project_id,
                audit_id: new_audit_id,
                result_type: item.result_type.clone(),
                exec_mode: item.exec_mode.clone(),
                on_error: item.on_error.clone(),
                actions_json: item.actions_json.clone(),
                status: item.status.clone(),
            },
        )
        .await?;
    }

    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "AUDIT_CLONE",
            "AUDIT",
            new_audit_id,
            json!({ "source_audit_id": audit_id, "name": name, "code": code }),
        ),
    )
    .await?;

    let created = repo::find_audit(state, new_audit_id).await?;
    let project_name = repo::find_project_name(state, project_id).await?;
    Ok(to_audit_view(&created, project_name))
}

/// 生成唯一的审核编码（带 `_copy` 后缀）。
async fn unique_code(state: &AppState, project_id: u64, code: &str) -> Result<String, ApiError> {
    let base = format!("{code}_copy");
    let mut candidate = base.clone();
    let mut index = 2;
    while repo::audit_code_exists(state, project_id, &candidate, 0).await?
        || repo::code_in_recycle_bin(state, project_id, &candidate).await?
    {
        candidate = format!("{base}_{index}");
        index += 1;
        if index > 100 {
            return Err(ApiError::internal("生成唯一审核编码失败"));
        }
    }
    Ok(candidate)
}

/// 生成唯一的审核名称（带 `_副本` 后缀）。
async fn unique_name(state: &AppState, project_id: u64, name: &str) -> Result<String, ApiError> {
    let base = format!("{name}_副本");
    let mut candidate = base.clone();
    let mut index = 2;
    while repo::audit_name_exists(state, project_id, &candidate, 0).await? {
        candidate = format!("{base}_{index}");
        index += 1;
        if index > 100 {
            return Err(ApiError::internal("生成唯一审核名称失败"));
        }
    }
    Ok(candidate)
}

// ---------------------------------------------------------------------------
// 触发源
// ---------------------------------------------------------------------------

/// 写入触发源。
async fn insert_triggers(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    project_id: u64,
    audit_id: u64,
    triggers: &[SaveTriggerRequest],
) -> Result<(), ApiError> {
    for item in triggers {
        repo::insert_trigger(
            tx,
            &repo::TriggerInsert {
                id: crate::common::ids::next_id(),
                project_id,
                audit_id,
                trigger_type: item.trigger_type.trim().to_ascii_uppercase(),
                name: item.name.trim().to_string(),
                config_json: item.config.clone(),
                priority: item.priority.unwrap_or(10),
                status: item
                    .status
                    .as_deref()
                    .map(|value| value.trim().to_ascii_uppercase())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| STATUS_ACTIVE.to_string()),
            },
        )
        .await?;
    }
    Ok(())
}

/// 触发源对账：按 id 增删改。
async fn sync_triggers(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    project_id: u64,
    audit_id: u64,
    triggers: &[SaveTriggerRequest],
    existing: &[TriggerSourceRow],
) -> Result<(), ApiError> {
    let mut keep: Vec<u64> = Vec::new();

    for item in triggers {
        let matched = item
            .id
            .and_then(|id| existing.iter().find(|row| row.id == id).cloned());
        match matched {
            Some(row) => {
                keep.push(row.id);
                repo::update_trigger(
                    tx,
                    row.id,
                    &repo::TriggerUpdate {
                        trigger_type: item.trigger_type.trim().to_ascii_uppercase(),
                        name: item.name.trim().to_string(),
                        config_json: item.config.clone(),
                        priority: item.priority.unwrap_or(row.priority),
                        status: item
                            .status
                            .as_deref()
                            .map(|value| value.trim().to_ascii_uppercase())
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| row.status.clone()),
                    },
                )
                .await?;
            }
            None => {
                let new_id = crate::common::ids::next_id();
                keep.push(new_id);
                repo::insert_trigger(
                    tx,
                    &repo::TriggerInsert {
                        id: new_id,
                        project_id,
                        audit_id,
                        trigger_type: item.trigger_type.trim().to_ascii_uppercase(),
                        name: item.name.trim().to_string(),
                        config_json: item.config.clone(),
                        priority: item.priority.unwrap_or(10),
                        status: item
                            .status
                            .as_deref()
                            .map(|value| value.trim().to_ascii_uppercase())
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| STATUS_ACTIVE.to_string()),
                    },
                )
                .await?;
            }
        }
    }

    for row in existing {
        if !keep.contains(&row.id) {
            repo::soft_delete_trigger(tx, row.id).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 规则
// ---------------------------------------------------------------------------

/// 写入规则组。
async fn insert_rules(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    project_id: u64,
    audit_id: u64,
    rules: &[SaveRuleRequest],
) -> Result<(), ApiError> {
    for item in rules {
        let rule_id = crate::common::ids::next_id();
        repo::insert_rule(
            tx,
            &repo::RuleInsert {
                id: rule_id,
                project_id,
                audit_id,
                name: item.name.trim().to_string(),
                priority: item.priority.unwrap_or(100),
                logic: item
                    .logic
                    .clone()
                    .unwrap_or_else(|| "AND".to_string())
                    .trim()
                    .to_ascii_uppercase(),
                stop_on_hit: item.stop_on_hit.unwrap_or(true),
                on_hit_result: item
                    .on_hit_result
                    .clone()
                    .unwrap_or_else(|| "REVIEW".to_string()),
                status: rule_status(item),
            },
        )
        .await?;
        insert_rule_items(tx, rule_id, &item.items).await?;
    }
    Ok(())
}

/// 写入规则条件项。
async fn insert_rule_items(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_id: u64,
    items: &[crate::models::audit::RuleItemView],
) -> Result<(), ApiError> {
    for (index, item) in items.iter().enumerate() {
        repo::insert_rule_item(
            tx,
            &repo::RuleItemInsert {
                id: crate::common::ids::next_id(),
                rule_id,
                field: item.field.trim().to_string(),
                operator: item.operator.trim().to_ascii_lowercase(),
                value_json: item.value.clone(),
                case_sensitive: item.case_sensitive,
                negate: item.negate,
                sort_order: if item.sort_order == 0 {
                    index as i32
                } else {
                    item.sort_order
                },
            },
        )
        .await?;
    }
    Ok(())
}

/// 规则组对账：按 id 增删改。
async fn sync_rules(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    project_id: u64,
    audit_id: u64,
    rules: &[SaveRuleRequest],
    existing: &[AuditRuleRow],
) -> Result<(), ApiError> {
    let mut keep: Vec<u64> = Vec::new();

    for item in rules {
        let matched = item
            .id
            .and_then(|id| existing.iter().find(|row| row.id == id).cloned());
        let rule_id = match matched {
            Some(row) => {
                keep.push(row.id);
                repo::update_rule(
                    tx,
                    row.id,
                    &repo::RuleUpdate {
                        name: item.name.trim().to_string(),
                        priority: item.priority.unwrap_or(row.priority),
                        logic: item
                            .logic
                            .clone()
                            .unwrap_or_else(|| row.logic.clone())
                            .trim()
                            .to_ascii_uppercase(),
                        stop_on_hit: item.stop_on_hit.unwrap_or(row.stop_on_hit),
                        on_hit_result: item
                            .on_hit_result
                            .clone()
                            .unwrap_or_else(|| row.on_hit_result.clone()),
                        status: item
                            .status
                            .as_deref()
                            .map(|value| value.trim().to_ascii_uppercase())
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| row.status.clone()),
                    },
                )
                .await?;
                row.id
            }
            None => {
                let new_id = crate::common::ids::next_id();
                keep.push(new_id);
                repo::insert_rule(
                    tx,
                    &repo::RuleInsert {
                        id: new_id,
                        project_id,
                        audit_id,
                        name: item.name.trim().to_string(),
                        priority: item.priority.unwrap_or(100),
                        logic: item
                            .logic
                            .clone()
                            .unwrap_or_else(|| "AND".to_string())
                            .trim()
                            .to_ascii_uppercase(),
                        stop_on_hit: item.stop_on_hit.unwrap_or(true),
                        on_hit_result: item
                            .on_hit_result
                            .clone()
                            .unwrap_or_else(|| "REVIEW".to_string()),
                        status: rule_status(item),
                    },
                )
                .await?;
                new_id
            }
        };

        repo::delete_rule_items(tx, rule_id).await?;
        insert_rule_items(tx, rule_id, &item.items).await?;
    }

    for row in existing {
        if !keep.contains(&row.id) {
            repo::soft_delete_rule(tx, row.id).await?;
        }
    }
    Ok(())
}

/// 审核下的规则组列表。
pub async fn list_rules(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<Vec<AuditRuleView>, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;

    let rule_rows = repo::list_rules(state, audit_id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;

    Ok(rule_rows
        .iter()
        .map(|item| {
            let items = item_map
                .get(&item.id)
                .map(|rows| rows.iter().map(to_rule_item_view).collect())
                .unwrap_or_default();
            to_rule_view(item, items)
        })
        .collect())
}

/// 新建规则组。
pub async fn create_rule(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    req: SaveRuleRequest,
) -> Result<AuditRuleView, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    if req.name.trim().is_empty() {
        return Err(ApiError::invalid_param(
            "规则组名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }

    let mut tx = state.db.begin().await?;
    let rules = vec![req.clone()];
    insert_rules(&mut tx, project_id, audit_id, &rules).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "RULE_CREATE",
            "RULE",
            audit_id,
            json!({ "name": req.name }),
        ),
    )
    .await?;

    let rule_rows = repo::list_rules(state, audit_id).await?;
    let created = rule_rows
        .iter()
        .find(|item| item.name == req.name.trim())
        .cloned()
        .ok_or_else(|| ApiError::internal("规则组创建后未找到"))?;
    let items = repo::list_rule_items(state, created.id).await?;
    Ok(to_rule_view(
        &created,
        items.iter().map(to_rule_item_view).collect(),
    ))
}

/// 规则组详情。
pub async fn get_rule(
    state: &AppState,
    ctx: &AuthContext,
    rule_id: u64,
) -> Result<AuditRuleView, ApiError> {
    let row = repo::find_rule(state, rule_id).await?;
    ctx.require_project(row.project_id)?;

    let items = repo::list_rule_items(state, rule_id).await?;
    Ok(to_rule_view(
        &row,
        items.iter().map(to_rule_item_view).collect(),
    ))
}

/// 更新规则组。
pub async fn update_rule(
    state: &AppState,
    ctx: &AuthContext,
    rule_id: u64,
    req: SaveRuleRequest,
) -> Result<AuditRuleView, ApiError> {
    let row = repo::find_rule(state, rule_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    if req.name.trim().is_empty() {
        return Err(ApiError::invalid_param(
            "规则组名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }

    let mut tx = state.db.begin().await?;
    repo::update_rule(
        &mut tx,
        rule_id,
        &repo::RuleUpdate {
            name: req.name.trim().to_string(),
            priority: req.priority.unwrap_or(row.priority),
            logic: req
                .logic
                .clone()
                .unwrap_or_else(|| row.logic.clone())
                .trim()
                .to_ascii_uppercase(),
            stop_on_hit: req.stop_on_hit.unwrap_or(row.stop_on_hit),
            on_hit_result: req
                .on_hit_result
                .clone()
                .unwrap_or_else(|| row.on_hit_result.clone()),
            status: req
                .status
                .as_deref()
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| row.status.clone()),
        },
    )
    .await?;
    repo::delete_rule_items(&mut tx, rule_id).await?;
    insert_rule_items(&mut tx, rule_id, &req.items).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "RULE_UPDATE",
            "RULE",
            rule_id,
            json!({ "name": req.name }),
        ),
    )
    .await?;

    let updated = repo::find_rule(state, rule_id).await?;
    let items = repo::list_rule_items(state, rule_id).await?;
    Ok(to_rule_view(
        &updated,
        items.iter().map(to_rule_item_view).collect(),
    ))
}

/// 删除规则组。
pub async fn delete_rule(
    state: &AppState,
    ctx: &AuthContext,
    rule_id: u64,
) -> Result<Value, ApiError> {
    let row = repo::find_rule(state, rule_id).await?;
    ctx.require_project(row.project_id)?;

    let mut tx = state.db.begin().await?;
    repo::soft_delete_rule(&mut tx, rule_id).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            row.project_id,
            "RULE_DELETE",
            "RULE",
            rule_id,
            json!({ "name": row.name }),
        ),
    )
    .await?;

    Ok(json!({ "rule_id": rule_id }))
}

/// 规则试跑。
pub async fn dry_run(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    sample: DryRunSample,
) -> Result<DryRunResult, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;

    let snapshot = snapshot_of(&row);
    let rule_rows = repo::list_rules(state, audit_id).await?;
    let rule_ids: Vec<u64> = rule_rows.iter().map(|item| item.id).collect();
    let item_map = repo::list_rule_items_for_rules(state, &rule_ids).await?;

    let groups: Vec<RuleGroupSpec> = rule_rows
        .iter()
        .map(|item| RuleGroupSpec {
            id: Some(item.id),
            name: item.name.clone(),
            priority: item.priority,
            logic: item.logic.clone(),
            stop_on_hit: item.stop_on_hit,
            on_hit_result: item.on_hit_result.clone(),
            status: Some(item.status.clone()),
            items: item_map
                .get(&item.id)
                .map(|rows| {
                    rows.iter()
                        .map(|row| RuleItemSpec {
                            field: row.field.clone(),
                            operator: row.operator.clone(),
                            value: row.value_json.clone(),
                            case_sensitive: row.case_sensitive,
                            negate: row.negate,
                            sort_order: row.sort_order,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();

    let context = eval_context(&sample);
    let (final_result, traces) =
        crate::engine::rule::evaluate(&groups, &context, &snapshot.default_result);
    let matched_rule = traces
        .iter()
        .find(|trace| trace.hit && !trace.skipped)
        .map(|trace| trace.rule.clone());

    Ok(DryRunResult {
        final_result,
        matched_rule,
        trace: traces,
    })
}

/// 用样例构造规则求值上下文。
fn eval_context(sample: &DryRunSample) -> EvalContext {
    let media_text = sample
        .media
        .iter()
        .filter(|item| item.media_type.eq_ignore_ascii_case("text"))
        .map(|item| item.content.clone())
        .collect::<Vec<String>>()
        .join("\n");

    let mut media_types: Vec<String> = Vec::new();
    for item in &sample.media {
        if !item.media_type.is_empty() && !media_types.contains(&item.media_type) {
            media_types.push(item.media_type.clone());
        }
    }

    let ext = match sample.ext.clone() {
        Value::Object(fields) => fields,
        _ => serde_json::Map::new(),
    };

    let model = sample.model.clone().unwrap_or_default();
    let task = sample.task.clone().unwrap_or_default();

    EvalContext {
        media_text_len: media_text.chars().count(),
        media_text,
        media_count: sample.media.len(),
        media_types,
        ext,
        model_label: model.label,
        model_score: model.score,
        model_risk_level: model.risk_level,
        source_type: task.source_type.unwrap_or_default(),
        submit_hour: task.submit_hour.unwrap_or(0),
        ..EvalContext::default()
    }
}

// ---------------------------------------------------------------------------
// 结果路由
// ---------------------------------------------------------------------------

/// 写入路由集合。
async fn upsert_routes(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    project_id: u64,
    audit_id: u64,
    routes: &HashMap<String, ResultRouteView>,
) -> Result<(), ApiError> {
    for route in routes.values() {
        repo::upsert_route(
            tx,
            &repo::RouteUpsert {
                id: crate::common::ids::next_id(),
                project_id,
                audit_id,
                result_type: route.result_type.clone(),
                exec_mode: route.exec_mode.clone(),
                on_error: route.on_error.clone(),
                actions_json: serde_json::to_value(&route.actions)?,
                status: route
                    .status
                    .clone()
                    .unwrap_or_else(|| STATUS_ACTIVE.to_string()),
            },
        )
        .await?;
    }
    Ok(())
}

/// 审核下的结果路由。
pub async fn list_routes(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
) -> Result<HashMap<String, ResultRouteView>, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;

    let rows = repo::list_routes(state, audit_id).await?;
    let mut routes = HashMap::new();
    for item in &rows {
        routes.insert(item.result_type.clone(), to_route_view(item));
    }
    Ok(routes)
}

/// 保存单条结果路由。
pub async fn put_route(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    result_type: &str,
    route: ResultRouteView,
) -> Result<ResultRouteView, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    let result_type = result_type.trim().to_ascii_uppercase();
    if !matches!(result_type.as_str(), "PASS" | "REJECT" | "REVIEW") {
        return Err(ApiError::invalid_param(
            format!("结果类型「{result_type}」不合法"),
            vec![FieldError::new(
                "result_type",
                "只能是 PASS / REJECT / REVIEW",
            )],
        ));
    }

    validate_actions(state, project_id, &route.actions).await?;

    let mut view = route;
    view.result_type = result_type.clone();
    if view.exec_mode.trim().is_empty() {
        view.exec_mode = "sequential".to_string();
    }
    if view.on_error.trim().is_empty() {
        view.on_error = "to_review".to_string();
    }
    if view.status.is_none() {
        view.status = Some(STATUS_ACTIVE.to_string());
    }

    let mut tx = state.db.begin().await?;
    let mut map = HashMap::new();
    map.insert(result_type.clone(), view.clone());
    upsert_routes(&mut tx, project_id, audit_id, &map).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "ROUTE_UPDATE",
            "ROUTE",
            audit_id,
            json!({ "result_type": result_type }),
        ),
    )
    .await?;

    Ok(view)
}

/// 应用路由模板。
pub async fn apply_route_template(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    req: ApplyRouteTemplateRequest,
) -> Result<HashMap<String, ResultRouteView>, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;
    let project_id = row.project_id;

    let template = req.template.trim().to_ascii_lowercase();
    let snapshot = snapshot_of(&row);

    let empty = |result_type: &str| ResultRouteView {
        id: None,
        result_type: result_type.to_string(),
        exec_mode: "sequential".to_string(),
        on_error: "to_review".to_string(),
        actions: Vec::new(),
        status: Some(STATUS_ACTIVE.to_string()),
    };

    let routes: HashMap<String, ResultRouteView> = match template.as_str() {
        "reject_all_except_pass" => {
            let mut map = HashMap::new();
            map.insert("PASS".to_string(), empty("PASS"));
            map.insert(
                "REJECT".to_string(),
                with_actions(empty("REJECT"), req.actions.clone()),
            );
            map.insert(
                "REVIEW".to_string(),
                with_actions(empty("REVIEW"), req.actions.clone()),
            );
            map
        }
        "same_actions_all" => {
            let mut map = HashMap::new();
            for result_type in ["PASS", "REJECT", "REVIEW"] {
                map.insert(
                    result_type.to_string(),
                    with_actions(empty(result_type), req.actions.clone()),
                );
            }
            map
        }
        "callback_only" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .or_else(|| callback_url(&snapshot));
            let Some(url) = url else {
                return Err(ApiError::invalid_param(
                    "仅回调模板需要回调地址：请传 url 或在审核配置里设置 media_review.callback_url",
                    vec![FieldError::new("url", "回调地址不能为空")],
                ));
            };
            let mut map = HashMap::new();
            for result_type in ["PASS", "REJECT", "REVIEW"] {
                map.insert(
                    result_type.to_string(),
                    with_actions(empty(result_type), vec![webhook_action(&url)]),
                );
            }
            map
        }
        "pass_release_review_manual" => {
            let mut map = HashMap::new();
            map.insert("PASS".to_string(), empty("PASS"));
            map.insert("REVIEW".to_string(), empty("REVIEW"));
            map.insert(
                "REJECT".to_string(),
                with_actions(empty("REJECT"), req.actions.clone()),
            );
            map
        }
        other => {
            return Err(ApiError::invalid_param(
                format!("不支持的路由模板「{other}」"),
                vec![FieldError::new(
                    "template",
                    "只能是 reject_all_except_pass / same_actions_all / callback_only / pass_release_review_manual",
                )],
            ));
        }
    };

    for route in routes.values() {
        validate_actions(state, project_id, &route.actions).await?;
    }

    let mut tx = state.db.begin().await?;
    repo::soft_delete_routes_of_audit(&mut tx, audit_id).await?;
    upsert_routes(&mut tx, project_id, audit_id, &routes).await?;
    tx.commit().await?;

    repo::write_audit_log(
        state,
        audit_entry(
            ctx,
            project_id,
            "ROUTE_TEMPLATE",
            "ROUTE",
            audit_id,
            json!({ "template": template }),
        ),
    )
    .await?;

    Ok(routes)
}

/// 模板给路由填动作。
fn with_actions(mut route: ResultRouteView, actions: Vec<ActionSpec>) -> ResultRouteView {
    route.actions = actions;
    route
}

/// 构造 Webhook 动作。
fn webhook_action(url: &str) -> ActionSpec {
    ActionSpec {
        id: None,
        action_type: "WEBHOOK".to_string(),
        name: Some("结果回调".to_string()),
        api_ref: None,
        method: None,
        path: None,
        headers: None,
        body: None,
        command: None,
        key: None,
        value: None,
        ttl_sec: None,
        datasource: None,
        sql: None,
        params: None,
        url: Some(url.to_string()),
        sign: None,
        target: None,
        topic: None,
        timeout_ms: None,
        retry: None,
        on_error: None,
    }
}

/// 审核配置里的回调地址。
fn callback_url(snapshot: &AuditConfigSnapshot) -> Option<String> {
    let fields = snapshot.media_review.as_object()?;
    let direct = fields.get("callback_url").and_then(Value::as_str);
    let nested = fields
        .get("text")
        .and_then(Value::as_object)
        .and_then(|item| item.get("callback_url"))
        .and_then(Value::as_str);
    direct
        .or(nested)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 预览路由渲染结果。
pub async fn preview_route(
    state: &AppState,
    ctx: &AuthContext,
    audit_id: u64,
    req: PreviewRouteRequest,
) -> Result<Value, ApiError> {
    let row = repo::find_audit(state, audit_id).await?;
    ctx.require_project(row.project_id)?;

    let result_type = req.result_type.trim().to_ascii_uppercase();
    let routes = list_routes(state, ctx, audit_id).await?;
    let Some(route) = routes.get(&result_type) else {
        return Err(ApiError::not_found(format!(
            "结果类型「{result_type}」的路由不存在"
        )));
    };

    let context = template_context(&req.sample, &result_type);
    let mut rendered = Vec::with_capacity(route.actions.len());
    for (index, action) in route.actions.iter().enumerate() {
        rendered.push(render_action(action, index, &context)?);
    }

    Ok(json!({
        "result_type": result_type,
        "exec_mode": route.exec_mode,
        "on_error": route.on_error,
        "actions": rendered,
    }))
}

/// 用样例构造模板上下文。
fn template_context(sample: &DryRunSample, result_type: &str) -> TemplateContext {
    let media_text = sample
        .media
        .iter()
        .filter(|item| item.media_type.eq_ignore_ascii_case("text"))
        .map(|item| item.content.clone())
        .collect::<Vec<String>>()
        .join("\n");
    let media_url = sample
        .media
        .iter()
        .map(|item| item.url.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_string();
    let model = sample.model.clone().unwrap_or_default();
    let task = sample.task.clone().unwrap_or_default();
    let ext = match sample.ext.clone() {
        Value::Object(fields) => fields,
        _ => serde_json::Map::new(),
    };

    TemplateContext {
        task_id: task.task_id.unwrap_or(0),
        task_no: task.task_no.unwrap_or_default(),
        task_result: result_type.to_string(),
        task_biz_key: task.biz_key.unwrap_or_default(),
        media_url,
        media_text,
        model_label: model.label.unwrap_or_default(),
        model_score: model.score.unwrap_or(0.0),
        ext,
        now_ms: crate::common::now_ms(),
        now: crate::common::time::now_iso8601(),
    }
}

/// 渲染动作里的模板。
fn render_action(
    action: &ActionSpec,
    index: usize,
    context: &TemplateContext,
) -> Result<Value, ApiError> {
    let render_text = |text: &str, name: &str| -> Result<Value, ApiError> {
        render_string(text, context)
            .map(Value::String)
            .map_err(|reason| {
                ApiError::invalid_param(
                    format!("模板渲染失败：{reason}"),
                    vec![FieldError::new(name, reason)],
                )
            })
    };

    let mut result = json!({
        "id": action.action_id(index),
        "type": action.action_type,
        "name": action.name,
    });

    if let Some(path) = action.path.as_deref() {
        result["path"] = render_text(path, "path")?;
    }
    if let Some(key) = action.key.as_deref() {
        result["key"] = render_text(key, "key")?;
    }
    if let Some(url) = action.url.as_deref() {
        result["url"] = render_text(url, "url")?;
    }
    if let Some(headers) = action.headers.as_ref() {
        result["headers"] = render_json(headers, "headers", context)?;
    }
    if let Some(body) = action.body.as_ref() {
        result["body"] = render_json(body, "body", context)?;
    }
    if let Some(value) = action.value.as_ref() {
        result["value"] = render_json(value, "value", context)?;
    }
    if let Some(method) = action.method.as_deref() {
        result["method"] = Value::String(method.to_string());
    }
    if let Some(command) = action.command.as_deref() {
        result["command"] = Value::String(command.to_string());
    }
    if let Some(sql) = action.sql.as_deref() {
        result["sql"] = Value::String(sql.to_string());
    }
    if let Some(params) = action.params.as_ref() {
        result["params"] = serde_json::to_value(params)?;
    }

    Ok(result)
}

/// 渲染 JSON 里的模板。
fn render_json(value: &Value, name: &str, context: &TemplateContext) -> Result<Value, ApiError> {
    render_value(value, context).map_err(|reason| {
        ApiError::invalid_param(
            format!("模板渲染失败：{reason}"),
            vec![FieldError::new(name, reason)],
        )
    })
}
