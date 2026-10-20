//! 动作 DSL 执行器：HTTP / REDIS / MYSQL / WEBHOOK / MQ。
//!
//! 语义见 `doc/API.md` 第五章：
//!
//! - 路由带 `exec_mode`（`sequential` / `parallel`）与 `on_error`
//!   （`continue` / `abort` / `to_review`）。
//! - 每个动作执行完写一行 `action_exec_log`：请求脱敏、响应摘要、耗时、状态、重试次数。
//! - 请求 / 响应 JSON 超过 8KB 截断并标记 `_truncated`。
//!
//! 安全约束：
//!
//! - Redis 键必须落在 `audit:{project_id}:` 前缀内，防止跨项目越权写。
//! - MySQL 动作只允许参数化的 `INSERT` / `UPDATE`，禁止 DDL 与 `DELETE`。
//! - WEBHOOK / HTTP 的目标地址不允许指向内网 / 回环（SSRF 防护）。

use std::time::{Duration, Instant};

use futures_util::future::join_all;
use hmac::{Hmac, Mac};
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};
use sha2::Sha256;
use sqlx::Row;
use sqlx::mysql::MySqlPoolOptions;

use crate::db::AppState;
use crate::engine::template::{self, TemplateContext};
use crate::error::ApiError;
use crate::models::rule::{ActionSpec, REDIS_COMMAND_WHITELIST};

type HmacSha256 = Hmac<Sha256>;

/// 动作成功。
const STATUS_SUCCESS: &str = "SUCCESS";
/// 动作失败。
const STATUS_FAILED: &str = "FAILED";
/// 动作跳过（依赖缺失等）。
const STATUS_SKIPPED: &str = "SKIPPED";

/// 请求 / 响应日志的最大字节数，超出即截断。
const MAX_LOG_BYTES: usize = 8 * 1024;

/// HTTP / WEBHOOK 默认超时（毫秒）。
const DEFAULT_TIMEOUT_MS: i64 = 5000;

/// 默认最大尝试次数（含首次）。
const DEFAULT_MAX_ATTEMPTS: i32 = 3;

/// 重试退避基数（毫秒）。
const RETRY_BASE_MS: i64 = 500;

/// Redis 键前缀模板。
fn redis_prefix(project_id: u64) -> String {
    format!("audit:{project_id}:")
}

/// 动作执行结果。
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub action_id: String,
    pub action_type: String,
    /// `SUCCESS` / `FAILED` / `SKIPPED`。
    pub status: String,
    pub duration_ms: i64,
    pub request: Value,
    pub response: Value,
    pub error_message: Option<String>,
    pub retry_count: i32,
    /// 本次执行是否因动作失败而中止了后续动作。
    pub aborted: bool,
    /// 是否需要把任务转待议（`on_error = to_review`）。
    pub to_review: bool,
}

/// 单个动作执行后的中间结果。
struct ActionResult {
    status: String,
    request: Value,
    response: Value,
    error_message: Option<String>,
    retry_count: i32,
}

impl ActionResult {
    fn failed(request: Value, message: impl Into<String>) -> Self {
        Self {
            status: STATUS_FAILED.to_string(),
            request,
            response: Value::Null,
            error_message: Some(message.into()),
            retry_count: 0,
        }
    }

    fn skipped(request: Value, message: impl Into<String>) -> Self {
        Self {
            status: STATUS_SKIPPED.to_string(),
            request,
            response: Value::Null,
            error_message: Some(message.into()),
            retry_count: 0,
        }
    }

    fn success(request: Value, response: Value, retry_count: i32) -> Self {
        Self {
            status: STATUS_SUCCESS.to_string(),
            request,
            response,
            error_message: None,
            retry_count,
        }
    }
}

/// 动作失败策略。
#[derive(Debug, Clone, Copy)]
struct FailurePolicy {
    /// 是否中止后续动作。
    stop: bool,
    /// 是否把任务转待议。
    to_review: bool,
}

impl FailurePolicy {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "abort" => Self {
                stop: true,
                to_review: false,
            },
            "to_review" => Self {
                stop: true,
                to_review: true,
            },
            _ => Self {
                stop: false,
                to_review: false,
            },
        }
    }
}

/// 重试参数。
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    max_attempts: i32,
    backoff_ms: i64,
}

impl RetryPolicy {
    fn parse(spec: &ActionSpec) -> Self {
        let mut policy = Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff_ms: RETRY_BASE_MS,
        };
        match spec.retry.as_ref() {
            Some(Value::Number(number)) => {
                if let Some(value) = number.as_i64() {
                    policy.max_attempts = value as i32;
                }
            }
            Some(Value::Object(fields)) => {
                if let Some(value) = fields.get("max_attempts").and_then(Value::as_i64) {
                    policy.max_attempts = value as i32;
                }
                if let Some(value) = fields.get("backoff_ms").and_then(Value::as_i64) {
                    policy.backoff_ms = value;
                }
            }
            _ => {}
        }
        policy.max_attempts = policy.max_attempts.clamp(1, 10);
        policy.backoff_ms = policy.backoff_ms.clamp(10, 60_000);
        policy
    }
}

/// 执行一条路由上的全部动作（默认顺序执行，失败继续）。
pub async fn execute_route(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    route_type: &str,
    actions: &[ActionSpec],
    context: &TemplateContext,
) -> Vec<ActionOutcome> {
    execute_route_with_mode(
        state,
        project_id,
        task_id,
        route_type,
        actions,
        "sequential",
        "continue",
        context,
    )
    .await
}

/// 按执行方式与失败策略执行一条路由上的全部动作。
pub async fn execute_route_with_mode(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    route_type: &str,
    actions: &[ActionSpec],
    exec_mode: &str,
    on_error: &str,
    context: &TemplateContext,
) -> Vec<ActionOutcome> {
    if actions.is_empty() {
        return Vec::new();
    }

    let policy = FailurePolicy::parse(on_error);

    let mut outcomes: Vec<ActionOutcome> = if exec_mode.trim().eq_ignore_ascii_case("parallel") {
        let futures = actions.iter().enumerate().map(|(index, spec)| {
            execute_one(state, project_id, task_id, route_type, spec, index, context)
        });
        join_all(futures).await
    } else {
        let mut list: Vec<ActionOutcome> = Vec::with_capacity(actions.len());
        for (index, spec) in actions.iter().enumerate() {
            let outcome =
                execute_one(state, project_id, task_id, route_type, spec, index, context).await;
            let failed = outcome.status == STATUS_FAILED;
            list.push(outcome);
            // 顺序执行下允许真正中止：失败策略是 abort / to_review 时不再执行后续动作。
            if failed && policy.stop {
                break;
            }
        }
        list
    };

    // 标记中止与是否转待议（并行模式下所有动作都已执行，只能事后标记）。
    if let Some(position) = outcomes
        .iter()
        .position(|item| item.status == STATUS_FAILED)
    {
        if policy.stop {
            outcomes[position].aborted = true;
            outcomes[position].to_review = policy.to_review;
        }
    }

    outcomes
}

/// 执行单个动作，并落一条执行日志。
async fn execute_one(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    route_type: &str,
    spec: &ActionSpec,
    index: usize,
    context: &TemplateContext,
) -> ActionOutcome {
    let started = Instant::now();
    let action_id = spec.action_id(index);
    let action_type = spec.action_type.trim().to_ascii_uppercase();

    let result = match action_type.as_str() {
        "HTTP" => exec_http(state, project_id, task_id, spec, context).await,
        "REDIS" => exec_redis(state, project_id, spec, context).await,
        "MYSQL" => exec_mysql(state, project_id, spec, context).await,
        "WEBHOOK" => exec_webhook(state, project_id, task_id, spec, context).await,
        "MQ" => exec_mq(state, project_id, spec, context).await,
        _ => Ok(ActionResult::failed(
            Value::Null,
            format!("不支持的动作类型「{}」", spec.action_type),
        )),
    };

    let mut outcome = match result {
        Ok(item) => ActionOutcome {
            action_id: action_id.clone(),
            action_type: action_type.clone(),
            status: item.status,
            duration_ms: 0,
            request: truncate_json(mask_sensitive(&item.request)),
            response: truncate_json(item.response),
            error_message: item.error_message,
            retry_count: item.retry_count,
            aborted: false,
            to_review: false,
        },
        Err(err) => ActionOutcome {
            action_id: action_id.clone(),
            action_type: action_type.clone(),
            status: STATUS_FAILED.to_string(),
            duration_ms: 0,
            request: Value::Null,
            response: Value::Null,
            error_message: Some(err.to_string()),
            retry_count: 0,
            aborted: false,
            to_review: false,
        },
    };

    outcome.duration_ms = started.elapsed().as_millis() as i64;
    write_exec_log(state, project_id, task_id, route_type, spec, &outcome).await;

    state.metrics.inc(
        "audit_action_exec_total",
        vec![
            ("project".to_string(), project_id.to_string()),
            ("action_type".to_string(), action_type.clone()),
            ("status".to_string(), outcome.status.clone()),
        ],
    );
    state.metrics.observe(
        "audit_action_duration_seconds",
        vec![
            ("project".to_string(), project_id.to_string()),
            ("action_type".to_string(), action_type),
        ],
        outcome.duration_ms as f64 / 1000.0,
        duration_buckets(),
    );

    outcome
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

async fn exec_http(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    spec: &ActionSpec,
    context: &TemplateContext,
) -> Result<ActionResult, ApiError> {
    let api_ref = spec.api_ref.clone().unwrap_or_default().trim().to_string();
    if api_ref.is_empty() {
        return Ok(ActionResult::failed(Value::Null, "HTTP 动作缺少 api_ref"));
    }

    let (config, pool_json, _tags) = match load_config(state, project_id, "API", &api_ref).await {
        Ok(value) => value,
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "api_ref": api_ref }),
                err.to_string(),
            ));
        }
    };

    let Some(base_url) = cfg_str(&config, "base_url") else {
        return Ok(ActionResult::failed(
            serde_json::json!({ "api_ref": api_ref }),
            "API 配置缺少 base_url",
        ));
    };

    let path = match spec.path.as_deref() {
        Some(raw) => template::render_string(raw, context)
            .map_err(|err| ApiError::bad_request(format!("路径模板渲染失败：{err}")))?,
        None => String::new(),
    };
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    if let Some(host) = url_host(&url) {
        if crate::modules::audit::service::is_blocked_host(&host) {
            return Ok(ActionResult::failed(
                serde_json::json!({ "url": url }),
                "目标地址不允许指向内网",
            ));
        }
    }

    let method_text = spec
        .method
        .as_deref()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "POST".to_string());
    let method = match Method::from_bytes(method_text.as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "url": url, "method": method_text }),
                format!("不支持的 HTTP 方法「{method_text}」"),
            ));
        }
    };

    // 请求体：模板渲染后的 JSON。
    let body = match spec.body.as_ref() {
        Some(raw) => template::render_value(raw, context)
            .map_err(|err| ApiError::bad_request(format!("请求体模板渲染失败：{err}")))?,
        None => Value::Null,
    };

    // 请求头：配置头 + 动作头 + 鉴权头 + 幂等键。
    let mut headers = HeaderMap::new();
    if let Some(Value::Object(config_headers)) = config.get("headers") {
        for (key, value) in config_headers {
            if let Some(text) = value.as_str() {
                insert_header(&mut headers, key, text);
            }
        }
    }
    if let Some(Value::Object(action_headers)) = spec.headers.as_ref() {
        for (key, raw) in action_headers {
            let text = match template::render_value(raw, context) {
                Ok(Value::String(text)) => text,
                Ok(other) => other.to_string(),
                Err(err) => {
                    return Ok(ActionResult::failed(
                        serde_json::json!({ "url": url }),
                        format!("请求头模板渲染失败：{err}"),
                    ));
                }
            };
            insert_header(&mut headers, key, &text);
        }
    }
    apply_auth(&mut headers, &config);
    // 幂等键：同一个任务重复触发时第三方可据此去重。
    insert_header(&mut headers, "X-Idempotency-Key", &task_id.to_string());

    let timeout_ms = spec
        .timeout_ms
        .or_else(|| cfg_i64(&config, "timeout_ms"))
        .or_else(|| {
            pool_json
                .as_ref()
                .and_then(|value| cfg_i64(value, "timeout_ms"))
        })
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(100, 120_000);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms as u64))
        .build()
    {
        Ok(value) => value,
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "url": url }),
                format!("HTTP 客户端初始化失败：{err}"),
            ));
        }
    };

    let retry = RetryPolicy::parse(spec);
    let request_log = serde_json::json!({
        "method": method_text,
        "url": url,
        "body": body,
    });

    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut builder = client
            .request(method.clone(), &url)
            .headers(headers.clone());
        if !body.is_null() {
            builder = builder.json(&body);
        }

        match builder.send().await {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let payload = serde_json::json!({ "status": status.as_u16(), "body": text });
                if status.is_success() {
                    return Ok(ActionResult::success(request_log, payload, attempt - 1));
                }
                // 4xx 不重试（429 限流除外），5xx 允许重试。
                let retryable = status.as_u16() >= 500 || status.as_u16() == 429;
                if !retryable || attempt >= retry.max_attempts {
                    return Ok(ActionResult {
                        status: STATUS_FAILED.to_string(),
                        request: request_log,
                        response: payload,
                        error_message: Some(format!("HTTP 请求失败，状态码 {}", status.as_u16())),
                        retry_count: attempt - 1,
                    });
                }
            }
            Err(err) => {
                // 只有超时与连接错误才重试。
                let retryable = err.is_timeout() || err.is_connect();
                if !retryable || attempt >= retry.max_attempts {
                    return Ok(ActionResult {
                        status: STATUS_FAILED.to_string(),
                        request: request_log,
                        response: Value::Null,
                        error_message: Some(format!("HTTP 请求异常：{err}")),
                        retry_count: attempt - 1,
                    });
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms(attempt, retry.backoff_ms))).await;
    }
}

// ---------------------------------------------------------------------------
// REDIS
// ---------------------------------------------------------------------------

async fn exec_redis(
    state: &AppState,
    project_id: u64,
    spec: &ActionSpec,
    context: &TemplateContext,
) -> Result<ActionResult, ApiError> {
    let command = spec
        .command
        .clone()
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    if !REDIS_COMMAND_WHITELIST.contains(&command.as_str()) {
        return Ok(ActionResult::failed(
            serde_json::json!({ "command": command }),
            "Redis 命令不在白名单内",
        ));
    }

    let key_raw = spec.key.clone().unwrap_or_default();
    let key = match template::render_string(&key_raw, context) {
        Ok(value) => value,
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "command": command }),
                format!("键模板渲染失败：{err}"),
            ));
        }
    };

    // 键必须落在本项目前缀内，防止跨项目越权写。
    let prefix = redis_prefix(project_id);
    if !key.starts_with(&prefix) {
        return Ok(ActionResult::failed(
            serde_json::json!({ "command": command, "key": key }),
            format!("Redis 键必须以「{prefix}」开头"),
        ));
    }

    let value = match spec.value.as_ref() {
        Some(raw) => template::render_value(raw, context)
            .map_err(|err| ApiError::bad_request(format!("值模板渲染失败：{err}")))?,
        None => Value::Null,
    };

    let Some(mut conn) = state.redis.clone() else {
        return Ok(ActionResult::failed(
            serde_json::json!({ "command": command, "key": key }),
            "Redis 不可用",
        ));
    };

    // 按命令类型拼参数：键 + 值。
    let cmd = match command.as_str() {
        "SET" => {
            let mut cmd = redis::cmd("SET");
            cmd.arg(&key).arg(value_to_text(&value));
            cmd
        }
        "HSET" => {
            let Some(fields) = value.as_object() else {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "command": command, "key": key }),
                    "HSET 的值必须是字段映射对象",
                ));
            };
            let mut cmd = redis::cmd("HSET");
            cmd.arg(&key);
            for (field, item) in fields {
                cmd.arg(field).arg(value_to_text(item));
            }
            cmd
        }
        "LPUSH" | "SADD" => {
            let Some(items) = value.as_array() else {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "command": command, "key": key }),
                    format!("{command} 的值必须是数组"),
                ));
            };
            let mut cmd = redis::cmd(command.as_str());
            cmd.arg(&key);
            for item in items {
                cmd.arg(value_to_text(item));
            }
            cmd
        }
        "ZADD" => {
            let Some(score) = value.get("score").and_then(Value::as_f64) else {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "command": command, "key": key }),
                    "ZADD 的值必须包含 score",
                ));
            };
            let member = value.get("member").map(value_to_text).unwrap_or_default();
            let mut cmd = redis::cmd("ZADD");
            cmd.arg(&key).arg(score).arg(member);
            cmd
        }
        "PUBLISH" => {
            let channel = value
                .get("channel")
                .map(value_to_text)
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| key.clone());
            let message = value.get("message").map(value_to_text).unwrap_or_default();
            let mut cmd = redis::cmd("PUBLISH");
            cmd.arg(channel).arg(message);
            cmd
        }
        "EXPIRE" => {
            let seconds = value
                .get("seconds")
                .and_then(Value::as_i64)
                .or_else(|| value.as_i64())
                .unwrap_or(0);
            if seconds <= 0 {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "command": command, "key": key }),
                    "EXPIRE 的秒数必须大于 0",
                ));
            }
            let mut cmd = redis::cmd("EXPIRE");
            cmd.arg(&key).arg(seconds);
            cmd
        }
        "DEL" => {
            let mut cmd = redis::cmd("DEL");
            cmd.arg(&key);
            cmd
        }
        _ => {
            let mut cmd = redis::cmd(command.as_str());
            cmd.arg(&key);
            cmd
        }
    };

    let request_log = serde_json::json!({
        "command": command,
        "key": key,
        "value": value,
    });

    if let Err(err) = cmd.query_async::<redis::Value>(&mut conn).await {
        return Ok(ActionResult::failed(
            request_log,
            format!("Redis 命令执行失败：{err}"),
        ));
    }

    // TTL：有值就补一条 EXPIRE。
    if let Some(ttl) = spec.ttl_sec {
        if ttl > 0 {
            let mut expire = redis::cmd("EXPIRE");
            expire.arg(&key).arg(ttl);
            if let Err(err) = expire.query_async::<redis::Value>(&mut conn).await {
                return Ok(ActionResult::failed(
                    request_log,
                    format!("设置过期时间失败：{err}"),
                ));
            }
        }
    }

    Ok(ActionResult::success(
        request_log,
        serde_json::json!({ "ok": true }),
        0,
    ))
}

// ---------------------------------------------------------------------------
// MYSQL
// ---------------------------------------------------------------------------

async fn exec_mysql(
    state: &AppState,
    project_id: u64,
    spec: &ActionSpec,
    context: &TemplateContext,
) -> Result<ActionResult, ApiError> {
    let datasource = spec
        .datasource
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    if datasource.is_empty() {
        return Ok(ActionResult::failed(
            Value::Null,
            "MYSQL 动作缺少 datasource",
        ));
    }

    let (config, pool_json, _tags) =
        match load_config(state, project_id, "MYSQL", &datasource).await {
            Ok(value) => value,
            Err(err) => {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "datasource": datasource }),
                    err.to_string(),
                ));
            }
        };

    let host = cfg_str(&config, "host").unwrap_or_default();
    if host.trim().is_empty() {
        return Ok(ActionResult::failed(
            serde_json::json!({ "datasource": datasource }),
            "数据源配置缺少 host",
        ));
    }
    let port = cfg_i64(&config, "port").unwrap_or(3306);
    let database = cfg_str(&config, "database").unwrap_or_default();
    let username = cfg_str(&config, "username").unwrap_or_default();
    let password = cfg_str(&config, "password").unwrap_or_default();
    let url = format!(
        "mysql://{}:{}@{}:{}/{}",
        urlencoding::encode(&username),
        urlencoding::encode(&password),
        host,
        port,
        database
    );

    let max_pool = pool_json
        .as_ref()
        .and_then(|value| cfg_i64(value, "max_pool_size"))
        .unwrap_or(10)
        .clamp(1, 100);

    let pool = match MySqlPoolOptions::new()
        .max_connections(max_pool as u32)
        .acquire_timeout(Duration::from_secs(5))
        // 会话时区固定为 UTC，避免时间列随服务端时区漂移。
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET time_zone = '+00:00'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "datasource": datasource }),
                format!("数据源连接失败：{err}"),
            ));
        }
    };

    let sql_raw = spec.sql.clone().unwrap_or_default();
    if sql_raw.trim().is_empty() {
        return Ok(ActionResult::failed(
            serde_json::json!({ "datasource": datasource }),
            "MYSQL 动作缺少 sql",
        ));
    }

    // 执行前再做一次 SQL 安全校验。
    if let Err(reason) = check_sql_safety(&sql_raw) {
        return Ok(ActionResult::failed(
            serde_json::json!({ "datasource": datasource }),
            format!("SQL 未通过安全校验：{reason}"),
        ));
    }

    let params: Vec<Value> = match spec.params.as_ref() {
        Some(items) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered
                    .push(template::render_value(item, context).map_err(|err| {
                        ApiError::bad_request(format!("参数模板渲染失败：{err}"))
                    })?);
            }
            rendered
        }
        None => Vec::new(),
    };

    let placeholders = sql_raw.matches('?').count();
    if placeholders != params.len() {
        return Ok(ActionResult::failed(
            serde_json::json!({ "datasource": datasource }),
            format!(
                "SQL 占位符数量（{placeholders}）与参数数量（{}）不一致",
                params.len()
            ),
        ));
    }

    let mut query = sqlx::query(&sql_raw);
    for param in &params {
        query = match param {
            Value::String(text) => query.bind(text.clone()),
            Value::Bool(flag) => query.bind(*flag),
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    query.bind(value)
                } else if let Some(value) = number.as_f64() {
                    query.bind(value)
                } else {
                    query.bind(number.to_string())
                }
            }
            Value::Null => query.bind(Option::<String>::None),
            other => query.bind(sqlx::types::Json(other.clone())),
        };
    }

    let request_log = serde_json::json!({
        "datasource": datasource,
        "sql": sql_raw,
        "params": params,
    });

    match query.execute(&pool).await {
        Ok(result) => Ok(ActionResult::success(
            request_log,
            serde_json::json!({ "rows_affected": result.rows_affected() }),
            0,
        )),
        Err(err) => Ok(ActionResult::failed(
            request_log,
            format!("SQL 执行失败：{err}"),
        )),
    }
}

/// SQL 安全校验：只允许参数化的 `INSERT` / `UPDATE`。
fn check_sql_safety(sql: &str) -> Result<(), String> {
    let trimmed = sql.trim();
    let upper = trimmed.to_ascii_uppercase();
    let head = upper
        .split(|c: char| !c.is_ascii_alphabetic())
        .find(|token| !token.is_empty())
        .unwrap_or_default();

    if head != "INSERT" && head != "UPDATE" {
        return Err("只允许 INSERT 或 UPDATE 语句".to_string());
    }

    // 关键字按整词匹配，避免 created_at 这类字段名误判。
    for keyword in [
        "DROP", "ALTER", "TRUNCATE", "DELETE", "GRANT", "REVOKE", "CREATE", "REPLACE", "RENAME",
    ] {
        let hit = upper
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|token| token == keyword);
        if hit {
            return Err(format!("禁止使用关键字「{keyword}」"));
        }
    }

    if head == "UPDATE"
        && !upper
            .split_whitespace()
            .collect::<Vec<_>>()
            .contains(&"WHERE")
    {
        return Err("UPDATE 语句必须带 WHERE 条件".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// WEBHOOK
// ---------------------------------------------------------------------------

async fn exec_webhook(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    spec: &ActionSpec,
    context: &TemplateContext,
) -> Result<ActionResult, ApiError> {
    let url_raw = spec.url.clone().unwrap_or_default();
    if url_raw.trim().is_empty() {
        return Ok(ActionResult::failed(Value::Null, "WEBHOOK 动作缺少 url"));
    }

    let url = template::render_string(&url_raw, context)
        .map_err(|err| ApiError::bad_request(format!("地址模板渲染失败：{err}")))?;

    // 渲染后再做 SSRF 校验，防止模板把内网地址拼出来。
    match reqwest::Url::parse(&url) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or_default().to_string();
            if crate::modules::audit::service::is_blocked_host(&host)
                || host.eq_ignore_ascii_case("localhost")
                || host.ends_with(".local")
            {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "url": url }),
                    "回调地址不允许指向内网",
                ));
            }
        }
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "url": url }),
                format!("回调地址不是合法 URL：{err}"),
            ));
        }
    }

    let body = match spec.body.as_ref() {
        Some(raw) => template::render_value(raw, context)
            .map_err(|err| ApiError::bad_request(format!("请求体模板渲染失败：{err}")))?,
        None => serde_json::json!({ "task_id": task_id }),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    // 签名：alg = hmac-sha256 时用 secret_ref 指向的项目配置密钥。
    let mut signature: Option<String> = None;
    if let Some(sign) = spec.sign.as_ref() {
        let alg = sign
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if alg == "hmac-sha256" {
            let secret_ref = sign
                .get("secret_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if secret_ref.is_empty() {
                return Ok(ActionResult::failed(
                    serde_json::json!({ "url": url }),
                    "签名配置缺少 secret_ref",
                ));
            }
            let secret = match load_secret(state, project_id, &secret_ref).await {
                Ok(value) => value,
                Err(err) => {
                    return Ok(ActionResult::failed(
                        serde_json::json!({ "url": url }),
                        err.to_string(),
                    ));
                }
            };
            let payload = serde_json::to_string(&body).unwrap_or_default();
            signature = Some(hmac_sha256_hex(payload.as_bytes(), secret.as_bytes()));
        }
    }

    if let Some(value) = signature.as_ref() {
        insert_header(&mut headers, "X-Signature", value);
    }

    let timeout_ms = spec
        .timeout_ms
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(100, 120_000);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms as u64))
        .build()
    {
        Ok(value) => value,
        Err(err) => {
            return Ok(ActionResult::failed(
                serde_json::json!({ "url": url }),
                format!("HTTP 客户端初始化失败：{err}"),
            ));
        }
    };

    let retry = RetryPolicy::parse(spec);
    let request_log = serde_json::json!({ "url": url, "body": body });

    let mut attempt = 0;
    loop {
        attempt += 1;
        match client
            .post(&url)
            .headers(headers.clone())
            .json(&body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let payload = serde_json::json!({ "status": status.as_u16(), "body": text });
                if status.is_success() {
                    return Ok(ActionResult::success(request_log, payload, attempt - 1));
                }
                let retryable = status.as_u16() >= 500 || status.as_u16() == 429;
                if !retryable || attempt >= retry.max_attempts {
                    return Ok(ActionResult {
                        status: STATUS_FAILED.to_string(),
                        request: request_log,
                        response: payload,
                        error_message: Some(format!("回调失败，状态码 {}", status.as_u16())),
                        retry_count: attempt - 1,
                    });
                }
            }
            Err(err) => {
                let retryable = err.is_timeout() || err.is_connect();
                if !retryable || attempt >= retry.max_attempts {
                    return Ok(ActionResult {
                        status: STATUS_FAILED.to_string(),
                        request: request_log,
                        response: Value::Null,
                        error_message: Some(format!("回调异常：{err}")),
                        retry_count: attempt - 1,
                    });
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms(attempt, retry.backoff_ms))).await;
    }
}

// ---------------------------------------------------------------------------
// MQ
// ---------------------------------------------------------------------------

async fn exec_mq(
    state: &AppState,
    project_id: u64,
    spec: &ActionSpec,
    context: &TemplateContext,
) -> Result<ActionResult, ApiError> {
    let target = spec.target.clone().unwrap_or_default().trim().to_string();
    let topic = spec.topic.clone().unwrap_or_default();
    let body = match spec.body.as_ref() {
        Some(raw) => template::render_value(raw, context)
            .map_err(|err| ApiError::bad_request(format!("消息体模板渲染失败：{err}")))?,
        None => Value::Null,
    };

    let request_log = serde_json::json!({
        "target": target,
        "topic": topic,
        "body": body,
    });

    if target.is_empty() {
        return Ok(ActionResult::skipped(request_log, "MQ 动作未配置目标队列"));
    }

    let exists = crate::modules::project_config::repositories::find_config_by_name(
        state, project_id, "MQ", &target,
    )
    .await
    .map(|row| row.is_some())
    .unwrap_or(false);

    if !exists {
        return Ok(ActionResult::skipped(
            request_log,
            format!("MQ 目标「{target}」未配置"),
        ));
    }

    // 目标已存在，但当前没有接入具体 MQ 客户端（如 Kafka / RocketMQ），
    // 这里只做记录，等接入投递通道后再改为真实投递。
    Ok(ActionResult::skipped(
        request_log,
        format!("MQ 目标「{target}」已配置，消息投递通道待接入"),
    ))
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

/// 读取并解密项目连接配置。
async fn load_config(
    state: &AppState,
    project_id: u64,
    config_type: &str,
    name: &str,
) -> Result<(Value, Option<Value>, Option<Value>), ApiError> {
    let row = crate::modules::project_config::repositories::find_config_by_name(
        state,
        project_id,
        config_type,
        name,
    )
    .await?
    .ok_or_else(|| {
        ApiError::unprocessable(
            "DEPENDENCY_MISSING",
            format!("项目连接配置不存在：{config_type}/{name}"),
        )
    })?;

    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, project_id, &row.config_encrypted)?;
    Ok((plain, row.pool_json, row.tags))
}

/// 按名称读取项目配置里的密钥（不限定配置类型）。
async fn load_secret(state: &AppState, project_id: u64, name: &str) -> Result<String, ApiError> {
    let row = sqlx::query(
        "SELECT config_encrypted FROM project_config
          WHERE project_id = ? AND name = ? AND deleted_at IS NULL
          LIMIT 1",
    )
    .bind(project_id)
    .bind(name)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::unprocessable(
            "DEPENDENCY_MISSING",
            format!("签名密钥配置不存在：{name}"),
        ));
    };

    let cipher: Vec<u8> = row.get("config_encrypted");
    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, project_id, &cipher)?;
    for field in [
        "secret",
        "secret_key",
        "key",
        "token",
        "api_key",
        "password",
    ] {
        if let Some(value) = cfg_str(&plain, field) {
            if !value.trim().is_empty() {
                return Ok(value);
            }
        }
    }
    Err(ApiError::unprocessable(
        "DEPENDENCY_MISSING",
        format!("签名密钥配置「{name}」里没有可用的密钥字段"),
    ))
}

/// 从配置里取字符串字段。
fn cfg_str(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|item| item.as_str())
        .map(|text| text.to_string())
}

/// 从配置里取整数字段。
fn cfg_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|item| item.as_i64())
}

/// 把 JSON 值转成文本（用于 Redis 参数与日志）。
fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

/// 往请求头里塞一个值，非法键值直接忽略。
fn insert_header(headers: &mut HeaderMap, key: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(key.trim().as_bytes()) else {
        return;
    };
    let Ok(value) = HeaderValue::from_str(value) else {
        return;
    };
    headers.insert(name, value);
}

/// 按配置补鉴权头。支持字符串、对象与常见字段名。
fn apply_auth(headers: &mut HeaderMap, config: &Value) {
    match config.get("auth") {
        Some(Value::String(text)) => {
            if !text.trim().is_empty() {
                let value = if text.trim().to_ascii_lowercase().starts_with("bearer ") {
                    text.trim().to_string()
                } else {
                    format!("Bearer {}", text.trim())
                };
                insert_header(headers, "Authorization", &value);
            }
        }
        Some(Value::Object(fields)) => {
            let kind = fields
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let token = fields
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            match kind.as_str() {
                "bearer" => insert_header(headers, "Authorization", &format!("Bearer {token}")),
                "basic" => {
                    let user = fields
                        .get("username")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let pass = fields
                        .get("password")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let raw = format!("{user}:{pass}");
                    let encoded = base64_encode(raw.as_bytes());
                    insert_header(headers, "Authorization", &format!("Basic {encoded}"));
                }
                "header" => {
                    let name = fields
                        .get("header")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let value = fields
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or(&token);
                    insert_header(headers, name, value);
                }
                _ => {
                    if !token.is_empty() {
                        insert_header(headers, "Authorization", &format!("Bearer {token}"));
                    }
                }
            }
        }
        _ => {}
    }

    // 常见的扁平字段。
    if let Some(key) = cfg_str(config, "api_key") {
        let name = cfg_str(config, "api_key_header").unwrap_or_else(|| "X-API-Key".to_string());
        insert_header(headers, &name, &key);
    }
    if let Some(token) = cfg_str(config, "token") {
        if !config.get("auth").is_some() {
            insert_header(headers, "Authorization", &format!("Bearer {token}"));
        }
    }
}

/// 标准 Base64 编码。
fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

/// HMAC-SHA256 十六进制小写。
fn hmac_sha256_hex(payload: &[u8], secret: &[u8]) -> String {
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(value) => value,
        Err(_) => return String::new(),
    };
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// 指数退避 + ±20% 抖动。
fn backoff_ms(attempt: i32, base_ms: i64) -> u64 {
    let factor = 1i64 << (attempt.saturating_sub(1).clamp(0, 6) as u32);
    let base = base_ms.saturating_mul(factor).max(1);
    let jitter = base / 5;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.subsec_nanos() as i64)
        .unwrap_or(0);
    let offset = seed % (jitter * 2 + 1) - jitter;
    (base + offset).max(1) as u64
}

/// 取 URL 里的主机名。
fn url_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_string()))
}

/// 敏感字段名判定。
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("access_key")
        || lower.contains("private_key")
        || lower.contains("credential")
        || lower == "pwd"
        || lower == "authorization"
}

/// 请求日志脱敏：把敏感字段的值替换掉。
fn mask_sensitive(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut masked = Map::with_capacity(fields.len());
            for (key, item) in fields {
                if is_sensitive_key(key) {
                    masked.insert(key.clone(), Value::String("***".to_string()));
                } else {
                    masked.insert(key.clone(), mask_sensitive(item));
                }
            }
            Value::Object(masked)
        }
        Value::Array(items) => Value::Array(items.iter().map(mask_sensitive).collect()),
        other => other.clone(),
    }
}

/// 截断过大的 JSON，并标记 `_truncated`。
fn truncate_json(value: Value) -> Value {
    let text = serde_json::to_string(&value).unwrap_or_default();
    if text.len() <= MAX_LOG_BYTES {
        return value;
    }
    let mut fields = Map::new();
    fields.insert("_truncated".to_string(), Value::Bool(true));
    fields.insert(
        "_preview".to_string(),
        Value::String(text.chars().take(1024).collect()),
    );
    Value::Object(fields)
}

/// 动作耗时直方图桶（秒）。
fn duration_buckets() -> Vec<f64> {
    vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
}

/// 写一行动作执行日志。写失败只告警，不影响动作结论。
async fn write_exec_log(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    route_type: &str,
    spec: &ActionSpec,
    outcome: &ActionOutcome,
) {
    let id = state.ids.next_id();
    let now = chrono::Utc::now().naive_utc();
    let result = sqlx::query(
        "INSERT INTO action_exec_log
            (id, task_id, project_id, route_type, action_id, action_type, action_name,
             request_json, response_json, status, retry_count, duration_ms, error_message,
             created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(task_id)
    .bind(project_id)
    .bind(route_type)
    .bind(&outcome.action_id)
    .bind(&outcome.action_type)
    .bind(spec.name.clone())
    .bind(&outcome.request)
    .bind(&outcome.response)
    .bind(&outcome.status)
    .bind(outcome.retry_count)
    .bind(outcome.duration_ms as i32)
    .bind(outcome.error_message.clone())
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(err) = result {
        tracing::error!(error = %err, task_id, action_id = %outcome.action_id, "写动作执行日志失败");
    }
}
