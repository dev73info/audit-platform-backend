//! 开放 API 的签名校验、限流与业务编排。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use redis::AsyncCommands;
use serde_json::{Value, json};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::common::MediaItem;
use crate::models::ops::AuditLogEntry;
use crate::models::task::TaskCommand;
use crate::security::signature;
use crate::modules::openapi::repositories;

/// 开放 API 的调用上下文（已通过签名校验）。
#[derive(Debug, Clone)]
pub struct VerifiedClient {
    pub client_id: u64,
    pub project_id: u64,
    pub app_key: String,
    pub name: String,
}

/// 签名头。
#[derive(Debug, Clone)]
pub struct SignatureRequest {
    pub api_key: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub client_ip: String,
}

/// 校验签名并返回客户端身份。
///
/// 校验顺序：参数完整性 → AppKey 存在且启用 → 时间偏差 → Nonce 未重复 →
/// 签名比对 → IP 白名单 → 项目状态 → 限流。任一步失败立即返回。
pub async fn verify(
    state: &AppState,
    request: &SignatureRequest,
) -> Result<VerifiedClient, ApiError> {
    if request.api_key.trim().is_empty()
        || request.timestamp.trim().is_empty()
        || request.nonce.trim().is_empty()
        || request.signature.trim().is_empty()
    {
        return Err(ApiError::bad_request("缺少签名请求头"));
    }

    let mut record = repositories::find_client_by_app_key(state, &request.api_key)
        .await?
        .ok_or_else(|| ApiError::unauthorized("UNAUTHORIZED", "AppKey 不存在"))?;

    if record.status != "ACTIVE" {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "AppKey 已停用"));
    }

    // 解密密钥
    let (secret_cipher, callback_cipher) =
        repositories::find_client_secret_cipher(state, record.id).await?;
    let key = state.settings.master_key();
    let secret = crate::security::encrypt::decrypt_bytes(&key, &secret_cipher)
        .map_err(|_| ApiError::internal("客户端密钥解密失败"))?;
    let secret = String::from_utf8_lossy(&secret).to_string();
    record.secret = secret.clone();
    record.callback_secret = callback_cipher.and_then(|cipher| {
        crate::security::encrypt::decrypt_bytes(&key, &cipher).ok()
            .and_then(|raw| String::from_utf8(raw).ok())
    });

    // 时间偏差
    signature::check_timestamp(&request.timestamp, state.settings.security.signature_tolerance_sec)
        .map_err(|_| ApiError::bad_request_with("TIMESTAMP_EXPIRED", "时间戳偏差超过允许范围"))?;

    // Nonce 防重放
    if let Some(redis) = state.redis.as_ref() {
        let mut conn = redis.clone();
        let key = format!("audit:{}:nonce:{}", record.project_id, request.nonce);
        match conn.set_nx(&key, "1").await {
            Ok(true) => {
                let _: () = conn.expire(&key, 600i64).await.unwrap_or(());
            }
            Ok(false) => {
                return Err(ApiError::bad_request_with("REPLAY_ATTACK", "Nonce 已被使用"));
            }
            Err(err) => {
                tracing::warn!(error = %err, "写入 Nonce 失败，跳过防重放校验");
            }
        }
    } else {
        tracing::warn!(app_key = %request.api_key, "Redis 不可用，Nonce 防重放已降级");
    }

    // 签名比对
    let canonical = signature::canonical_string(
        &request.method,
        &request.path,
        &request.timestamp,
        &request.nonce,
        &request.body,
    );
    if !signature::verify_signature(&secret, &canonical, &request.signature) {
        write_audit(
            state,
            AuditLogEntry {
                project_id: Some(record.project_id),
                operator: request.api_key.clone(),
                action: "API_SIGN_FAILED".to_string(),
                object_type: Some("API_CLIENT".to_string()),
                object_id: Some(record.id.to_string()),
                result: "FAIL".to_string(),
                detail: Some(json!({ "path": request.path })),
                ..Default::default()
            },
        )
        .await;
        return Err(ApiError::bad_request_with(
            "INVALID_SIGNATURE",
            "签名校验不通过",
        ));
    }

    // IP 白名单
    if !record.allow_ips.is_empty() {
        let ip = request.client_ip.trim();
        let allowed = record
            .allow_ips
            .iter()
            .any(|pattern| ip_matches(pattern, ip));
        if !allowed {
            return Err(ApiError::forbidden("PERM_DENIED", "来源 IP 不在白名单内"));
        }
    }

    // 项目状态
    let status = repositories::find_project_status(state, record.project_id)
        .await?
        .ok_or_else(|| ApiError::not_found("项目不存在"))?;
    match status.as_str() {
        "PAUSED" => return Err(ApiError::forbidden("PROJECT_PAUSED", "项目已暂停")),
        "DELETED" => return Err(ApiError::forbidden("PROJECT_DELETED", "项目已删除")),
        "DISABLED" => return Err(ApiError::forbidden("PROJECT_PAUSED", "项目已停用")),
        _ => {}
    }

    // 限流
    let scope = format!("{}:{}", record.app_key, request.path);
    check_rate_limit(state, record.project_id, &scope, &request.client_ip).await?;

    let _ = repositories::touch_client(state, record.id).await;

    Ok(VerifiedClient {
        client_id: record.id,
        project_id: record.project_id,
        app_key: record.app_key,
        name: record.name,
    })
}

/// IP 白名单匹配：支持精确匹配与 `*` 结尾的前缀匹配。
fn ip_matches(pattern: &str, ip: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return ip.starts_with(prefix);
    }
    pattern == ip
}

/// 三级令牌桶：项目 / 客户端 / 单 IP。超限返回 429。
pub async fn check_rate_limit(
    state: &AppState,
    project_id: u64,
    scope: &str,
    client_ip: &str,
) -> Result<(), ApiError> {
    let Some(redis) = state.redis.as_ref() else {
        // Redis 不可用时降级为不限流，只打警告。
        tracing::warn!(project_id, "Redis 不可用，开放 API 限流已降级为不限制");
        return Ok(());
    };

    let quota = crate::modules::audit::repositories::load_quota(state, project_id).await?;
    let limits = [
        (format!("audit:{project_id}:rate:project"), quota.max_qps),
        (format!("audit:{project_id}:rate:client:{scope}"), (quota.max_qps / 2).max(1)),
        (format!("audit:{project_id}:rate:ip:{client_ip}"), 200),
    ];

    let mut conn = redis.clone();
    for (key, limit) in limits {
        let count: i64 = conn.incr(&key, 1i64).await.unwrap_or(0);
        if count == 1 {
            let _: () = conn.expire(&key, 1i64).await.unwrap_or(());
        }
        if count > limit {
            write_audit(
                state,
                AuditLogEntry {
                    project_id: Some(project_id),
                    operator: "openapi".to_string(),
                    action: "API_RATE_LIMITED".to_string(),
                    object_type: Some("API_CLIENT".to_string()),
                    result: "FAIL".to_string(),
                    detail: Some(json!({ "scope": scope, "limit": limit })),
                    ..Default::default()
                },
            )
            .await;
            return Err(ApiError::rate_limited("请求过于频繁，请稍后重试", 1));
        }
    }
    Ok(())
}

/// 提交任务的入参。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubmitRequest {
    #[serde(default)]
    pub biz_key: Option<String>,
    #[serde(default)]
    pub media: Vec<MediaItem>,
    #[serde(default)]
    pub ext: Value,
    #[serde(default)]
    pub callback: Option<CallbackSpec>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
}

/// 回调配置。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CallbackSpec {
    pub url: String,
    #[serde(default)]
    pub headers: Value,
    #[serde(default)]
    pub secret_ref: Option<String>,
}

/// 提交响应。
#[derive(Debug, Clone, serde::Serialize)]
pub struct SubmitResponse {
    pub task_id: u64,
    pub task_no: String,
    pub dedupe: String,
    pub status: String,
    pub submit_at: String,
    /// 命中去重时的原任务。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_task_id: Option<u64>,
}

/// 校验提交入参。
pub fn validate_submit(request: &SubmitRequest) -> Result<(), ApiError> {
    if request.media.is_empty() {
        return Err(ApiError::invalid_param(
            "媒体内容不能为空",
            vec![crate::error::FieldError::new("media", "至少提交一条媒体")],
        ));
    }
    for (index, media) in request.media.iter().enumerate() {
        match media.media_type.as_str() {
            "text" => {
                if media.content.trim().is_empty() {
                    return Err(ApiError::invalid_param(
                        "文本媒体缺少内容",
                        vec![crate::error::FieldError::new(
                            format!("media[{index}].content"),
                            "文本媒体必须提供 content",
                        )],
                    ));
                }
            }
            "image" | "video" | "audio" => {
                if media.url.trim().is_empty() {
                    return Err(ApiError::invalid_param(
                        "媒体缺少地址",
                        vec![crate::error::FieldError::new(
                            format!("media[{index}].url"),
                            "图片/视频/音频必须提供 url",
                        )],
                    ));
                }
            }
            other => {
                return Err(ApiError::invalid_param(
                    "媒体类型不支持",
                    vec![crate::error::FieldError::new(
                        format!("media[{index}].type"),
                        format!("不支持的媒体类型：{other}"),
                    )],
                ));
            }
        }
    }
    Ok(())
}

/// 执行一次提交：建任务 → 跑流水线 → 返回结果。
pub async fn submit(
    state: &AppState,
    client: &VerifiedClient,
    audit_id: u64,
    request: SubmitRequest,
) -> Result<SubmitResponse, ApiError> {
    validate_submit(&request)?;

    let audit_row = crate::modules::audit::repositories::find_audit(state, audit_id).await?;
    if audit_row.project_id != client.project_id {
        return Err(ApiError::out_of_scope("审核定义不属于该项目"));
    }
    if audit_row.status != "ACTIVE" {
        return Err(ApiError::conflict("DEPENDENCY_MISSING", "审核未启用"));
    }

    let snapshot = crate::engine::worker::load_snapshot(state, audit_id).await?;
    let rules = snapshot.rules.clone();

    let command = TaskCommand {
        project_id: client.project_id,
        audit_id,
        source_type: "OPENAPI".to_string(),
        source_id: Some(client.client_id),
        biz_key: request.biz_key.clone(),
        media: request.media.clone(),
        ext: request.ext.clone(),
        callback_url: request.callback.as_ref().map(|item| item.url.clone()),
        dedupe_key: request.dedupe_key.clone(),
        sync_wait_ms: None,
        trace_id: Some(crate::trace::current_trace_id()),
    };

    let outcome = crate::engine::pipeline::run_pipeline(
        state,
        crate::engine::pipeline::PipelineInput {
            command,
            audit: snapshot,
            audit_rules: rules,
            routes: repositories::load_routes(state, audit_id).await?,
        },
    )
    .await?;

    let dedupe = if outcome.status == crate::common::TaskStatus::Duplicated {
        "DUPLICATED"
    } else {
        "NORMAL"
    };

    write_audit(
        state,
        AuditLogEntry {
            project_id: Some(client.project_id),
            operator: client.app_key.clone(),
            action: "API_CALL".to_string(),
            object_type: Some("AUDIT".to_string()),
            object_id: Some(audit_id.to_string()),
            result: "SUCCESS".to_string(),
            detail: Some(json!({
                "task_id": outcome.task_id,
                "biz_key": request.biz_key,
                "dedupe": dedupe,
            })),
            ..Default::default()
        },
    )
    .await;

    Ok(SubmitResponse {
        task_id: outcome.task_id,
        task_no: outcome.task_no,
        dedupe: dedupe.to_string(),
        status: outcome.status.as_str().to_string(),
        submit_at: crate::common::now_iso8601(),
        origin_task_id: None,
    })
}

/// 任务查询结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TaskResultResponse {
    pub task_id: u64,
    pub task_no: String,
    pub status: String,
    pub result: String,
    pub reasons: Vec<Value>,
    pub media: Vec<Value>,
    pub duration_ms: Option<i32>,
    pub finished_at: Option<String>,
}

/// 把任务行转成对外结果。
pub fn to_task_result(row: repositories::TaskResultRow) -> TaskResultResponse {
    let mut reasons: Vec<Value> = Vec::new();
    if let Some(model) = row.model_result_json.as_ref() {
        if let Some(label) = model.get("label").and_then(Value::as_str) {
            reasons.push(json!({
                "source": "model",
                "label": label,
                "score": model.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            }));
        }
    }
    if let Some(rules) = row.rule_hit_json.as_ref() {
        if let Some(items) = rules.as_array() {
            for item in items {
                if item.get("hit").and_then(Value::as_bool).unwrap_or(false) {
                    reasons.push(json!({
                        "source": "rule",
                        "rule": item.get("rule").and_then(Value::as_str).unwrap_or_default(),
                    }));
                }
            }
        }
    }

    let media = row
        .media
        .iter()
        .map(|(media_type, url)| {
            json!({ "type": media_type, "url": url })
        })
        .collect();

    TaskResultResponse {
        task_id: row.id,
        task_no: row.task_no,
        status: row.status,
        result: row.result,
        reasons,
        media,
        duration_ms: row.duration_ms,
        finished_at: row.finished_at,
    }
}

/// 轮询响应。
#[derive(Debug, Clone, serde::Serialize)]
pub struct PollResponse {
    pub items: Vec<TaskResultResponse>,
    pub next_cursor: String,
    pub has_more: bool,
}

/// 游标编解码：base64(`audit_id:last_task_id`)。
pub fn encode_cursor(audit_id: u64, last_id: u64) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{audit_id}:{last_id}"))
}

/// 解码游标；非法游标按从头开始处理。
pub fn decode_cursor(cursor: &str, audit_id: u64) -> u64 {
    use base64::Engine;
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cursor.trim()) else {
        return 0;
    };
    let Ok(text) = String::from_utf8(raw) else {
        return 0;
    };
    let mut parts = text.split(':');
    let cursor_audit = parts.next().and_then(|v| v.parse::<u64>().ok());
    let last_id = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    if cursor_audit != Some(audit_id) {
        return 0;
    }
    last_id
}

/// 注册回调。
pub async fn register_callback(
    state: &AppState,
    client: &VerifiedClient,
    callback_url: &str,
    secret: Option<String>,
) -> Result<(), ApiError> {
    let host = host_of(callback_url);
    if host.is_empty() || crate::modules::audit::service::is_blocked_host(&host) {
        return Err(ApiError::invalid_param(
            "回调地址不允许指向内网",
            vec![crate::error::FieldError::new("callback_url", "回调地址必须指向公网地址")],
        ));
    }

    let cipher = match secret {
        Some(raw) if !raw.trim().is_empty() => {
            let key = state.settings.master_key();
            Some(crate::security::encrypt::encrypt_bytes(&key, raw.as_bytes())?)
        }
        _ => None,
    };

    repositories::update_callback(state, client.client_id, callback_url, cipher).await
}

/// 从 URL 里取主机部分。
pub fn host_of(url: &str) -> String {
    let mut rest = url.trim();
    if let Some(index) = rest.find("://") {
        rest = &rest[index + 3..];
    }
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    host.trim().to_ascii_lowercase()
}

/// 写审计日志（失败只打日志，不影响主流程）。
pub async fn write_audit(state: &AppState, entry: AuditLogEntry) {
    if let Err(err) = crate::modules::auth::repositories::write_audit_log(state, entry).await {
        tracing::error!(error = %err, "写开放 API 审计日志失败");
    }
}

/// WebSocket 连接计数（按项目）。
static WS_CONNECTIONS: std::sync::LazyLock<std::sync::Mutex<HashMap<u64, AtomicUsize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// 登记一条 WebSocket 连接；超过上限返回 false。
pub fn acquire_ws_slot(project_id: u64, limit: usize) -> bool {
    let mut guard = match WS_CONNECTIONS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let counter = guard.entry(project_id).or_insert_with(|| AtomicUsize::new(0));
    let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
    if current > limit {
        counter.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    true
}

/// 释放一条 WebSocket 连接。
pub fn release_ws_slot(project_id: u64) {
    let guard = match WS_CONNECTIONS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(counter) = guard.get(&project_id) {
        counter.fetch_sub(1, Ordering::SeqCst);
    }
}
