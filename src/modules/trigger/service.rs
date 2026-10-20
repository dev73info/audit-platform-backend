//! 触发源的业务编排：CRUD、启停、测试与最近消费记录。
//!
//! 四种触发源（Redis 队列 / 轮询接口 / WebSocket / 开放 API）的配置结构各不相同，
//! 校验与归一化都集中在本文件的 `validate_trigger` 与 `normalize_config`。

use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};

use crate::db::AppState;
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::audit::{SaveTriggerRequest, TriggerSourceRow, TriggerSourceView};
use crate::models::ops::AuditLogEntry;
use crate::modules::audit::repositories::write_audit_log;
use crate::modules::audit::service as audit_service;
use crate::modules::trigger::repositories;

/// 触发源类型。
const TYPE_REDIS: &str = "REDIS";
const TYPE_POLLING: &str = "POLLING";
const TYPE_WEBSOCKET: &str = "WEBSOCKET";
const TYPE_OPENAPI: &str = "OPENAPI";

/// 审计日志里的对象类型。
const OBJECT_TRIGGER: &str = "TRIGGER";

/// 触发源测试的阶段耗时视图。
#[derive(Debug, Clone, Serialize)]
pub struct StageView {
    pub stage: String,
    pub ok: bool,
    pub cost_ms: i64,
    pub detail: String,
}

/// 触发源消费记录视图。
#[derive(Debug, Clone, Serialize)]
pub struct ConsumeLogView {
    pub id: u64,
    pub message_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// 各类触发源的默认优先级（数字小的先消费）。
pub fn default_priority(trigger_type: &str) -> i32 {
    match trigger_type.trim().to_ascii_uppercase().as_str() {
        TYPE_REDIS => 10,
        TYPE_POLLING => 20,
        TYPE_WEBSOCKET => 30,
        TYPE_OPENAPI => 40,
        _ => 50,
    }
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// 列出审核下的触发源。
pub async fn list_triggers(
    state: &AppState,
    auth: &AuthContext,
    audit_id: u64,
) -> Result<Vec<TriggerSourceView>, ApiError> {
    auth.require_permission("trigger:read")?;
    let project_id = find_audit_project(state, audit_id).await?;
    auth.require_project(project_id)?;

    let rows = repositories::list_triggers(state, audit_id).await?;
    Ok(rows.iter().map(trigger_view).collect())
}

/// 新建触发源。
pub async fn create_trigger(
    state: &AppState,
    auth: &AuthContext,
    audit_id: u64,
    request: SaveTriggerRequest,
) -> Result<TriggerSourceView, ApiError> {
    auth.require_permission("trigger:write")?;
    let project_id = find_audit_project(state, audit_id).await?;
    auth.require_project(project_id)?;
    ensure_project_writable(state, project_id).await?;

    validate_trigger(&request)?;

    let trigger_type = request.trigger_type.trim().to_ascii_uppercase();
    let priority = request
        .priority
        .unwrap_or_else(|| default_priority(&trigger_type));
    let status = request
        .status
        .clone()
        .unwrap_or_else(|| "ACTIVE".to_string())
        .to_ascii_uppercase();
    let config = normalize_config(&trigger_type, &request.config);

    let trigger_id = crate::common::ids::next_id();
    let mut tx = state.db.begin().await?;
    repositories::insert_trigger(
        &mut tx,
        &repositories::TriggerInsert {
            id: trigger_id,
            project_id,
            audit_id,
            trigger_type: trigger_type.clone(),
            name: request.name.trim().to_string(),
            config_json: config,
            priority,
            status: status.clone(),
        },
    )
    .await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            project_id,
            "TRIGGER_CREATE",
            trigger_id,
            json!({ "audit_id": audit_id, "type": trigger_type, "name": request.name }),
        ),
    )
    .await?;

    get_trigger(state, auth, trigger_id).await
}

/// 取触发源详情。
pub async fn get_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<TriggerSourceView, ApiError> {
    auth.require_permission("trigger:read")?;
    let row = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(row.project_id)?;
    Ok(trigger_view(&row))
}

/// 更新触发源。
pub async fn update_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
    request: SaveTriggerRequest,
) -> Result<TriggerSourceView, ApiError> {
    auth.require_permission("trigger:write")?;
    let current = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(current.project_id)?;
    ensure_project_writable(state, current.project_id).await?;

    validate_trigger(&request)?;

    let trigger_type = request.trigger_type.trim().to_ascii_uppercase();
    let priority = request
        .priority
        .unwrap_or_else(|| default_priority(&trigger_type));
    let status = request
        .status
        .clone()
        .unwrap_or_else(|| current.status.clone())
        .to_ascii_uppercase();
    let config = normalize_config(&trigger_type, &request.config);

    let mut tx = state.db.begin().await?;
    repositories::update_trigger(
        &mut tx,
        trigger_id,
        &repositories::TriggerUpdate {
            trigger_type: trigger_type.clone(),
            name: request.name.trim().to_string(),
            config_json: config,
            priority,
            status,
        },
    )
    .await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            current.project_id,
            "TRIGGER_UPDATE",
            trigger_id,
            json!({ "audit_id": current.audit_id, "type": trigger_type, "name": request.name }),
        ),
    )
    .await?;

    get_trigger(state, auth, trigger_id).await
}

/// 删除触发源（软删除）。
pub async fn delete_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<Value, ApiError> {
    auth.require_permission("trigger:write")?;
    let current = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(current.project_id)?;

    let mut tx = state.db.begin().await?;
    repositories::soft_delete_trigger(&mut tx, trigger_id).await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            current.project_id,
            "TRIGGER_DELETE",
            trigger_id,
            json!({ "audit_id": current.audit_id, "name": current.name }),
        ),
    )
    .await?;

    Ok(json!({ "id": trigger_id, "deleted": true }))
}

/// 启用触发源。
pub async fn enable_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<TriggerSourceView, ApiError> {
    auth.require_permission("trigger:write")?;
    let current = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(current.project_id)?;

    let mut tx = state.db.begin().await?;
    repositories::set_trigger_status(&mut tx, trigger_id, "ACTIVE").await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            current.project_id,
            "TRIGGER_ENABLE",
            trigger_id,
            json!({ "audit_id": current.audit_id, "name": current.name }),
        ),
    )
    .await?;

    get_trigger(state, auth, trigger_id).await
}

/// 暂停触发源。
pub async fn pause_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<TriggerSourceView, ApiError> {
    auth.require_permission("trigger:write")?;
    let current = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(current.project_id)?;

    let mut tx = state.db.begin().await?;
    repositories::set_trigger_status(&mut tx, trigger_id, "PAUSED").await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            current.project_id,
            "TRIGGER_PAUSE",
            trigger_id,
            json!({ "audit_id": current.audit_id, "name": current.name }),
        ),
    )
    .await?;

    get_trigger(state, auth, trigger_id).await
}

/// 测试触发源：构造一条合法消息做格式与链路校验，不真正跑审核。
pub async fn test_trigger(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<Value, ApiError> {
    auth.require_permission("trigger:write")?;
    let row = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(row.project_id)?;

    let total_start = Instant::now();
    let mut stages: Vec<StageView> = Vec::new();

    // 第一段：格式校验——构造一条合法消息并检查必填字段。
    let format_start = Instant::now();
    let sample = build_sample_message(&row);
    let format_detail = match validate_sample(&sample) {
        Ok(detail) => StageView {
            stage: "格式校验".to_string(),
            ok: true,
            cost_ms: format_start.elapsed().as_millis() as i64,
            detail,
        },
        Err(reason) => StageView {
            stage: "格式校验".to_string(),
            ok: false,
            cost_ms: format_start.elapsed().as_millis() as i64,
            detail: reason,
        },
    };
    stages.push(format_detail);

    // 第二段：链路校验——检查依赖的中间件与配置是否就绪。
    let link_start = Instant::now();
    let link_detail = match check_link(state, &row).await {
        Ok(detail) => StageView {
            stage: "链路校验".to_string(),
            ok: true,
            cost_ms: link_start.elapsed().as_millis() as i64,
            detail,
        },
        Err(reason) => StageView {
            stage: "链路校验".to_string(),
            ok: false,
            cost_ms: link_start.elapsed().as_millis() as i64,
            detail: reason,
        },
    };
    stages.push(link_detail);

    let ok = stages.iter().all(|stage| stage.ok);
    let total_cost_ms = total_start.elapsed().as_millis() as i64;
    let message_id = format!("test-{}", crate::common::ids::next_id());

    // 测试也要留一条消费记录，方便在「最近消费记录」里回看。
    let mut tx = state.db.begin().await?;
    let log_id = repositories::insert_consume_log(
        &mut tx,
        &repositories::ConsumeLogInsert {
            id: crate::common::ids::next_id(),
            project_id: row.project_id,
            audit_id: row.audit_id,
            trigger_id,
            message_id: Some(message_id.clone()),
            status: if ok { "SUCCESS" } else { "FAILED" }.to_string(),
            duration_ms: Some(total_cost_ms as i32),
            error_message: stages
                .iter()
                .find(|stage| !stage.ok)
                .map(|stage| stage.detail.clone()),
        },
    )
    .await?;
    tx.commit().await?;

    write_audit_log(
        state,
        log_entry(
            auth,
            row.project_id,
            "TRIGGER_TEST",
            trigger_id,
            json!({ "audit_id": row.audit_id, "ok": ok, "total_cost_ms": total_cost_ms }),
        ),
    )
    .await?;

    Ok(json!({
        "ok": ok,
        "trigger_id": trigger_id,
        "type": row.r#type,
        "message_id": message_id,
        "stages": stages,
        "total_cost_ms": total_cost_ms,
        "sample": sample,
        "consume_log_id": log_id,
    }))
}

/// 取触发源最近的消费记录（最多 50 条）。
pub async fn recent_logs(
    state: &AppState,
    auth: &AuthContext,
    trigger_id: u64,
) -> Result<Vec<ConsumeLogView>, ApiError> {
    auth.require_permission("trigger:read")?;
    let row = repositories::find_trigger(state, trigger_id).await?;
    auth.require_project(row.project_id)?;

    let rows = repositories::list_consume_logs(state, trigger_id, 50).await?;
    Ok(rows
        .into_iter()
        .map(|item| ConsumeLogView {
            id: item.id,
            message_id: item.message_id,
            status: item.status,
            duration_ms: item.duration_ms,
            error_message: item.error_message,
            created_at: crate::common::format_datetime(item.created_at),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// 校验与归一化
// ---------------------------------------------------------------------------

/// 校验触发源入参：通用字段 + 类型专属配置。
pub fn validate_trigger(trigger: &SaveTriggerRequest) -> Result<(), ApiError> {
    let mut errors: Vec<FieldError> = Vec::new();

    if trigger.name.trim().is_empty() {
        errors.push(FieldError::new("name", "触发源名称不能为空"));
    } else if trigger.name.chars().count() > 64 {
        errors.push(FieldError::new("name", "触发源名称不能超过 64 个字符"));
    }

    let trigger_type = trigger.trigger_type.trim().to_ascii_uppercase();
    if !matches!(
        trigger_type.as_str(),
        TYPE_REDIS | TYPE_POLLING | TYPE_WEBSOCKET | TYPE_OPENAPI
    ) {
        errors.push(FieldError::new(
            "type",
            "触发源类型只能是 REDIS / POLLING / WEBSOCKET / OPENAPI",
        ));
        return Err(ApiError::invalid_param("触发源配置校验失败", errors));
    }

    if trigger.config.as_object().is_none() {
        errors.push(FieldError::new("config", "触发源配置必须是 JSON 对象"));
        return Err(ApiError::invalid_param("触发源配置校验失败", errors));
    }

    match trigger_type.as_str() {
        TYPE_REDIS => {
            if config_str(&trigger.config, "stream").is_empty() {
                errors.push(FieldError::new("config.stream", "Redis 队列名不能为空"));
            }
            if config_str(&trigger.config, "group").is_empty() {
                errors.push(FieldError::new("config.group", "Redis 消费组不能为空"));
            }
            check_range(
                &mut errors,
                "config.batch_size",
                config_i64(&trigger.config, "batch_size").unwrap_or(16),
                1,
                1000,
                "批量大小",
            );
            check_range(
                &mut errors,
                "config.visibility_timeout_ms",
                config_i64(&trigger.config, "visibility_timeout_ms").unwrap_or(60000),
                1000,
                600000,
                "可见性超时",
            );
        }
        TYPE_POLLING => {
            let url = config_str(&trigger.config, "url");
            if url.is_empty() {
                errors.push(FieldError::new("config.url", "轮询接口地址不能为空"));
            } else if let Err(reason) = check_public_url(&url) {
                errors.push(FieldError::new("config.url", reason));
            }
            check_range(
                &mut errors,
                "config.interval_sec",
                config_i64(&trigger.config, "interval_sec").unwrap_or(10),
                5,
                300,
                "轮询间隔",
            );
            check_range(
                &mut errors,
                "config.page_size",
                config_i64(&trigger.config, "page_size").unwrap_or(50),
                1,
                500,
                "分页大小",
            );
        }
        TYPE_WEBSOCKET => {
            let host = config_str(&trigger.config, "host");
            if host.is_empty() {
                errors.push(FieldError::new("config.host", "WebSocket 主机不能为空"));
            } else if let Err(reason) = check_public_host(&host) {
                errors.push(FieldError::new("config.host", reason));
            }
            let auth_type = {
                let value = config_str(&trigger.config, "auth_type");
                if value.is_empty() {
                    "none".to_string()
                } else {
                    value
                }
            };
            if !matches!(
                auth_type.as_str(),
                "none" | "basic" | "bearer" | "header" | "hmac"
            ) {
                errors.push(FieldError::new(
                    "config.auth_type",
                    "认证方式只能是 none / basic / bearer / header / hmac",
                ));
            }
            check_range(
                &mut errors,
                "config.heartbeat_sec",
                config_i64(&trigger.config, "heartbeat_sec").unwrap_or(30),
                5,
                300,
                "心跳间隔",
            );
        }
        TYPE_OPENAPI => {
            check_range(
                &mut errors,
                "config.sync_wait_ms",
                config_i64(&trigger.config, "sync_wait_ms").unwrap_or(3000),
                0,
                30000,
                "同步等待时间",
            );
        }
        _ => {}
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiError::invalid_param("触发源配置校验失败", errors))
    }
}

/// 归一化触发源配置：补齐默认值后落库。
pub fn normalize_config(trigger_type: &str, config: &Value) -> Value {
    match trigger_type.trim().to_ascii_uppercase().as_str() {
        TYPE_REDIS => {
            let stream = config_str(config, "stream");
            let group = config_str(config, "group");
            let batch_size = config_i64(config, "batch_size").unwrap_or(16);
            let visibility_timeout_ms =
                config_i64(config, "visibility_timeout_ms").unwrap_or(60000);
            json!({
                "stream": stream,
                "group": group,
                "batch_size": batch_size,
                "visibility_timeout_ms": visibility_timeout_ms,
            })
        }
        TYPE_POLLING => {
            let url = config_str(config, "url");
            let interval_sec = config_i64(config, "interval_sec").unwrap_or(10);
            let cursor_path = non_empty(config_str(config, "cursor_path"), "$.cursor");
            let biz_key_path = non_empty(config_str(config, "biz_key_path"), "$.biz_key");
            let page_size = config_i64(config, "page_size").unwrap_or(50);
            let increment_field = config_str(config, "increment_field");
            json!({
                "url": url,
                "interval_sec": interval_sec,
                "cursor_path": cursor_path,
                "biz_key_path": biz_key_path,
                "page_size": page_size,
                "increment_field": increment_field,
            })
        }
        TYPE_WEBSOCKET => {
            let host = config_str(config, "host");
            let path = non_empty(config_str(config, "path"), "/ws");
            let auth_type = non_empty(config_str(config, "auth_type"), "none");
            let topics = config_strings(config, "topics");
            let heartbeat_sec = config_i64(config, "heartbeat_sec").unwrap_or(30);
            json!({
                "host": host,
                "path": path,
                "auth_type": auth_type,
                "topics": topics,
                "heartbeat_sec": heartbeat_sec,
            })
        }
        TYPE_OPENAPI => {
            let sync_wait_ms = config_i64(config, "sync_wait_ms").unwrap_or(3000);
            let require_biz_key = config_bool(config, "require_biz_key").unwrap_or(true);
            json!({
                "sync_wait_ms": sync_wait_ms,
                "require_biz_key": require_biz_key,
            })
        }
        _ => config.clone(),
    }
}

/// 取非空值，空则用默认值。
fn non_empty(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

/// 构造一条合法的测试消息。
fn build_sample_message(row: &TriggerSourceRow) -> Value {
    let biz_key = format!("test:{}", row.id);
    json!({
        "biz_key": biz_key,
        "media": [ { "type": "text", "content": "这是一条触发源测试消息" } ],
        "ext": { "source": "trigger_test", "trigger_id": row.id },
        "task": { "source_type": row.r#type },
    })
}

/// 校验测试消息的格式。
fn validate_sample(sample: &Value) -> Result<String, String> {
    let Some(object) = sample.as_object() else {
        return Err("测试消息必须是 JSON 对象".to_string());
    };

    let biz_key = object
        .get("biz_key")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if biz_key.trim().is_empty() {
        return Err("测试消息缺少 biz_key".to_string());
    }

    let media = object.get("media").and_then(|value| value.as_array());
    let Some(media) = media else {
        return Err("测试消息缺少 media 数组".to_string());
    };
    if media.is_empty() {
        return Err("测试消息的 media 不能为空".to_string());
    }
    for item in media {
        let media_type = item
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if media_type.trim().is_empty() {
            return Err("测试消息的媒体缺少 type 字段".to_string());
        }
    }

    Ok(format!("消息格式合法，biz_key={biz_key}"))
}

/// 链路校验：检查触发源依赖的中间件与配置是否就绪。
async fn check_link(state: &AppState, row: &TriggerSourceRow) -> Result<String, String> {
    match row.r#type.as_str() {
        TYPE_REDIS => {
            if state.redis_available() {
                Ok("Redis 连接可用".to_string())
            } else {
                Err("Redis 连接不可用，请检查系统 Redis 配置".to_string())
            }
        }
        TYPE_POLLING => {
            let url = config_str(&row.config_json, "url");
            check_public_url(&url)?;
            Ok(format!("轮询地址可用：{url}"))
        }
        TYPE_WEBSOCKET => {
            let host = config_str(&row.config_json, "host");
            check_public_host(&host)?;
            Ok(format!("WebSocket 主机可用：{host}"))
        }
        TYPE_OPENAPI => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM api_client WHERE project_id = ? AND status = 'ACTIVE'",
            )
            .bind(row.project_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
            if count > 0 {
                Ok("项目已配置可用的开放 API 客户端".to_string())
            } else {
                Err("项目还没有启用中的开放 API 客户端".to_string())
            }
        }
        other => Err(format!("未知的触发源类型「{other}」")),
    }
}

/// 校验 URL 指向的主机不是内网地址。
fn check_public_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| "地址格式不正确".to_string())?;
    let Some(host) = parsed.host_str() else {
        return Err("地址必须包含主机名".to_string());
    };
    if audit_service::is_blocked_host(host) {
        return Err(format!("地址指向内网主机（{host}），不允许使用"));
    }
    Ok(())
}

/// 校验主机名不是内网地址。允许写 `wss://host` 或裸 `host[:port]`。
fn check_public_host(host: &str) -> Result<(), String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("主机名不能为空".to_string());
    }
    if trimmed.contains("://") {
        return check_public_url(trimmed);
    }
    // 裸主机名可能带端口。
    let bare = trimmed.split('/').next().unwrap_or(trimmed);
    let host_part = bare.rsplit_once(':').map(|(left, _)| left).unwrap_or(bare);
    if audit_service::is_blocked_host(host_part) {
        return Err(format!("主机指向内网地址（{host_part}），不允许使用"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

/// 组装触发源视图。
fn trigger_view(row: &TriggerSourceRow) -> TriggerSourceView {
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

/// 取配置里的字符串。
fn config_str(config: &Value, key: &str) -> String {
    config
        .get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

/// 取配置里的整数（数字或数字字符串都认）。
fn config_i64(config: &Value, key: &str) -> Option<i64> {
    let value = config.get(key)?;
    value.as_i64().or_else(|| {
        value
            .as_str()
            .and_then(|text| text.trim().parse::<i64>().ok())
    })
}

/// 取配置里的布尔值。
fn config_bool(config: &Value, key: &str) -> Option<bool> {
    let value = config.get(key)?;
    value.as_bool().or_else(|| {
        value
            .as_str()
            .and_then(|text| match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
    })
}

/// 取配置里的字符串数组。
fn config_strings(config: &Value, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|text| text.trim().to_string()))
                .filter(|text| !text.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// 校验数值范围。
fn check_range(
    errors: &mut Vec<FieldError>,
    field: &str,
    value: i64,
    min: i64,
    max: i64,
    label: &str,
) {
    if value < min || value > max {
        errors.push(FieldError::new(
            field,
            format!("{label}范围是 {min}~{max}，当前为 {value}"),
        ));
    }
}

/// 取审核所属项目 ID。审核不存在时返回 404。
async fn find_audit_project(state: &AppState, audit_id: u64) -> Result<u64, ApiError> {
    repositories::find_audit_project(state, audit_id)
        .await?
        .ok_or_else(|| ApiError::not_found("审核定义不存在"))
}

/// 确认项目存在且可写。
async fn ensure_project_writable(state: &AppState, project_id: u64) -> Result<(), ApiError> {
    match repositories::find_project_status(state, project_id).await? {
        Some(status) if status == "ACTIVE" => Ok(()),
        Some(status) if status == "PAUSED" => Err(ApiError::forbidden(
            "PROJECT_PAUSED",
            "项目已暂停，不能修改配置",
        )),
        Some(status) if status == "DELETED" => Err(ApiError::forbidden(
            "PROJECT_DELETED",
            "项目已删除，不能修改配置",
        )),
        Some(_) => Err(ApiError::forbidden("PROJECT_PAUSED", "项目当前不可写")),
        None => Err(ApiError::not_found("项目不存在")),
    }
}

/// 构造审计日志条目。
fn log_entry(
    auth: &AuthContext,
    project_id: u64,
    action: &str,
    object_id: u64,
    detail: Value,
) -> AuditLogEntry {
    AuditLogEntry {
        project_id: Some(project_id),
        operator: auth.username.clone(),
        operator_id: Some(auth.user_id),
        operator_ip: None,
        action: action.to_string(),
        object_type: Some(OBJECT_TRIGGER.to_string()),
        object_id: Some(object_id.to_string()),
        result: "SUCCESS".to_string(),
        detail: Some(detail),
        trace_id: Some(auth.trace_id.clone()),
    }
}
