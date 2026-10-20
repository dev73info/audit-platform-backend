//! 项目连接配置域的业务编排层：保存前校验、加密落库、版本历史、连接测试与审计写入。
//!
//! 分层约定见 `doc/开发约定.md`：handler 只做参数解析与权限判定，
//! 业务校验、状态流转与事务都在这一层，SQL 在 `repositories.rs`。

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::db::AppState;
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::ops::AuditLogEntry;
use crate::models::project::{
    ConnectionTestResult, ProjectConfigRow, ProjectConfigView, SaveConfigRequest, TestConfigRequest,
};
use crate::response::Page;

use super::repositories as repo;

/// 支持的连接配置类型。
const CONFIG_TYPES: &[&str] = &["REDIS", "MYSQL", "API", "OSS", "MQ"];

/// 回滚入参。
#[derive(Debug, Clone, Deserialize)]
pub struct RollbackRequest {
    /// 要回滚到的历史版本号。
    pub version: i32,
}

/// 明文查看入参：需要二次确认当前登录用户的口令。
#[derive(Debug, Clone, Deserialize)]
pub struct RevealRequest {
    /// 当前登录用户的口令。
    pub password: String,
}

/// 版本历史项。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigVersionItem {
    pub version: i32,
    /// 操作人用户名。
    pub operator: String,
    pub operator_id: u64,
    pub change_note: Option<String>,
    pub created_at: String,
}

/// 连接配置列表。
pub async fn list_configs(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
) -> Result<Page<ProjectConfigView>, ApiError> {
    ctx.require_project(project_id)?;
    let rows = repo::list_configs(state, project_id).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(to_view(state, &row)?);
    }
    let total = items.len() as u64;
    Ok(Page::new(items, total, 1, total.max(1)))
}

/// 连接配置详情。
pub async fn get_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
) -> Result<ProjectConfigView, ApiError> {
    ctx.require_project(project_id)?;
    let row = find_config(state, project_id, config_id).await?;
    to_view(state, &row)
}

/// 新建连接配置。
pub async fn create_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: SaveConfigRequest,
) -> Result<ProjectConfigView, ApiError> {
    ctx.require_project(project_id)?;

    let config_type = validate_type(&req.config_type)?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::invalid_param(
            "配置名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }

    if repo::find_config_by_name(state, project_id, &config_type, &name)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("同类型下的配置名称 {name} 已存在"),
        ));
    }

    let key = state.settings.master_key();
    let encrypted = crate::security::encrypt::encrypt_json(&key, project_id, &req.config)?;
    let pool_json = req.pool.clone();
    let tags_json = req.tags.as_ref().map(|tags| json!(tags));
    let config_id = crate::common::ids::next_id();

    let mut tx = state.db.begin().await?;
    repo::insert_config(
        &mut tx,
        config_id,
        project_id,
        &config_type,
        &name,
        &encrypted,
        pool_json.as_ref(),
        tags_json.as_ref(),
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_CREATE",
        "PROJECT_CONFIG",
        config_id,
        json!({ "type": config_type, "name": name }),
    )
    .await?;

    let row = find_config(state, project_id, config_id).await?;
    to_view(state, &row)
}

/// 更新连接配置（旧版本进历史，版本号 +1）。
pub async fn update_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
    req: SaveConfigRequest,
) -> Result<ProjectConfigView, ApiError> {
    ctx.require_project(project_id)?;
    let row = find_config(state, project_id, config_id).await?;

    let config_type = validate_type(&req.config_type)?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::invalid_param(
            "配置名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }
    if let Some(other) = repo::find_config_by_name(state, project_id, &config_type, &name).await?
        && other.id != config_id
    {
        return Err(ApiError::conflict(
            "CODE_CONFLICT",
            format!("同类型下的配置名称 {name} 已存在"),
        ));
    }

    let key = state.settings.master_key();
    let encrypted = crate::security::encrypt::encrypt_json(&key, project_id, &req.config)?;
    let pool_json = req.pool.clone();
    let tags_json = req.tags.as_ref().map(|tags| json!(tags));
    let new_version = row.version + 1;

    let mut tx = state.db.begin().await?;
    repo::insert_history(
        &mut tx,
        crate::common::ids::next_id(),
        project_id,
        config_id,
        row.version,
        &row.config_encrypted,
        row.pool_json.as_ref(),
        ctx.user_id,
        req.change_note.as_deref(),
    )
    .await?;
    repo::update_config(
        &mut tx,
        config_id,
        &config_type,
        &name,
        &encrypted,
        pool_json.as_ref(),
        tags_json.as_ref(),
        new_version,
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_UPDATE",
        "PROJECT_CONFIG",
        config_id,
        json!({ "type": config_type, "name": name, "version": new_version }),
    )
    .await?;

    let row = find_config(state, project_id, config_id).await?;
    to_view(state, &row)
}

/// 删除连接配置（软删）。
pub async fn delete_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
) -> Result<Value, ApiError> {
    ctx.require_project(project_id)?;
    let row = find_config(state, project_id, config_id).await?;

    let mut tx = state.db.begin().await?;
    repo::soft_delete_config(&mut tx, config_id).await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_DELETE",
        "PROJECT_CONFIG",
        config_id,
        json!({ "type": row.r#type, "name": row.name }),
    )
    .await?;

    Ok(json!({ "id": config_id, "deleted": true }))
}

/// 连接测试（只测试，不落库；已存在的配置会回写测试结果）。
pub async fn test_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: TestConfigRequest,
) -> Result<ConnectionTestResult, ApiError> {
    ctx.require_project(project_id)?;
    let config_type = validate_type(&req.config_type)?;

    let result = match config_type.as_str() {
        "REDIS" => test_redis(&req.config).await?,
        "MYSQL" => test_mysql(state, &req.config, req.pool.as_ref()).await?,
        "API" => test_api(&req.config).await?,
        _ => {
            return Err(ApiError::invalid_param(
                format!("暂不支持 {config_type} 类型的连接测试"),
                vec![FieldError::new("type", "当前只支持 REDIS / MYSQL / API")],
            ));
        }
    };

    // 已存在的同名同内容配置回写测试结果。
    write_back_test_result(state, project_id, &config_type, &req.config, &result).await?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_TEST",
        "PROJECT_CONFIG",
        0,
        json!({ "type": config_type, "ok": result.ok, "latency_ms": result.latency_ms }),
    )
    .await?;

    if !result.ok {
        return Err(ApiError::unprocessable_with(
            "CONNECTION_TEST_FAILED",
            result
                .error
                .clone()
                .unwrap_or_else(|| "连接测试失败".to_string()),
            serde_json::to_value(&result)?,
        ));
    }

    Ok(result)
}

/// 回滚到历史版本（版本号继续 +1，并写一条新的历史）。
pub async fn rollback_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
    version: i32,
) -> Result<ProjectConfigView, ApiError> {
    ctx.require_project(project_id)?;
    let row = find_config(state, project_id, config_id).await?;

    let history = repo::find_history(state, config_id, version)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("版本 {version} 不存在")))?;

    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, project_id, &history.config_encrypted)?;
    let encrypted = crate::security::encrypt::encrypt_json(&key, project_id, &plain)?;
    let new_version = row.version + 1;

    let mut tx = state.db.begin().await?;
    repo::insert_history(
        &mut tx,
        crate::common::ids::next_id(),
        project_id,
        config_id,
        row.version,
        &row.config_encrypted,
        row.pool_json.as_ref(),
        ctx.user_id,
        Some(&format!("回滚到版本 {version}")),
    )
    .await?;
    repo::update_config(
        &mut tx,
        config_id,
        &row.r#type,
        &row.name,
        &encrypted,
        history.pool_json.as_ref(),
        row.tags.as_ref(),
        new_version,
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_ROLLBACK",
        "PROJECT_CONFIG",
        config_id,
        json!({ "from_version": row.version, "to_version": new_version, "rollback_to": version }),
    )
    .await?;

    let row = find_config(state, project_id, config_id).await?;
    to_view(state, &row)
}

/// 版本历史列表。
pub async fn list_versions(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
) -> Result<Vec<ConfigVersionItem>, ApiError> {
    ctx.require_project(project_id)?;
    let _ = find_config(state, project_id, config_id).await?;
    let rows = repo::list_history(state, config_id).await?;

    let mut operator_ids: Vec<u64> = rows.iter().map(|row| row.operator_id).collect();
    operator_ids.sort_unstable();
    operator_ids.dedup();
    let names = repo::load_user_names(state, &operator_ids).await?;

    Ok(rows
        .into_iter()
        .map(|row| ConfigVersionItem {
            version: row.version,
            operator: names
                .get(&row.operator_id)
                .cloned()
                .unwrap_or_else(|| row.operator_id.to_string()),
            operator_id: row.operator_id,
            change_note: row.change_note,
            created_at: repo::format_created_at(row.created_at),
        })
        .collect())
}

/// 查看明文配置（二次确认口令）。
pub async fn reveal_config(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    config_id: u64,
    password: String,
) -> Result<Value, ApiError> {
    ctx.require_project(project_id)?;
    let row = find_config(state, project_id, config_id).await?;

    // 二次确认：校验当前登录用户的口令。
    let user = crate::modules::auth::repositories::find_user_by_id(state, ctx.user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("UNAUTHORIZED", "账号不存在"))?;
    if !crate::security::password::verify_password(&password, &user.password_hash) {
        return Err(ApiError::unauthorized("UNAUTHORIZED", "口令校验失败"));
    }

    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, project_id, &row.config_encrypted)?;

    write_audit(
        state,
        ctx,
        project_id,
        "CONFIG_REVEAL",
        "PROJECT_CONFIG",
        config_id,
        json!({ "type": row.r#type, "name": row.name }),
    )
    .await?;

    Ok(plain)
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 取连接配置，不存在返回 404。
async fn find_config(
    state: &AppState,
    project_id: u64,
    config_id: u64,
) -> Result<ProjectConfigRow, ApiError> {
    repo::find_config(state, project_id, config_id)
        .await?
        .ok_or_else(|| ApiError::not_found("连接配置不存在"))
}

/// 校验配置类型。
fn validate_type(config_type: &str) -> Result<String, ApiError> {
    let normalized = config_type.trim().to_ascii_uppercase();
    if !CONFIG_TYPES.contains(&normalized.as_str()) {
        return Err(ApiError::invalid_param(
            "连接配置类型不合法",
            vec![FieldError::new(
                "type",
                "只允许 REDIS / MYSQL / API / OSS / MQ",
            )],
        ));
    }
    Ok(normalized)
}

/// 行转对外结构（密钥脱敏）。
fn to_view(state: &AppState, row: &ProjectConfigRow) -> Result<ProjectConfigView, ApiError> {
    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, row.project_id, &row.config_encrypted)?;

    Ok(ProjectConfigView {
        id: row.id,
        project_id: row.project_id,
        config_type: row.r#type.clone(),
        name: row.name.clone(),
        version: row.version,
        config: mask_config(&plain),
        pool: row.pool_json.clone().unwrap_or_else(|| json!({})),
        tags: parse_tags(row.tags.as_ref()),
        test_status: row
            .test_status
            .clone()
            .unwrap_or_else(|| "UNTESTED".to_string()),
        test_message: row.test_message.clone(),
        tested_at: row.tested_at.map(crate::common::format_datetime),
        created_at: crate::common::format_datetime(row.created_at),
        updated_at: crate::common::format_datetime(row.updated_at),
    })
}

/// 解析标签数组。
fn parse_tags(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|item| serde_json::from_value::<Vec<String>>(item.clone()).ok())
        .unwrap_or_default()
}

/// 敏感字段判定。
fn is_sensitive(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("passwd")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("access_key")
        || key.contains("private_key")
        || key.contains("credential")
        || key == "pwd"
}

/// 脱敏配置里的敏感字段。
fn mask_config(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, item) in map {
                if is_sensitive(key) {
                    let masked = match item {
                        Value::String(text) => crate::security::encrypt::mask_secret(text),
                        _ => "****".to_string(),
                    };
                    result.insert(key.clone(), Value::String(masked));
                } else {
                    result.insert(key.clone(), mask_config(item));
                }
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(items.iter().map(mask_config).collect()),
        other => other.clone(),
    }
}

/// 取配置项里的字符串。
fn str_field(config: &Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 取配置项里的整数。
fn int_field(config: &Value, key: &str) -> Option<i64> {
    config.get(key).and_then(|value| value.as_i64()).or_else(|| {
        config
            .get(key)
            .and_then(|value| value.as_str())
            .and_then(|value| value.trim().parse::<i64>().ok())
    })
}

/// 回写连接测试结果：只回写到已存在且内容一致的配置。
async fn write_back_test_result(
    state: &AppState,
    project_id: u64,
    config_type: &str,
    config: &Value,
    result: &ConnectionTestResult,
) -> Result<(), ApiError> {
    let rows = repo::list_configs(state, project_id).await?;
    let key = state.settings.master_key();

    for row in rows {
        if row.r#type != config_type {
            continue;
        }
        let plain = match crate::security::encrypt::decrypt_json(&key, project_id, &row.config_encrypted)
        {
            Ok(value) => value,
            Err(_) => continue,
        };
        if &plain != config {
            continue;
        }

        let status = if result.ok { "OK" } else { "FAILED" };
        let message = result.error.clone().or_else(|| {
            result
                .server_info
                .clone()
                .map(|info| format!("连接正常：{info}"))
        });
        let mut tx = state.db.begin().await?;
        repo::update_test_result(&mut tx, row.id, status, message.as_deref()).await?;
        tx.commit().await?;
        break;
    }

    Ok(())
}

/// 测试 Redis 连接。
async fn test_redis(config: &Value) -> Result<ConnectionTestResult, ApiError> {
    let host = str_field(config, "host")
        .ok_or_else(|| ApiError::invalid_param("缺少 host", vec![FieldError::new("host", "必填")]))?;
    let port = int_field(config, "port").unwrap_or(6379);
    let db_index = int_field(config, "db_index").unwrap_or(0);
    let password = str_field(config, "password");

    let url = match password {
        Some(value) => format!(
            "redis://:{}@{}:{}/{}",
            urlencoding::encode(&value),
            host,
            port,
            db_index
        ),
        None => format!("redis://{host}:{port}/{db_index}"),
    };

    let client = redis::Client::open(url.as_str())
        .map_err(|err| ApiError::bad_request(format!("Redis 连接串不合法：{err}")))?;

    let start = Instant::now();
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(conn) => conn,
        Err(err) => {
            return Ok(ConnectionTestResult {
                config_type: "REDIS".to_string(),
                ok: false,
                latency_ms: 0,
                server_info: None,
                max_connections: None,
                current_used: None,
                global_limit: None,
                remain_for_project: None,
                warnings: Vec::new(),
                error: Some(format!("Redis 连接失败：{err}")),
            });
        }
    };

    let pong: String = match redis::cmd("PING").query_async(&mut conn).await {
        Ok(value) => value,
        Err(err) => {
            return Ok(ConnectionTestResult {
                config_type: "REDIS".to_string(),
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                server_info: None,
                max_connections: None,
                current_used: None,
                global_limit: None,
                remain_for_project: None,
                warnings: Vec::new(),
                error: Some(format!("Redis PING 失败：{err}")),
            });
        }
    };
    let latency_ms = start.elapsed().as_millis() as u64;

    let info: String = redis::cmd("INFO")
        .arg("server")
        .query_async(&mut conn)
        .await
        .unwrap_or_default();
    let version = parse_redis_version(&info);

    Ok(ConnectionTestResult {
        config_type: "REDIS".to_string(),
        ok: pong.eq_ignore_ascii_case("PONG"),
        latency_ms,
        server_info: version,
        max_connections: None,
        current_used: None,
        global_limit: None,
        remain_for_project: None,
        warnings: Vec::new(),
        error: None,
    })
}

/// 从 `INFO server` 里取版本号。
fn parse_redis_version(info: &str) -> Option<String> {
    info.lines()
        .find_map(|line| line.trim().strip_prefix("redis_version:"))
        .map(|value| value.trim().to_string())
}

/// 测试 MySQL 连接。
async fn test_mysql(
    state: &AppState,
    config: &Value,
    pool: Option<&Value>,
) -> Result<ConnectionTestResult, ApiError> {
    let host = str_field(config, "host")
        .ok_or_else(|| ApiError::invalid_param("缺少 host", vec![FieldError::new("host", "必填")]))?;
    let port = int_field(config, "port").unwrap_or(3306);
    let database = str_field(config, "database").unwrap_or_default();
    let username = str_field(config, "username").unwrap_or_default();
    let password = str_field(config, "password").unwrap_or_default();

    let url = format!(
        "mysql://{}:{}@{}:{}/{}",
        urlencoding::encode(&username),
        urlencoding::encode(&password),
        host,
        port,
        database
    );

    let options = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(10));

    let start = Instant::now();
    let conn = match options.connect(&url).await {
        Ok(conn) => conn,
        Err(err) => {
            return Ok(ConnectionTestResult {
                config_type: "MYSQL".to_string(),
                ok: false,
                latency_ms: 0,
                server_info: None,
                max_connections: None,
                current_used: None,
                global_limit: None,
                remain_for_project: None,
                warnings: Vec::new(),
                error: Some(format!("MySQL 连接失败：{err}")),
            });
        }
    };

    if let Err(err) = sqlx::query("SELECT 1").execute(&conn).await {
        return Ok(ConnectionTestResult {
            config_type: "MYSQL".to_string(),
            ok: false,
            latency_ms: start.elapsed().as_millis() as u64,
            server_info: None,
            max_connections: None,
            current_used: None,
            global_limit: None,
            remain_for_project: None,
            warnings: Vec::new(),
            error: Some(format!("MySQL 查询失败：{err}")),
        });
    }
    let latency_ms = start.elapsed().as_millis() as u64;

    use sqlx::Row;
    let variables = sqlx::query(
        "SELECT @@max_connections AS max_connections, @@wait_timeout AS wait_timeout",
    )
    .fetch_one(&conn)
    .await;
    let (server_max_connections, wait_timeout) = match variables {
        Ok(row) => (
            row.try_get::<i64, _>("max_connections").unwrap_or(0),
            row.try_get::<i64, _>("wait_timeout").unwrap_or(0),
        ),
        Err(_) => (0, 0),
    };

    let current_used = sqlx::query("SHOW STATUS LIKE 'Threads_connected'")
        .fetch_one(&conn)
        .await
        .ok()
        .and_then(|row| row.try_get::<String, _>("Value").ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0);

    let settings = state.settings.as_ref();
    let global_limit = ((settings.database.max_connections as f64)
        * settings.audit.global_pool_ratio)
        .floor() as i64;
    let remain_for_project = (global_limit - current_used).max(0);

    let mut warnings = Vec::new();
    if let Some(max_lifetime_ms) = pool.and_then(|value| int_field(value, "max_lifetime_ms"))
        && wait_timeout > 0
        && max_lifetime_ms >= wait_timeout * 1000
    {
        warnings.push(format!(
            "maxLifetime({max_lifetime_ms}ms) 接近或超过 wait_timeout({}ms)，建议下调",
            wait_timeout * 1000
        ));
    }

    Ok(ConnectionTestResult {
        config_type: "MYSQL".to_string(),
        ok: true,
        latency_ms,
        server_info: Some(server_max_connections.to_string()),
        max_connections: Some(server_max_connections),
        current_used: Some(current_used),
        global_limit: Some(global_limit),
        remain_for_project: Some(remain_for_project),
        warnings,
        error: None,
    })
}

/// 测试 HTTP API 连接。
async fn test_api(config: &Value) -> Result<ConnectionTestResult, ApiError> {
    let base_url = str_field(config, "base_url").ok_or_else(|| {
        ApiError::invalid_param("缺少 base_url", vec![FieldError::new("base_url", "必填")])
    })?;

    let url = reqwest::Url::parse(&base_url).map_err(|_| {
        ApiError::invalid_param(
            "base_url 不是合法 URL",
            vec![FieldError::new("base_url", "必须是带 scheme 的完整 URL")],
        )
    })?;

    let host = url.host_str().unwrap_or_default().to_string();
    // 目标地址不得指向内网 / 回环。
    if crate::modules::audit::service::is_blocked_host(&host)
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
    {
        return Err(ApiError::invalid_param(
            "目标地址不允许指向内网",
            vec![FieldError::new("base_url", "禁止访问内网 / 回环地址")],
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| ApiError::internal(format!("HTTP 客户端初始化失败：{err}")))?;

    let start = Instant::now();
    let response = match client.head(url.clone()).send().await {
        Ok(response) => response,
        Err(err) => {
            return Ok(ConnectionTestResult {
                config_type: "API".to_string(),
                ok: false,
                latency_ms: 0,
                server_info: None,
                max_connections: None,
                current_used: None,
                global_limit: None,
                remain_for_project: None,
                warnings: Vec::new(),
                error: Some(format!("请求失败：{err}")),
            });
        }
    };
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = response.status();

    let mut warnings = Vec::new();
    if status.as_u16() >= 400 {
        warnings.push(format!("目标返回 HTTP {}，请确认地址是否正确", status.as_u16()));
    }

    Ok(ConnectionTestResult {
        config_type: "API".to_string(),
        ok: true,
        latency_ms,
        server_info: Some(format!("HTTP {}", status.as_u16())),
        max_connections: None,
        current_used: None,
        global_limit: None,
        remain_for_project: None,
        warnings,
        error: None,
    })
}

/// 写审计日志。
async fn write_audit(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    action: &str,
    object_type: &str,
    object_id: u64,
    detail: Value,
) -> Result<(), ApiError> {
    let entry = AuditLogEntry {
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
    };
    crate::modules::auth::repositories::write_audit_log(state, entry).await
}
