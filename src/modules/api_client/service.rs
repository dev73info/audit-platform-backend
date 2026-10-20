//! 开放 API 客户端域的业务编排层：凭据生成、密钥轮换与审计写入。
//!
//! 明文密钥只在创建与轮换时返回一次，列表里只给脱敏值。

use serde::Serialize;
use serde_json::{Value, json};

use crate::db::AppState;
use crate::error::{ApiError, FieldError};
use crate::middleware::AuthContext;
use crate::models::ops::AuditLogEntry;
use crate::models::project::{
    ApiClientRow, ApiClientView, CreateApiClientRequest, UpdateApiClientRequest,
};
use crate::response::Page;

use super::repositories as repo;

/// 合法的客户端状态。
const CLIENT_STATUS: &[&str] = &["ACTIVE", "DISABLED"];

/// AppKey 前缀。
const APP_KEY_PREFIX: &str = "ak_";

/// 创建 / 轮换结果：附带只返回一次的明文密钥。
#[derive(Debug, Clone, Serialize)]
pub struct ApiClientCreated {
    #[serde(flatten)]
    pub client: ApiClientView,
    /// 明文密钥，仅创建与轮换时返回一次。
    pub secret: String,
}

/// 客户端列表。
pub async fn list_clients(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
) -> Result<Page<ApiClientView>, ApiError> {
    ctx.require_project(project_id)?;
    let rows = repo::list_clients(state, project_id).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(to_view(state, &row)?);
    }
    let total = items.len() as u64;
    Ok(Page::new(items, total, 1, total.max(1)))
}

/// 新建客户端。
pub async fn create_client(
    state: &AppState,
    ctx: &AuthContext,
    project_id: u64,
    req: CreateApiClientRequest,
) -> Result<ApiClientCreated, ApiError> {
    ctx.require_project(project_id)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::invalid_param(
            "客户端名称不能为空",
            vec![FieldError::new("name", "不能为空")],
        ));
    }

    let app_key = format!(
        "{APP_KEY_PREFIX}{}",
        crate::security::signature::random_app_key()
    );
    let secret = match req.secret.as_ref().map(|value| value.trim().to_string()) {
        Some(value) if !value.is_empty() => value,
        _ => crate::security::signature::random_secret(),
    };

    let key = state.settings.master_key();
    let encrypted = crate::security::encrypt::encrypt_bytes(&key, secret.as_bytes())?;
    let rate_limit = req.rate_limit.clone();
    let allow_ips = req.allow_ips.as_ref().map(|items| json!(items));
    let client_id = crate::common::ids::next_id();

    let mut tx = state.db.begin().await?;
    repo::insert_client(
        &mut tx,
        client_id,
        project_id,
        &app_key,
        &encrypted,
        &name,
        rate_limit.as_ref(),
        allow_ips.as_ref(),
        req.callback_url.as_deref(),
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        project_id,
        "API_CLIENT_CREATE",
        "API_CLIENT",
        client_id,
        json!({ "name": name, "app_key": app_key }),
    )
    .await?;

    let row = find_client(state, client_id).await?;
    Ok(ApiClientCreated {
        client: to_view(state, &row)?,
        secret,
    })
}

/// 更新客户端。
pub async fn update_client(
    state: &AppState,
    ctx: &AuthContext,
    client_id: u64,
    req: UpdateApiClientRequest,
) -> Result<ApiClientView, ApiError> {
    let row = find_client(state, client_id).await?;
    ctx.require_project(row.project_id)?;

    let name = match req.name.as_ref() {
        Some(value) => {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::invalid_param(
                    "客户端名称不能为空",
                    vec![FieldError::new("name", "不能为空")],
                ));
            }
            trimmed
        }
        None => row.name.clone(),
    };

    let status = match req.status.as_ref() {
        Some(value) => {
            let normalized = value.trim().to_ascii_uppercase();
            if !CLIENT_STATUS.contains(&normalized.as_str()) {
                return Err(ApiError::invalid_param(
                    "客户端状态取值不合法",
                    vec![FieldError::new("status", "只允许 ACTIVE / DISABLED")],
                ));
            }
            normalized
        }
        None => row.status.clone(),
    };

    let rate_limit = req.rate_limit.clone().or(row.rate_limit_json.clone());
    let allow_ips = match req.allow_ips.as_ref() {
        Some(items) => Some(json!(items)),
        None => row.allow_ips.clone(),
    };
    let callback_url = req.callback_url.clone().or(row.callback_url.clone());

    let mut tx = state.db.begin().await?;
    repo::update_client(
        &mut tx,
        client_id,
        &name,
        &status,
        rate_limit.as_ref(),
        allow_ips.as_ref(),
        callback_url.as_deref(),
    )
    .await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        row.project_id,
        "API_CLIENT_UPDATE",
        "API_CLIENT",
        client_id,
        json!({ "name": name, "status": status }),
    )
    .await?;

    let row = find_client(state, client_id).await?;
    to_view(state, &row)
}

/// 轮换密钥：生成新密钥并返回一次明文。
pub async fn rotate_secret(
    state: &AppState,
    ctx: &AuthContext,
    client_id: u64,
) -> Result<ApiClientCreated, ApiError> {
    let row = find_client(state, client_id).await?;
    ctx.require_project(row.project_id)?;

    let secret = crate::security::signature::random_secret();
    let key = state.settings.master_key();
    let encrypted = crate::security::encrypt::encrypt_bytes(&key, secret.as_bytes())?;

    let mut tx = state.db.begin().await?;
    repo::update_secret(&mut tx, client_id, &encrypted).await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        row.project_id,
        "API_CLIENT_UPDATE",
        "API_CLIENT",
        client_id,
        json!({ "action": "rotate_secret", "app_key": row.app_key }),
    )
    .await?;

    let row = find_client(state, client_id).await?;
    Ok(ApiClientCreated {
        client: to_view(state, &row)?,
        secret,
    })
}

/// 删除客户端。
pub async fn delete_client(
    state: &AppState,
    ctx: &AuthContext,
    client_id: u64,
) -> Result<Value, ApiError> {
    let row = find_client(state, client_id).await?;
    ctx.require_project(row.project_id)?;

    let mut tx = state.db.begin().await?;
    repo::delete_client(&mut tx, client_id).await?;
    tx.commit().await?;

    write_audit(
        state,
        ctx,
        row.project_id,
        "API_CLIENT_DELETE",
        "API_CLIENT",
        client_id,
        json!({ "name": row.name, "app_key": row.app_key }),
    )
    .await?;

    Ok(json!({ "id": client_id, "deleted": true }))
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 取客户端，不存在返回 404。
async fn find_client(state: &AppState, client_id: u64) -> Result<ApiClientRow, ApiError> {
    repo::find_client(state, client_id)
        .await?
        .ok_or_else(|| ApiError::not_found("开放 API 客户端不存在"))
}

/// 行转对外结构（密钥脱敏）。
fn to_view(state: &AppState, row: &ApiClientRow) -> Result<ApiClientView, ApiError> {
    let key = state.settings.master_key();
    // 解密失败（密钥已变更）时只给固定掩码，不泄露细节。
    let secret_masked = match crate::security::encrypt::decrypt_bytes(&key, &row.secret_encrypted) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => crate::security::encrypt::mask_secret(&text),
            Err(_) => "****".to_string(),
        },
        Err(_) => "****".to_string(),
    };

    Ok(ApiClientView {
        id: row.id,
        project_id: row.project_id,
        app_key: row.app_key.clone(),
        name: row.name.clone(),
        status: row.status.clone(),
        secret_masked,
        rate_limit: row.rate_limit_json.clone().unwrap_or_else(|| json!({})),
        allow_ips: row
            .allow_ips
            .as_ref()
            .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
            .unwrap_or_default(),
        callback_url: row.callback_url.clone(),
        last_used_at: row.last_used_at.map(crate::common::format_datetime),
        created_at: crate::common::format_datetime(row.created_at),
        updated_at: crate::common::format_datetime(row.updated_at),
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
