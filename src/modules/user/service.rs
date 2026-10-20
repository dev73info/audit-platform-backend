//! 用户业务编排：账号增删改查、项目授权调整、口令重置。

use serde::Serialize;

use crate::db::AppState;
use crate::error::{ApiError, FieldError};
use crate::models::ops::AuditLogEntry;
use crate::modules::auth::repositories::write_audit_log;
use crate::modules::user::repositories::{self, AdminUserRow, UserFilters};
use crate::security::password;

/// 账号对外结构。
#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub id: u64,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role: String,
    pub status: String,
    pub fail_count: i32,
    pub locked_until: Option<String>,
    pub last_login_at: Option<String>,
    pub last_login_ip: Option<String>,
    pub projects: Vec<u64>,
    pub created_at: String,
}

/// 新建账号入参。
#[derive(Debug, Clone)]
pub struct CreateUserInput {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role_code: String,
    pub project_ids: Vec<u64>,
}

/// 修改账号入参。
#[derive(Debug, Clone, Default)]
pub struct UpdateUserInput {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role_code: Option<String>,
    pub status: Option<String>,
}

/// 账号列表。
pub async fn list_users(
    state: &AppState,
    filters: UserFilters,
    page: u64,
    page_size: u64,
) -> Result<(Vec<UserView>, u64), ApiError> {
    let total = repositories::count_users(state, &filters).await?;
    let rows = repositories::list_users(state, &filters, page_size, (page - 1) * page_size).await?;

    let user_ids: Vec<u64> = rows.iter().map(|row| row.id).collect();
    let scope_rows = repositories::list_scope_rows(state, &user_ids).await?;

    let items = rows
        .into_iter()
        .map(|row| {
            let projects: Vec<u64> = scope_rows
                .iter()
                .filter(|scope| scope.user_id == row.id)
                .map(|scope| scope.project_id)
                .collect();
            to_view(row, projects)
        })
        .collect();

    Ok((items, total))
}

/// 账号详情。
pub async fn get_user(state: &AppState, user_id: u64) -> Result<UserView, ApiError> {
    let row = find_user_or_404(state, user_id).await?;
    let projects = repositories::list_user_project_ids(state, user_id).await?;
    Ok(to_view(row, projects))
}

/// 新建账号。
pub async fn create_user(
    state: &AppState,
    input: CreateUserInput,
    operator: &str,
    operator_id: Option<u64>,
) -> Result<UserView, ApiError> {
    let username = input.username.trim().to_string();
    if username.is_empty() {
        return Err(ApiError::invalid_param(
            "新建账号参数不合法",
            vec![FieldError::new("username", "用户名不能为空")],
        ));
    }
    if username.chars().count() > 64 {
        return Err(ApiError::invalid_param(
            "新建账号参数不合法",
            vec![FieldError::new("username", "用户名长度不能超过 64")],
        ));
    }

    // 口令强度。
    if let Err(reason) = password::check_password_strength(&input.password) {
        return Err(ApiError::invalid_param(
            "口令强度不足",
            vec![FieldError::new("password", reason)],
        ));
    }

    // 角色编码必须是内置角色之一。
    let role_code = input.role_code.trim().to_string();
    if crate::common::RoleCode::parse(&role_code).is_none() {
        return Err(ApiError::invalid_param(
            "角色编码不合法",
            vec![FieldError::new(
                "role_code",
                "角色必须是 SUPER_ADMIN / PROJECT_ADMIN / AUDIT_CONFIGURER / REVIEWER / READONLY 之一",
            )],
        ));
    }

    // 用户名唯一。
    if repositories::find_user_by_username(state, &username)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict("CODE_CONFLICT", "用户名已存在"));
    }

    // 校验项目授权。
    let project_ids = validate_project_ids(state, &input.project_ids).await?;

    let hash = password::hash_password(&input.password)?;
    repositories::insert_user(
        state,
        &username,
        &hash,
        input.display_name.as_deref(),
        input.email.as_deref(),
        &role_code,
    )
    .await?;

    let created = repositories::find_user_by_username(state, &username)
        .await?
        .ok_or_else(|| ApiError::internal("创建账号失败"))?;

    if !project_ids.is_empty() {
        repositories::replace_user_projects(state, created.id, &project_ids).await?;
    }

    write_audit(
        state,
        operator,
        operator_id,
        "USER_CREATE",
        created.id,
        Some(serde_json::json!({
            "username": created.username,
            "role": created.role_code,
            "projects": project_ids,
        })),
    )
    .await;

    Ok(to_view(created, project_ids))
}

/// 修改账号。
pub async fn update_user(
    state: &AppState,
    user_id: u64,
    input: UpdateUserInput,
    operator: &str,
    operator_id: Option<u64>,
) -> Result<UserView, ApiError> {
    find_user_or_404(state, user_id).await?;

    let role_code = match input.role_code.as_ref() {
        Some(raw) if !raw.trim().is_empty() => {
            let code = raw.trim().to_string();
            if crate::common::RoleCode::parse(&code).is_none() {
                return Err(ApiError::invalid_param(
                    "角色编码不合法",
                    vec![FieldError::new(
                        "role_code",
                        "角色必须是 SUPER_ADMIN / PROJECT_ADMIN / AUDIT_CONFIGURER / REVIEWER / READONLY 之一",
                    )],
                ));
            }
            Some(code)
        }
        _ => None,
    };

    let status = match input.status.as_ref() {
        Some(raw) if !raw.trim().is_empty() => {
            let code = raw.trim().to_uppercase();
            if !["ACTIVE", "LOCKED", "DISABLED"].contains(&code.as_str()) {
                return Err(ApiError::invalid_param(
                    "账号状态不合法",
                    vec![FieldError::new(
                        "status",
                        "状态必须是 ACTIVE / LOCKED / DISABLED 之一",
                    )],
                ));
            }
            Some(code)
        }
        _ => None,
    };

    repositories::update_user(
        state,
        user_id,
        input.display_name.as_deref(),
        input.email.as_deref(),
        role_code.as_deref(),
        status.as_deref(),
    )
    .await?;

    let row = find_user_or_404(state, user_id).await?;
    let projects = repositories::list_user_project_ids(state, user_id).await?;

    write_audit(
        state,
        operator,
        operator_id,
        "USER_UPDATE",
        user_id,
        Some(serde_json::json!({
            "display_name": input.display_name,
            "email": input.email,
            "role_code": role_code,
            "status": status,
        })),
    )
    .await;

    Ok(to_view(row, projects))
}

/// 重置口令。`password` 为空时自动生成一个随机强口令并回传。
pub async fn reset_password(
    state: &AppState,
    user_id: u64,
    plain: Option<&str>,
    operator: &str,
    operator_id: Option<u64>,
) -> Result<serde_json::Value, ApiError> {
    let row = find_user_or_404(state, user_id).await?;

    let password_plain = match plain.map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => {
            if let Err(reason) = password::check_password_strength(value) {
                return Err(ApiError::invalid_param(
                    "口令强度不足",
                    vec![FieldError::new("password", reason)],
                ));
            }
            value.to_string()
        }
        None => generate_password(),
    };

    let hash = password::hash_password(&password_plain)?;
    repositories::update_password(state, user_id, &hash).await?;

    write_audit(
        state,
        operator,
        operator_id,
        "USER_RESET_PASSWORD",
        user_id,
        Some(serde_json::json!({ "username": row.username })),
    )
    .await;

    Ok(serde_json::json!({ "password": password_plain }))
}

/// 用户被授权的项目 ID。
pub async fn list_user_projects(state: &AppState, user_id: u64) -> Result<Vec<u64>, ApiError> {
    find_user_or_404(state, user_id).await?;
    repositories::list_user_project_ids(state, user_id).await
}

/// 全量设置用户的项目授权。
pub async fn set_user_projects(
    state: &AppState,
    user_id: u64,
    project_ids: Vec<u64>,
    operator: &str,
    operator_id: Option<u64>,
) -> Result<Vec<u64>, ApiError> {
    find_user_or_404(state, user_id).await?;
    let ids = validate_project_ids(state, &project_ids).await?;

    repositories::replace_user_projects(state, user_id, &ids).await?;

    write_audit(
        state,
        operator,
        operator_id,
        "USER_SCOPE_UPDATE",
        user_id,
        Some(serde_json::json!({ "projects": ids })),
    )
    .await;

    Ok(ids)
}

/// 校验项目 ID：去重，并要求项目真实存在。
async fn validate_project_ids(state: &AppState, project_ids: &[u64]) -> Result<Vec<u64>, ApiError> {
    let mut unique: Vec<u64> = Vec::with_capacity(project_ids.len());
    for id in project_ids {
        if !unique.contains(id) {
            unique.push(*id);
        }
    }
    if unique.is_empty() {
        return Ok(unique);
    }

    let existing = repositories::existing_project_ids(state, &unique).await?;
    if existing.len() != unique.len() {
        let missing: Vec<u64> = unique
            .iter()
            .copied()
            .filter(|id| !existing.contains(id))
            .collect();
        return Err(ApiError::invalid_param(
            "项目不存在",
            vec![FieldError::new(
                "project_ids",
                format!("以下项目不存在：{missing:?}"),
            )],
        ));
    }
    Ok(unique)
}

/// 按 ID 取账号，不存在则 404。
async fn find_user_or_404(state: &AppState, user_id: u64) -> Result<AdminUserRow, ApiError> {
    repositories::find_user_by_id(state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))
}

/// 行结构转对外结构。
fn to_view(row: AdminUserRow, projects: Vec<u64>) -> UserView {
    UserView {
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        email: row.email,
        role: row.role_code,
        status: row.status,
        fail_count: row.fail_count,
        locked_until: row.locked_until.map(crate::common::format_datetime),
        last_login_at: row.last_login_at.map(crate::common::format_datetime),
        last_login_ip: row.last_login_ip,
        projects,
        created_at: crate::common::format_datetime(row.created_at),
    }
}

/// 写审计日志（失败只记录日志，不影响主流程）。
async fn write_audit(
    state: &AppState,
    operator: &str,
    operator_id: Option<u64>,
    action: &str,
    object_id: u64,
    detail: Option<serde_json::Value>,
) {
    let entry = AuditLogEntry {
        operator: if operator.is_empty() {
            "anonymous".to_string()
        } else {
            operator.to_string()
        },
        operator_id,
        action: action.to_string(),
        object_type: Some("USER".to_string()),
        object_id: Some(object_id.to_string()),
        result: "SUCCESS".to_string(),
        detail,
        trace_id: Some(crate::trace::current_trace_id()),
        ..Default::default()
    };
    if let Err(err) = write_audit_log(state, entry).await {
        tracing::error!(error = %err, action, "写审计日志失败");
    }
}

/// 生成随机强口令：大小写 + 数字 + 特殊字符，长度 16 位。
fn generate_password() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    const CHARSETS: [&str; 4] = [
        "abcdefghijkmnopqrstuvwxyz",
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "23456789",
        "!@#$%^&*?",
    ];
    let mut text = String::with_capacity(16);
    for charset in CHARSETS {
        let index = rng.random_range(0..charset.len());
        text.push(charset.as_bytes()[index] as char);
    }
    while text.len() < 16 {
        let index = rng.random_range(0..CHARSETS[0].len());
        text.push(CHARSETS[0].as_bytes()[index] as char);
    }
    text
}
