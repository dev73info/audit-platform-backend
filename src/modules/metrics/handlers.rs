//! 监控看板的接口。

use actix_web::web;
use serde::Deserialize;

use crate::db::AppState;
use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::modules::metrics::repositories::{self, Overview};
use crate::response::{ApiResult, ListQuery, ok};

/// 概览查询参数。
#[derive(Debug, Clone, Deserialize)]
pub struct OverviewQuery {
    /// `global` / `project` / `audit`。
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id: Option<u64>,
    /// `1h` / `6h` / `24h` / `7d`。
    #[serde(default)]
    pub range: Option<String>,
}

/// `GET /api/admin/v1/metrics/overview`
pub async fn overview(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<OverviewQuery>,
) -> ApiResult<Overview> {
    ctx.require_permission("metrics:read")?;

    let scope = query.scope.clone().unwrap_or_else(|| "global".to_string());
    let project_id: Option<u64> = match scope.as_str() {
        "project" | "audit" => Some(query.id.ok_or_else(|| {
            ApiError::invalid_param("缺少目标 ID", vec![crate::error::FieldError::new("id", "必填")])
        })?),
        _ => None,
    };

    if let Some(pid) = project_id {
        ctx.require_project(pid)?;
    }

    let hours = match query.range.as_deref().unwrap_or("24h") {
        "1h" => 1,
        "6h" => 6,
        "7d" => 24 * 7,
        _ => 24,
    };

    let (total, pass, reject, review, failed) = repositories::task_counts(&state, project_id).await?;
    let today = repositories::task_today(&state, project_id).await?;
    let dedupe = repositories::dedupe_hits(&state, project_id).await?;
    let backlog = repositories::backlog(&state, project_id).await?;
    let dead_letter = repositories::dead_letters(&state, project_id).await?;
    let (p50, p95, p99) = repositories::duration_percentiles(&state, project_id).await?;
    let (action_total, action_failed) = repositories::action_counts(&state, project_id).await?;
    let series = repositories::series(&state, project_id, hours).await?;
    let projects = repositories::project_health(&state, ctx.visible_projects()).await?;
    let alerts = repositories::active_alerts(&state, 20).await?;

    let success_rate = if action_total > 0 {
        1.0 - action_failed as f64 / action_total as f64
    } else {
        1.0
    };

    ok(Overview {
        task_total: total,
        task_today: today,
        pass,
        reject,
        review,
        failed,
        dedupe_hit: dedupe,
        backlog,
        dead_letter,
        duration_p50: p50,
        duration_p95: p95,
        duration_p99: p99,
        action_total,
        action_failed,
        action_success_rate: success_rate,
        series,
        projects,
        alerts,
    })
}

/// `GET /api/admin/v1/metrics/alerts`
pub async fn alerts(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<Vec<crate::models::ops::AlertEventRow>> {
    ctx.require_permission("metrics:read")?;
    let limit = query.page_size().min(200) as i64;
    let items = repositories::active_alerts(&state, limit).await?;
    ok(items)
}

/// `GET /api/admin/v1/notifications`
pub async fn notifications(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<crate::response::Page<crate::models::ops::NotificationRow>> {
    ctx.require_permission("metrics:read")?;
    let (items, total) = repositories::notifications(
        &state,
        Some(ctx.user_id),
        query.offset(),
        query.page_size(),
    )
    .await?;
    ok(crate::response::Page::new(items, total, query.page(), query.page_size()))
}

/// `POST /api/admin/v1/notifications/{id}/read`
pub async fn read_notification(
    ctx: AuthContext,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("metrics:read")?;
    let id = path.into_inner();
    sqlx::query("UPDATE notification SET read_at = ? WHERE id = ? AND (user_id IS NULL OR user_id = ?)")
        .bind(chrono::Utc::now().naive_utc())
        .bind(id)
        .bind(ctx.user_id)
        .execute(&state.db)
        .await?;
    ok(serde_json::json!({ "read": true }))
}

/// `POST /api/admin/v1/notifications/read-all`
pub async fn read_all(
    ctx: AuthContext,
    state: web::Data<AppState>,
) -> ApiResult<serde_json::Value> {
    ctx.require_permission("metrics:read")?;
    sqlx::query("UPDATE notification SET read_at = ? WHERE read_at IS NULL AND (user_id IS NULL OR user_id = ?)")
        .bind(chrono::Utc::now().naive_utc())
        .bind(ctx.user_id)
        .execute(&state.db)
        .await?;
    ok(serde_json::json!({ "read": true }))
}
