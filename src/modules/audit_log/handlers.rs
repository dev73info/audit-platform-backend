//! 审计日志的接口与导出。

use actix_web::web;
use serde::Serialize;

use crate::db::AppState;
use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::models::ops::AuditLogView;
use crate::modules::audit_log::repositories::{self, AuditLogFilter};
use crate::response::{ApiResult, ListQuery, ok};

/// 把查询参数解析成筛选条件。
pub fn parse_filter(query: &ListQuery) -> AuditLogFilter {
    AuditLogFilter {
        operator: query.filter("operator").map(|v| v.to_string()),
        action: query.filter("action").map(|v| v.to_string()),
        object_type: query.filter("object_type").map(|v| v.to_string()),
        object_id: query.filter("object_id").map(|v| v.to_string()),
        project_id: query.filter("project_id").and_then(|v| v.parse::<u64>().ok()),
        result: query.filter("result").map(|v| v.to_string()),
        created_at_from: query.filter("created_at_from").map(|v| v.to_string()),
        created_at_to: query.filter("created_at_to").map(|v| v.to_string()),
        keyword: query.keyword.clone(),
    }
}

/// 行转对外结构。
pub fn to_view(row: crate::models::ops::AuditLogRow) -> AuditLogView {
    AuditLogView {
        id: row.id,
        project_id: row.project_id,
        operator: row.operator,
        operator_id: row.operator_id,
        operator_ip: row.operator_ip,
        action: row.action,
        object_type: row.object_type,
        object_id: row.object_id,
        result: row.result,
        detail: row.detail_json.unwrap_or(serde_json::Value::Null),
        trace_id: row.trace_id,
        created_at: row.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    }
}

/// `GET /api/admin/v1/audit-logs`
pub async fn list(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<crate::response::Page<AuditLogView>> {
    ctx.require_permission("audit_log:read")?;
    let filter = parse_filter(&query);
    let (rows, total) = repositories::list(
        &state,
        &filter,
        ctx.visible_projects(),
        query.offset(),
        query.page_size(),
    )
    .await?;
    let items: Vec<AuditLogView> = rows.into_iter().map(to_view).collect();
    ok(crate::response::Page::new(items, total, query.page(), query.page_size()))
}

/// 导出结果。
#[derive(Debug, Clone, Serialize)]
pub struct ExportResult {
    pub export_id: u64,
    pub status: String,
    pub total_rows: i64,
    pub file_path: String,
}

/// `POST /api/admin/v1/audit-logs/export`
pub async fn export(
    ctx: AuthContext,
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> ApiResult<ExportResult> {
    ctx.require_permission("audit_log:export")?;
    let filter = parse_filter(&query);

    const EXPORT_LIMIT: i64 = 10_000;
    let rows = repositories::list_for_export(&state, &filter, EXPORT_LIMIT).await?;

    let export_id = state.ids.next_id();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/exports");
    std::fs::create_dir_all(&dir)
        .map_err(|err| ApiError::internal(format!("创建导出目录失败：{err}")))?;
    let file_path = dir.join(format!("audit_logs_{export_id}.csv"));

    let mut csv = String::from("时间,操作人,IP,操作,对象类型,对象ID,结果,追踪ID\n");
    for row in &rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            row.created_at.format("%Y-%m-%d %H:%M:%S"),
            csv_escape(&row.operator),
            csv_escape(row.operator_ip.as_deref().unwrap_or("")),
            csv_escape(&row.action),
            csv_escape(row.object_type.as_deref().unwrap_or("")),
            csv_escape(row.object_id.as_deref().unwrap_or("")),
            csv_escape(&row.result),
            csv_escape(row.trace_id.as_deref().unwrap_or("")),
        ));
    }
    std::fs::write(&file_path, csv)
        .map_err(|err| ApiError::internal(format!("写导出文件失败：{err}")))?;

    sqlx::query(
        "INSERT INTO export_task
            (id, project_id, requested_by, page_key, filters_json, format, status, total_rows, file_path, created_at)
         VALUES (?, ?, ?, 'audit_logs', ?, 'CSV', 'DONE', ?, ?, ?)",
    )
    .bind(export_id)
    .bind(ctx.visible_projects().and_then(|s| s.first().copied()))
    .bind(ctx.user_id)
    .bind(serde_json::to_value(&filter.project_id).unwrap_or(serde_json::Value::Null))
    .bind(rows.len() as i64)
    .bind(file_path.to_string_lossy().to_string())
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;

    ok(ExportResult {
        export_id,
        status: "DONE".to_string(),
        total_rows: rows.len() as i64,
        file_path: file_path.to_string_lossy().to_string(),
    })
}

/// CSV 字段转义。
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
