//! 审计日志的数据访问层。

use serde_json::Value;
use sqlx::Row;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AuditLogRow;

/// 绑定筛选条件（顺序与 `conditions()` 一致）。
macro_rules! bind_filter {
    ($query:expr, $filter:expr) => {{
        let mut query = $query;
        let filter = $filter;
        if let Some(value) = filter.operator.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(format!("%{value}%"));
        }
        if let Some(value) = filter.action.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.object_type.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.object_id.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.project_id {
            query = query.bind(value);
        }
        if let Some(value) = filter.result.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.created_at_from.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.created_at_to.as_ref().filter(|v| !v.is_empty()) {
            query = query.bind(value.clone());
        }
        if let Some(value) = filter.keyword.as_ref().filter(|v| !v.is_empty()) {
            query = query
                .bind(format!("%{value}%"))
                .bind(format!("%{value}%"))
                .bind(format!("%{value}%"));
        }
        query
    }};
}

/// 审计日志筛选条件。
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub operator: Option<String>,
    pub action: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
    pub project_id: Option<u64>,
    pub result: Option<String>,
    pub created_at_from: Option<String>,
    pub created_at_to: Option<String>,
    pub keyword: Option<String>,
}

impl AuditLogFilter {
    /// 拼出 WHERE 条件（占位符顺序与绑定顺序一致）。
    fn conditions(&self) -> String {
        let mut conditions = vec!["1 = 1".to_string()];
        if self.operator.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("operator LIKE ?".to_string());
        }
        if self.action.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("action = ?".to_string());
        }
        if self.object_type.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("object_type = ?".to_string());
        }
        if self.object_id.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("object_id = ?".to_string());
        }
        if self.project_id.is_some() {
            conditions.push("project_id = ?".to_string());
        }
        if self.result.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("result = ?".to_string());
        }
        if self.created_at_from.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("created_at >= ?".to_string());
        }
        if self.created_at_to.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("created_at <= ?".to_string());
        }
        if self.keyword.as_ref().is_some_and(|v| !v.is_empty()) {
            conditions.push("(operator LIKE ? OR action LIKE ? OR object_id LIKE ?)".to_string());
        }
        conditions.join(" AND ")
    }
}

/// 列出审计日志。
pub async fn list(
    state: &AppState,
    filter: &AuditLogFilter,
    visible_projects: Option<&[u64]>,
    offset: u64,
    limit: u64,
) -> Result<(Vec<AuditLogRow>, u64), ApiError> {
    let where_sql = filter.conditions();

    let count_sql = format!("SELECT COUNT(*) FROM audit_log WHERE {where_sql}");
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    count_query = bind_filter!(count_query, filter);
    let mut total = count_query.fetch_one(&state.db).await? as u64;

    let list_sql = format!(
        "SELECT id, project_id, operator, operator_id, operator_ip, action, object_type,
                object_id, result, detail_json, trace_id, created_at
           FROM audit_log
          WHERE {where_sql}
          ORDER BY created_at DESC, id DESC
          LIMIT ? OFFSET ?"
    );
    let mut list_query = sqlx::query(&list_sql);
    list_query = bind_filter!(list_query, filter);
    let rows = list_query.bind(limit).bind(offset).fetch_all(&state.db).await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let project_id = row.get::<Option<u64>, _>("project_id");
        if let Some(scope) = visible_projects
            && let Some(pid) = project_id
            && !scope.contains(&pid)
        {
            total = total.saturating_sub(1);
            continue;
        }
        items.push(AuditLogRow {
            id: row.get("id"),
            project_id,
            operator: row.get("operator"),
            operator_id: row.get("operator_id"),
            operator_ip: row.get("operator_ip"),
            action: row.get("action"),
            object_type: row.get("object_type"),
            object_id: row.get("object_id"),
            result: row.get("result"),
            detail_json: row.get("detail_json"),
            trace_id: row.get("trace_id"),
            created_at: row.get("created_at"),
        });
    }

    Ok((items, total))
}

/// 导出用的全部记录（受上限保护）。
pub async fn list_for_export(
    state: &AppState,
    filter: &AuditLogFilter,
    limit: i64,
) -> Result<Vec<AuditLogRow>, ApiError> {
    let (items, _) = list(state, filter, None, 0, limit as u64).await?;
    Ok(items)
}

/// 写一条审计日志。
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    state: &AppState,
    project_id: Option<u64>,
    operator: &str,
    operator_id: Option<u64>,
    operator_ip: Option<&str>,
    action: &str,
    object_type: Option<&str>,
    object_id: Option<&str>,
    result: &str,
    detail: Option<Value>,
    trace_id: Option<&str>,
) -> Result<(), ApiError> {
    let id = state.ids.next_id();
    sqlx::query(
        "INSERT INTO audit_log
            (id, project_id, operator, operator_id, operator_ip, action, object_type,
             object_id, result, detail_json, trace_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(operator)
    .bind(operator_id)
    .bind(operator_ip)
    .bind(action)
    .bind(object_type)
    .bind(object_id)
    .bind(result)
    .bind(detail)
    .bind(trace_id)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;
    Ok(())
}
