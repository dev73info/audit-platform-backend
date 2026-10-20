//! 审计日志模块的公共辅助。

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AuditLogEntry;

/// 写一条审计日志。
pub async fn write(state: &AppState, entry: AuditLogEntry) -> Result<(), ApiError> {
    repositories_insert(state, entry).await
}

async fn repositories_insert(state: &AppState, entry: AuditLogEntry) -> Result<(), ApiError> {
    super::repositories::insert(
        state,
        entry.project_id,
        &entry.operator,
        entry.operator_id,
        entry.operator_ip.as_deref(),
        &entry.action,
        entry.object_type.as_deref(),
        entry.object_id.as_deref(),
        &entry.result,
        entry.detail,
        entry.trace_id.as_deref(),
    )
    .await
}
