//! 监控模块的公共辅助。

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AuditLogEntry;

/// 写一条审计日志。
pub async fn write(state: &AppState, entry: AuditLogEntry) -> Result<(), ApiError> {
    crate::modules::auth::repositories::write_audit_log(state, entry).await
}
