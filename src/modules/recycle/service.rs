//! 回收站的业务编排：列表、恢复、永久删除。

use serde_json::json;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::{AuditLogEntry, RecycleBinView};
use crate::modules::recycle::repositories::{self, RecycleBinItem};
use crate::response::ListQuery;

/// 列出回收站条目。
pub async fn list(
    state: &AppState,
    query: &ListQuery,
    visible_projects: Option<&[u64]>,
) -> Result<(Vec<RecycleBinView>, u64), ApiError> {
    let object_type = query.filter("object_type").map(|v| v.to_string());
    let project_filter = query
        .filter("project_id")
        .and_then(|v| v.parse::<u64>().ok());
    let keyword = query.keyword.as_deref();

    let (items, total) = repositories::list(
        state,
        object_type.as_deref(),
        project_filter,
        keyword,
        query.offset(),
        query.page_size(),
    )
    .await?;

    let mut result = Vec::with_capacity(items.len());
    for item in items {
        if let Some(scope) = visible_projects
            && !scope.contains(&item.row.project_id)
        {
            continue;
        }
        result.push(to_view(item));
    }

    Ok((result, total))
}

/// 条目转对外结构。
pub fn to_view(item: RecycleBinItem) -> RecycleBinView {
    RecycleBinView {
        id: item.row.id,
        object_type: item.row.object_type,
        object_id: item.row.object_id,
        object_name: item.row.object_name,
        object_code: item.row.object_code,
        project_id: item.row.project_id,
        project_name: item.project_name,
        deleted_by: item.row.deleted_by,
        deleted_by_name: item.deleted_by_name,
        deleted_at: item.row.deleted_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        expire_at: item.row.expire_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        remain_days: repositories::remain_days(item.row.expire_at),
        purge_status: item.row.purge_status.unwrap_or_else(|| "NONE".to_string()),
        purge_message: item.row.purge_message,
        children_count: item.children_count,
    }
}

/// 恢复一个对象。返回冲突说明（若有）。
pub async fn restore(
    state: &AppState,
    id: u64,
    operator_id: u64,
) -> Result<RecycleBinView, ApiError> {
    let row = repositories::find(state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("回收站条目不存在"))?;

    let mut conflicts: Vec<serde_json::Value> = Vec::new();

    match row.object_type.as_str() {
        "PROJECT" => {
            // 编码冲突校验（含回收站外的同名对象）
            let conflict = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM project WHERE code = ? AND id <> ? AND deleted_at IS NULL",
            )
            .bind(row.object_code.clone().unwrap_or_default())
            .bind(row.object_id)
            .fetch_one(&state.db)
            .await?;
            if conflict > 0 {
                conflicts.push(json!({
                    "type": "project",
                    "field": "code",
                    "value": row.object_code,
                    "detail": "同一项目下已存在同名编码，请先重命名或永久删除冲突项",
                }));
            }

            if conflicts.is_empty() {
                sqlx::query(
                    "UPDATE project SET status = 'ACTIVE', deleted_at = NULL, deleted_by = NULL
                      WHERE id = ?",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;

                sqlx::query(
                    "UPDATE audit_definition SET deleted_at = NULL, deleted_by = NULL
                      WHERE project_id = ? AND deleted_at IS NOT NULL",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;
                sqlx::query(
                    "UPDATE trigger_source SET deleted_at = NULL
                      WHERE audit_id IN (SELECT id FROM audit_definition WHERE project_id = ?)",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;
                sqlx::query(
                    "UPDATE audit_rule SET deleted_at = NULL
                      WHERE audit_id IN (SELECT id FROM audit_definition WHERE project_id = ?)",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;
                sqlx::query(
                    "UPDATE result_route SET deleted_at = NULL
                      WHERE audit_id IN (SELECT id FROM audit_definition WHERE project_id = ?)",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;
            }
        }
        "AUDIT" => {
            let conflict = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_definition
                  WHERE project_id = ? AND code = ? AND id <> ? AND deleted_at IS NULL",
            )
            .bind(row.project_id)
            .bind(row.object_code.clone().unwrap_or_default())
            .bind(row.object_id)
            .fetch_one(&state.db)
            .await?;
            if conflict > 0 {
                conflicts.push(json!({
                    "type": "audit",
                    "field": "code",
                    "value": row.object_code,
                    "detail": "同一项目下已存在同名编码，请先重命名或永久删除冲突项",
                }));
            }

            if conflicts.is_empty() {
                sqlx::query(
                    "UPDATE audit_definition SET status = 'DRAFT', deleted_at = NULL, deleted_by = NULL
                      WHERE id = ?",
                )
                .bind(row.object_id)
                .execute(&state.db)
                .await?;
                sqlx::query("UPDATE trigger_source SET deleted_at = NULL WHERE audit_id = ?")
                    .bind(row.object_id)
                    .execute(&state.db)
                    .await?;
                sqlx::query("UPDATE audit_rule SET deleted_at = NULL WHERE audit_id = ?")
                    .bind(row.object_id)
                    .execute(&state.db)
                    .await?;
                sqlx::query("UPDATE result_route SET deleted_at = NULL WHERE audit_id = ?")
                    .bind(row.object_id)
                    .execute(&state.db)
                    .await?;
            }
        }
        other => {
            return Err(ApiError::bad_request(format!("不支持回收的对象类型：{other}")));
        }
    }

    if !conflicts.is_empty() {
        return Err(ApiError::conflict_with(
            "CODE_CONFLICT",
            "恢复失败，存在冲突",
            json!({ "conflicts": conflicts }),
        ));
    }

    repositories::remove(state, id).await?;

    write_audit(
        state,
        row.project_id,
        operator_id,
        "RECYCLE_RESTORE",
        &row.object_type,
        row.object_id,
        "SUCCESS",
        json!({ "name": row.object_name }),
    )
    .await;

    let restored = RecycleBinView {
        id: row.id,
        object_type: row.object_type,
        object_id: row.object_id,
        object_name: row.object_name,
        object_code: row.object_code,
        project_id: row.project_id,
        project_name: None,
        deleted_by: row.deleted_by,
        deleted_by_name: None,
        deleted_at: row.deleted_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        expire_at: row.expire_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        remain_days: 0,
        purge_status: "NONE".to_string(),
        purge_message: None,
        children_count: 0,
    };
    Ok(restored)
}

/// 永久删除：要求确认名与对象名完全一致。
pub async fn purge(
    state: &AppState,
    id: u64,
    confirm_name: &str,
    operator_id: u64,
) -> Result<serde_json::Value, ApiError> {
    let row = repositories::find(state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("回收站条目不存在"))?;

    if confirm_name.trim() != row.object_name.trim() {
        return Err(ApiError::invalid_param(
            "确认名称不匹配",
            vec![crate::error::FieldError::new(
                "confirm_name",
                format!("请输入「{}」以确认", row.object_name),
            )],
        ));
    }

    let cleanup_id = repositories::insert_cleanup_task(
        state,
        Some(id),
        &row.object_type,
        row.object_id,
        &row.object_name,
        operator_id,
    )
    .await?;

    repositories::set_purge_status(state, id, "PURGING", None).await?;
    repositories::update_cleanup_task(state, cleanup_id, "RUNNING", 10, Some("清理关联数据"), None)
        .await?;

    let outcome = match row.object_type.as_str() {
        "PROJECT" => repositories::purge_project_data(state, row.object_id).await,
        "AUDIT" => repositories::purge_audit_data(state, row.object_id).await,
        _ => Err(ApiError::bad_request("不支持的对象类型")),
    };

    match outcome {
        Ok(()) => {
            repositories::update_cleanup_task(state, cleanup_id, "DONE", 100, Some("清理完成"), None)
                .await?;
            repositories::set_purge_status(state, id, "PURGED", None).await?;
            repositories::remove(state, id).await?;

            write_audit(
                state,
                row.project_id,
                operator_id,
                "RECYCLE_PURGE",
                &row.object_type,
                row.object_id,
                "SUCCESS",
                json!({ "name": row.object_name, "affected": 1 }),
            )
            .await;

            Ok(json!({
                "cleanup_id": cleanup_id,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "object_name": row.object_name,
                "status": "PURGED",
            }))
        }
        Err(err) => {
            repositories::update_cleanup_task(
                state,
                cleanup_id,
                "FAILED",
                0,
                None,
                Some(&err.to_string()),
            )
            .await?;
            repositories::set_purge_status(state, id, "NONE", Some("清理失败")).await?;
            Err(err)
        }
    }
}

/// 批量永久删除：逐项执行，失败的单独列出。
pub async fn batch_purge(
    state: &AppState,
    ids: &[u64],
    operator_id: u64,
) -> Result<serde_json::Value, ApiError> {
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();

    for id in ids {
        match purge(state, *id, "", operator_id).await {
            Ok(_) => succeeded.push(*id),
            Err(err) => failed.push(json!({ "id": id, "reason": err.to_string() })),
        }
    }

    Ok(json!({ "succeeded": succeeded, "failed": failed }))
}

/// 写审计日志。
pub async fn write_audit(
    state: &AppState,
    project_id: u64,
    operator_id: u64,
    action: &str,
    object_type: &str,
    object_id: u64,
    result: &str,
    detail: serde_json::Value,
) {
    let entry = AuditLogEntry {
        project_id: Some(project_id),
        operator: operator_id.to_string(),
        operator_id: Some(operator_id),
        action: action.to_string(),
        object_type: Some(object_type.to_string()),
        object_id: Some(object_id.to_string()),
        result: result.to_string(),
        detail: Some(detail),
        ..Default::default()
    };
    if let Err(err) = crate::modules::auth::repositories::write_audit_log(state, entry).await {
        tracing::error!(error = %err, "写回收站审计日志失败");
    }
}
