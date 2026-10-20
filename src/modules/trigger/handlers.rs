//! 触发源的 HTTP 处理。
//!
//! 这一层只做参数解析、鉴权上下文提取与响应映射，业务逻辑在 `service.rs`。

use actix_web::web;

use crate::db::AppState;
use crate::middleware::AuthContext;
use crate::models::audit::{SaveTriggerRequest, TriggerSourceView};
use crate::modules::trigger::service::{self, ConsumeLogView};
use crate::response::{ApiResult, ok};

/// 列出审核下的触发源。
pub async fn list_triggers(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<Vec<TriggerSourceView>> {
    let audit_id = path.into_inner();
    let items = service::list_triggers(&state, &auth, audit_id).await?;
    ok(items)
}

/// 新建触发源。
pub async fn create_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
    body: web::Json<SaveTriggerRequest>,
) -> ApiResult<TriggerSourceView> {
    let audit_id = path.into_inner();
    let item = service::create_trigger(&state, &auth, audit_id, body.into_inner()).await?;
    ok(item)
}

/// 取触发源详情。
pub async fn get_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<TriggerSourceView> {
    let trigger_id = path.into_inner();
    let item = service::get_trigger(&state, &auth, trigger_id).await?;
    ok(item)
}

/// 更新触发源。
pub async fn update_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
    body: web::Json<SaveTriggerRequest>,
) -> ApiResult<TriggerSourceView> {
    let trigger_id = path.into_inner();
    let item = service::update_trigger(&state, &auth, trigger_id, body.into_inner()).await?;
    ok(item)
}

/// 删除触发源。
pub async fn delete_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    let trigger_id = path.into_inner();
    let result = service::delete_trigger(&state, &auth, trigger_id).await?;
    ok(result)
}

/// 启用触发源。
pub async fn enable_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<TriggerSourceView> {
    let trigger_id = path.into_inner();
    let item = service::enable_trigger(&state, &auth, trigger_id).await?;
    ok(item)
}

/// 暂停触发源。
pub async fn pause_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<TriggerSourceView> {
    let trigger_id = path.into_inner();
    let item = service::pause_trigger(&state, &auth, trigger_id).await?;
    ok(item)
}

/// 测试触发源。
pub async fn test_trigger(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<serde_json::Value> {
    let trigger_id = path.into_inner();
    let result = service::test_trigger(&state, &auth, trigger_id).await?;
    ok(result)
}

/// 取触发源最近的消费记录。
pub async fn recent_logs(
    state: web::Data<AppState>,
    auth: AuthContext,
    path: web::Path<u64>,
) -> ApiResult<Vec<ConsumeLogView>> {
    let trigger_id = path.into_inner();
    let items = service::recent_logs(&state, &auth, trigger_id).await?;
    ok(items)
}
