//! 开放 API 的 HTTP 与 WebSocket 处理器。

use actix_web::{HttpRequest, web};
use actix_ws::Message;
use serde::Deserialize;
use serde_json::json;

use crate::db::AppState;
use crate::error::ApiError;
use crate::modules::openapi::repositories;
use crate::modules::openapi::service::{
    self, PollResponse, SignatureRequest, SubmitRequest, TaskResultResponse,
};
use crate::response::{ApiResult, ok};

/// 从请求里取出签名头与来源 IP。
fn signature_request(
    req: &HttpRequest,
    method: &str,
    path: &str,
    body: &[u8],
) -> SignatureRequest {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };

    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or_default()
        .to_string();

    SignatureRequest {
        api_key: header("X-Api-Key"),
        timestamp: header("X-Timestamp"),
        nonce: header("X-Nonce"),
        signature: header("X-Signature"),
        method: method.to_string(),
        path: path.to_string(),
        body: body.to_vec(),
        client_ip,
    }
}

/// `POST /open/v1/projects/{pid}/audits/{aid}/submit`
pub async fn submit(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    body: web::Bytes,
) -> ApiResult<service::SubmitResponse> {
    let (project_id, audit_id) = path.into_inner();
    let signature = signature_request(&req, "POST", &format!("/open/v1/projects/{project_id}/audits/{audit_id}/submit"), &body);

    let client = service::verify(&state, &signature).await?;
    if client.project_id != project_id {
        return Err(ApiError::out_of_scope("项目与应用密钥不匹配"));
    }

    let payload: SubmitRequest = serde_json::from_slice(&body)
        .map_err(|err| ApiError::invalid_param(format!("请求体解析失败：{err}"), Vec::new()))?;

    let response = service::submit(&state, &client, audit_id, payload).await?;

    if response.dedupe == "DUPLICATED" {
        return Err(ApiError::conflict_with(
            "DUPLICATED_TASK",
            "重复任务",
            json!({
                "task_id": response.task_id,
                "dedupe": "DUPLICATED",
                "origin_task_id": response.task_id,
            }),
        ));
    }

    ok(response)
}

/// `GET /open/v1/projects/{pid}/tasks/{task_id}`
pub async fn get_task(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> ApiResult<TaskResultResponse> {
    let (project_id, task_id) = path.into_inner();
    let signature = signature_request(
        &req,
        "GET",
        &format!("/open/v1/projects/{project_id}/tasks/{task_id}"),
        &[],
    );

    let client = service::verify(&state, &signature).await?;
    if client.project_id != project_id {
        return Err(ApiError::out_of_scope("项目与应用密钥不匹配"));
    }

    let row = repositories::find_task(&state, project_id, task_id)
        .await?
        .ok_or_else(|| ApiError::not_found("任务不存在"))?;

    ok(service::to_task_result(row))
}

/// 轮询查询参数。
#[derive(Debug, Clone, Deserialize)]
pub struct PollQuery {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub size: Option<i64>,
}

/// `GET /open/v1/projects/{pid}/audits/{aid}/poll`
pub async fn poll(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    query: web::Query<PollQuery>,
) -> ApiResult<PollResponse> {
    let (project_id, audit_id) = path.into_inner();
    let signature = signature_request(
        &req,
        "GET",
        &format!("/open/v1/projects/{project_id}/audits/{audit_id}/poll"),
        &[],
    );

    let client = service::verify(&state, &signature).await?;
    if client.project_id != project_id {
        return Err(ApiError::out_of_scope("项目与应用密钥不匹配"));
    }

    let size = query.size.unwrap_or(50).clamp(1, 200);
    let after_id = query
        .cursor
        .as_deref()
        .map(|cursor| service::decode_cursor(cursor, audit_id))
        .unwrap_or(0);

    let rows = repositories::poll_finished_tasks(&state, project_id, audit_id, after_id, size + 1)
        .await?;
    let has_more = rows.len() as i64 > size;
    let items: Vec<TaskResultResponse> = rows
        .into_iter()
        .take(size as usize)
        .map(service::to_task_result)
        .collect();
    let next_cursor = items
        .last()
        .map(|item| service::encode_cursor(audit_id, item.task_id))
        .unwrap_or_else(|| service::encode_cursor(audit_id, after_id));

    ok(PollResponse {
        items,
        next_cursor,
        has_more,
    })
}

/// 回调注册入参。
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackRequest {
    pub callback_url: String,
    #[serde(default)]
    pub secret: Option<String>,
}

/// `POST /open/v1/callbacks/register`
pub async fn register_callback(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> ApiResult<serde_json::Value> {
    let signature = signature_request(&req, "POST", "/open/v1/callbacks/register", &body);
    let client = service::verify(&state, &signature).await?;

    let payload: CallbackRequest = serde_json::from_slice(&body)
        .map_err(|err| ApiError::invalid_param(format!("请求体解析失败：{err}"), Vec::new()))?;

    service::register_callback(
        &state,
        &client,
        &payload.callback_url,
        payload.secret.clone(),
    )
    .await?;

    ok(json!({ "registered": true }))
}

/// WebSocket 查询参数。
#[derive(Debug, Clone, Deserialize)]
pub struct WsQuery {
    #[serde(default)]
    pub app_key: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub sign: Option<String>,
}

/// `WS /open/v1/ws/projects/{pid}/audits/{aid}`
pub async fn websocket(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
    query: web::Query<WsQuery>,
    payload: web::Payload,
) -> Result<actix_web::HttpResponse, actix_web::Error> {
    let (project_id, audit_id) = path.into_inner();
    let ws_path = format!("/open/v1/ws/projects/{project_id}/audits/{audit_id}");

    let signature = SignatureRequest {
        api_key: query.app_key.clone().unwrap_or_default(),
        timestamp: query.timestamp.clone().unwrap_or_default(),
        nonce: query.nonce.clone().unwrap_or_default(),
        signature: query.sign.clone().unwrap_or_default(),
        method: "GET".to_string(),
        path: ws_path,
        body: Vec::new(),
        client_ip: req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or_default()
            .to_string(),
    };

    let client = match service::verify(&state, &signature).await {
        Ok(client) => client,
        Err(_) => {
            // 认证失败直接断开，关闭码 4401。
            return Ok(actix_web::HttpResponse::Unauthorized()
                .insert_header(("X-Close-Code", "4401"))
                .json(json!({ "code": 401, "message": "UNAUTHORIZED" })));
        }
    };

    if client.project_id != project_id {
        return Ok(actix_web::HttpResponse::Unauthorized()
            .insert_header(("X-Close-Code", "4401"))
            .json(json!({ "code": 403, "message": "PROJECT_OUT_OF_SCOPE" })));
    }

    const WS_MAX_PER_PROJECT: usize = 100;
    if !service::acquire_ws_slot(project_id, WS_MAX_PER_PROJECT) {
        return Ok(actix_web::HttpResponse::TooManyRequests()
            .insert_header(("X-Close-Code", "4429"))
            .json(json!({ "code": 429, "message": "RATE_LIMITED" })));
    }

    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, payload)?;
    let state = state.clone();
    let client = client.clone();

    actix_web::rt::spawn(async move {
        let _guard = WsGuard { project_id };
        let mut last_pong = std::time::Instant::now();

        while let Some(Ok(message)) = msg_stream.next().await {
            match message {
                Message::Ping(bytes) => {
                    let _ = session.pong(&bytes).await;
                }
                Message::Pong(_) => {
                    last_pong = std::time::Instant::now();
                }
                Message::Text(text) => {
                    handle_ws_text(&state, &client, audit_id, &text, &mut session).await;
                }
                Message::Close(reason) => {
                    let _ = session.close(reason).await;
                    break;
                }
                _ => {}
            }

            if last_pong.elapsed() > std::time::Duration::from_secs(90) {
                let _ = session
                    .close(Some((actix_ws::CloseCode::Away, "心跳超时").into()))
                    .await;
                break;
            }
        }
    });

    Ok(response)
}

/// 连接守卫：断开时归还名额。
struct WsGuard {
    project_id: u64,
}

impl Drop for WsGuard {
    fn drop(&mut self) {
        service::release_ws_slot(self.project_id);
    }
}

/// 处理 WebSocket 文本帧。
async fn handle_ws_text(
    state: &web::Data<AppState>,
    client: &service::VerifiedClient,
    audit_id: u64,
    text: &str,
    session: &mut actix_ws::Session,
) {
    let Ok(frame) = serde_json::from_str::<serde_json::Value>(text) else {
        let _ = session
            .text(json!({ "type": "error", "message": "帧格式非法" }).to_string())
            .await;
        return;
    };

    match frame.get("type").and_then(|v| v.as_str()).unwrap_or_default() {
        "auth" => {
            let _ = session
                .text(json!({ "type": "auth_ok", "app_key": client.app_key }).to_string())
                .await;
        }
        "ping" => {
            let _ = session.text(json!({ "type": "pong" }).to_string()).await;
        }
        "submit" => {
            let body = frame.get("data").cloned().unwrap_or(json!({}));
            let request: SubmitRequest = match serde_json::from_value(body) {
                Ok(request) => request,
                Err(err) => {
                    let _ = session
                        .text(json!({ "type": "error", "message": format!("请求体解析失败：{err}") }).to_string())
                        .await;
                    return;
                }
            };

            match service::submit(state, client, audit_id, request).await {
                Ok(response) => {
                    let _ = session
                        .text(json!({ "type": "ack", "task_id": response.task_id, "status": response.status }).to_string())
                        .await;
                }
                Err(err) => {
                    let _ = session
                        .text(json!({ "type": "error", "code": err.code(), "message": err.to_string() }).to_string())
                        .await;
                }
            }
        }
        other => {
            let _ = session
                .text(json!({ "type": "error", "message": format!("未知帧类型：{other}") }).to_string())
                .await;
        }
    }
}

use futures_util::StreamExt;
