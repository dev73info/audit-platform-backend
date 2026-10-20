//! audit-platform 后端入口。
//!
//! 启动流程：加载配置 → 初始化连接池 → 可选自动迁移 → 组装路由 → 监听。

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::middleware::Next;
use actix_web::{App, Error, HttpResponse, HttpServer, web};

use audit_platform::db::AppState;
use audit_platform::metrics::MetricsRegistry;
use audit_platform::settings::Settings;
use audit_platform::{modules, trace};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_tracing();

    let config_dir = std::env::var("AUDIT_CONFIG_DIR").unwrap_or_else(|_| "config".to_string());
    let settings = match Settings::load(&config_dir) {
        Ok(settings) => Arc::new(settings),
        Err(err) => {
            eprintln!("加载配置失败：{err}");
            return Err(std::io::Error::other(err.to_string()));
        }
    };

    let state = build_state(&settings)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    if settings.database.auto_migrate {
        if let Err(err) = modules::bootstrap::run_migrations(&state).await {
            eprintln!("自动迁移失败：{err}");
            return Err(std::io::Error::other(err.to_string()));
        }
    }

    let bind_address = format!("{}:{}", settings.server.host, settings.server.port);
    tracing::info!(address = %bind_address, "审核中台后端启动");

    let allow_origins = settings.server.cors_allow_origins.clone();
    let state_data = web::Data::new(state);

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .max_age(3600);
        if allow_origins.is_empty() {
            cors = cors.allow_any_origin();
        } else {
            for origin in &allow_origins {
                cors = cors.allowed_origin(origin.as_str());
            }
        }

        App::new()
            .app_data(state_data.clone())
            .wrap(actix_web::middleware::from_fn(trace_middleware))
            .wrap(cors)
            .configure(modules::configure)
            .service(web::resource("/metrics").route(web::get().to(prometheus_metrics)))
            .default_service(web::route().to(spa_fallback))
    })
    .bind(bind_address)?
    .run()
    .await
}

/// 组装应用状态。
pub async fn build_state(settings: &Settings) -> anyhow::Result<AppState> {
    let db = AppState::connect_db(settings).await?;
    let redis = AppState::connect_redis(settings).await;
    if redis.is_none() && !settings.redis.degrade_to_db_only {
        anyhow::bail!("Redis 不可用且未开启降级，启动中止");
    }
    Ok(AppState {
        db,
        redis,
        settings: Arc::new(settings.clone()),
        metrics: Arc::new(MetricsRegistry::new()),
        ids: Arc::new(audit_platform::common::IdGenerator::from_env()),
    })
}

/// 追踪中间件：生成 `trace_id`、回写响应头、记录访问日志。
async fn trace_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let trace_id = req
        .headers()
        .get("X-Trace-Id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty() && value.len() <= 64)
        .map(|value| value.to_string())
        .unwrap_or_else(trace::new_trace_id);

    let method = req.method().clone();
    let path = req.path().to_string();

    let response = trace::scope(trace_id.clone(), next.call(req)).await?;

    let cost_ms = trace::current_cost_ms();
    tracing::info!(
        trace_id = %trace_id,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        cost_ms,
        "请求完成"
    );

    let mut response = response;
    if let Ok(value) = header::HeaderValue::from_str(&trace_id) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("x-trace-id"), value);
    }
    Ok(response)
}

/// Prometheus 指标输出。
async fn prometheus_metrics(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(state.metrics.render_prometheus())
}

/// 静态资源兜底：存在前端构建产物时返回 SPA 入口，否则提示未构建。
async fn spa_fallback(_req: actix_web::HttpRequest) -> HttpResponse {
    let dist_dir =
        std::env::var("AUDIT_FRONTEND_DIST").unwrap_or_else(|_| "../frontend/dist".to_string());
    let index = std::path::Path::new(&dist_dir).join("index.html");

    if !index.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "code": 404,
            "message": "NOT_FOUND",
            "data": serde_json::Value::Null,
            "trace_id": trace::current_trace_id(),
            "cost_ms": 0,
        }));
    }

    match std::fs::read_to_string(&index) {
        Ok(content) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(content),
        Err(_) => HttpResponse::InternalServerError().body("读取前端入口失败"),
    }
}

/// 初始化日志。
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,actix_server=warn"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .init();
}
