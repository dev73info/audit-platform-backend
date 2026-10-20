//! 数据库迁移入口：建表 + 种子数据 + 初始管理员。
//!
//! 用法：`cargo run --bin migrate`

use std::sync::Arc;

use audit_platform::db::AppState;
use audit_platform::modules::bootstrap;
use audit_platform::settings::Settings;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx=warn")),
        )
        .init();

    let config_dir = std::env::var("AUDIT_CONFIG_DIR").unwrap_or_else(|_| "config".to_string());
    let settings = Settings::load(&config_dir)?;

    let db = AppState::connect_db(&settings).await?;
    let redis = AppState::connect_redis(&settings).await;

    let state = AppState {
        db,
        redis,
        settings: Arc::new(settings),
        metrics: Arc::new(audit_platform::metrics::MetricsRegistry::new()),
        ids: Arc::new(audit_platform::common::IdGenerator::from_env()),
    };

    bootstrap::apply_scripts(&state.db).await?;
    bootstrap::ensure_bootstrap_admin(&state).await?;

    println!("迁移完成。");
    Ok(())
}
