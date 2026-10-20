//! 应用状态：数据库连接池、Redis 连接、配置、指标注册表。
//!
//! 整个进程共享一份 `AppState`，通过 `web::Data<AppState>` 注入各 handler。

use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::Executor;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

use crate::metrics::MetricsRegistry;
use crate::settings::Settings;

/// 全局应用状态。
#[derive(Clone)]
pub struct AppState {
    /// 系统库（项目、审核、任务、审计）。
    pub db: MySqlPool,
    /// Redis 连接管理器；Redis 不可用时为 `None`，系统降级为「仅数据库唯一索引去重」。
    pub redis: Option<ConnectionManager>,
    /// 运行期配置。
    pub settings: Arc<Settings>,
    /// 进程内指标注册表。
    pub metrics: Arc<MetricsRegistry>,
    /// 雪花 ID 生成器。
    pub ids: Arc<crate::common::IdGenerator>,
}

impl AppState {
    /// 初始化数据库连接池。
    pub async fn connect_db(settings: &Settings) -> anyhow::Result<MySqlPool> {
        let pool = MySqlPoolOptions::new()
            .max_connections(settings.database.max_connections)
            .min_connections(settings.database.min_connections)
            .acquire_timeout(std::time::Duration::from_millis(
                settings.database.acquire_timeout_ms,
            ))
            // 会话时区固定为 UTC：库里的 DATETIME 一律按 UTC 解释，
            // 否则服务端时区一变，同一时刻写入的时间就会漂。
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET time_zone = '+00:00'")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&settings.database.url)
            .await?;
        Ok(pool)
    }

    /// 初始化 Redis 连接。连接失败不阻断启动：返回 `None`，调用方按降级策略处理。
    pub async fn connect_redis(settings: &Settings) -> Option<ConnectionManager> {
        let client = redis::Client::open(settings.redis.url.as_str()).ok()?;
        match redis::aio::ConnectionManager::new(client).await {
            Ok(manager) => Some(manager),
            Err(err) => {
                tracing::warn!(error = %err, "Redis 连接失败，幂等锁降级为数据库唯一索引");
                None
            }
        }
    }

    /// Redis 是否可用。
    pub fn redis_available(&self) -> bool {
        self.redis.is_some()
    }
}

/// 执行 `schema.sql` 与 `seed.sql`。脚本里的语句按分号切分后逐条执行。
pub async fn apply_sql_files(pool: &MySqlPool, files: &[&str]) -> anyhow::Result<()> {
    for file in files {
        let raw = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("读取 SQL 文件 {file} 失败：{e}"))?;
        for statement in split_sql_statements(&raw) {
            pool.execute(statement.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("执行 {file} 中的语句失败：{e}\nSQL: {statement}"))?;
        }
        tracing::info!(file, "SQL 脚本执行完成");
    }
    Ok(())
}

/// 粗粒度地按分号切分 SQL。跳过注释行与空语句。
fn split_sql_statements(raw: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut buffer = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        buffer.push_str(line);
        buffer.push('\n');
        if trimmed.ends_with(';') {
            let statement = buffer.trim().trim_end_matches(';').trim().to_string();
            if !statement.is_empty() {
                statements.push(statement);
            }
            buffer.clear();
        }
    }
    let tail = buffer.trim().trim_end_matches(';').trim().to_string();
    if !tail.is_empty() {
        statements.push(tail);
    }
    statements
}
