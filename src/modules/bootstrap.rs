//! 启动期迁移：建表 + 种子数据 + 初始管理员账号。
//!
//! `cargo run --bin migrate` 与后端启动时的 `auto_migrate` 都走这里。

use anyhow::Context;
use sqlx::mysql::MySqlPool;

use crate::db::AppState;

/// 执行建表脚本、种子脚本，并确保初始管理员存在。
pub async fn run_migrations(state: &AppState) -> anyhow::Result<()> {
    apply_scripts(&state.db).await?;
    ensure_bootstrap_admin(state).await?;
    Ok(())
}

/// 执行 `db/schema.sql` 与 `db/seed.sql`。
pub async fn apply_scripts(pool: &MySqlPool) -> anyhow::Result<()> {
    let schema_path = resolve_path("db/schema.sql");
    let seed_path = resolve_path("db/seed.sql");
    crate::db::apply_sql_files(pool, &[schema_path.as_str(), seed_path.as_str()]).await
}

/// 定位 `db/` 目录：先看当前工作目录，再看上两级（从 `backend/` 跑到仓库根的情况）。
fn resolve_path(relative: &str) -> String {
    let candidates = [
        relative.to_string(),
        format!("backend/{relative}"),
        format!("../backend/{relative}"),
    ];
    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            return candidate.clone();
        }
    }
    relative.to_string()
}

/// 确保初始管理员账号存在；不存在则按配置创建。
pub async fn ensure_bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    let username = state.settings.security.bootstrap_admin_username.trim();
    if username.is_empty() {
        return Ok(());
    }

    let exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM admin_user WHERE username = ? LIMIT 1")
            .bind(username)
            .fetch_optional(&state.db)
            .await
            .context("查询初始管理员失败")?;

    if exists.is_some() {
        return Ok(());
    }

    let password = state.settings.security.bootstrap_admin_password.clone();
    let hash = crate::security::password::hash_password(&password)
        .map_err(|err| anyhow::anyhow!("初始管理员口令哈希失败：{}", err.code()))?;
    let id = state.ids.next_id();

    sqlx::query(
        "INSERT INTO admin_user (id, username, password_hash, display_name, role_code, status)
         VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
    )
    .bind(id)
    .bind(username)
    .bind(hash)
    .bind("系统管理员")
    .bind("SUPER_ADMIN")
    .execute(&state.db)
    .await
    .context("创建初始管理员失败")?;

    tracing::info!(username, "初始管理员账号已创建");
    Ok(())
}
