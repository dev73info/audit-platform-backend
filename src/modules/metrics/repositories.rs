//! 监控指标的数据访问层。

use serde::Serialize;
use sqlx::Row;

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::ops::AlertEventRow;

/// 时间序列上的一点。
#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    pub ts: String,
    pub pass: i64,
    pub reject: i64,
    pub review: i64,
    pub failed: i64,
}

/// 项目健康度。
#[derive(Debug, Clone, Serialize)]
pub struct ProjectHealth {
    pub project_id: u64,
    pub project_name: String,
    pub health: String,
    pub task_total: i64,
    pub backlog: i64,
    pub error_rate: f64,
    pub mysql_pool_in_use: i64,
    pub redis_conn_in_use: i64,
}

/// 看板概览。
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub task_total: i64,
    pub task_today: i64,
    pub pass: i64,
    pub reject: i64,
    pub review: i64,
    pub failed: i64,
    pub dedupe_hit: i64,
    pub backlog: i64,
    pub dead_letter: i64,
    pub duration_p50: i64,
    pub duration_p95: i64,
    pub duration_p99: i64,
    pub action_total: i64,
    pub action_failed: i64,
    pub action_success_rate: f64,
    pub series: Vec<SeriesPoint>,
    pub projects: Vec<ProjectHealth>,
    pub alerts: Vec<AlertEventRow>,
}

/// 统计任务结果分布。
pub async fn task_counts(
    state: &AppState,
    project_id: Option<u64>,
) -> Result<(i64, i64, i64, i64, i64), ApiError> {
    let mut query = sqlx::query(
        "SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS pass,
            SUM(CASE WHEN result = 'REJECT' THEN 1 ELSE 0 END) AS reject,
            SUM(CASE WHEN result = 'REVIEW' THEN 1 ELSE 0 END) AS review,
            SUM(CASE WHEN status IN ('FAILED', 'DEAD_LETTER') THEN 1 ELSE 0 END) AS failed
           FROM audit_task WHERE 1 = 1",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    let row = query.fetch_one(&state.db).await?;
    Ok((
        row.get::<Option<i64>, _>("total").unwrap_or(0),
        row.get::<Option<i64>, _>("pass").unwrap_or(0),
        row.get::<Option<i64>, _>("reject").unwrap_or(0),
        row.get::<Option<i64>, _>("review").unwrap_or(0),
        row.get::<Option<i64>, _>("failed").unwrap_or(0),
    ))
}

/// 今日任务数。
pub async fn task_today(state: &AppState, project_id: Option<u64>) -> Result<i64, ApiError> {
    let mut query = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_task WHERE created_at >= CURRENT_DATE",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    Ok(query.fetch_one(&state.db).await?)
}

/// 去重命中数。
pub async fn dedupe_hits(state: &AppState, project_id: Option<u64>) -> Result<i64, ApiError> {
    let mut query = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_task WHERE dedupe_flag = 'DUPLICATED'",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    Ok(query.fetch_one(&state.db).await?)
}

/// 死信数。
pub async fn dead_letters(state: &AppState, project_id: Option<u64>) -> Result<i64, ApiError> {
    let mut query =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_task WHERE status = 'DEAD_LETTER'");
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    Ok(query.fetch_one(&state.db).await?)
}

/// 队列积压（按状态统计的待处理任务数）。
pub async fn backlog(state: &AppState, project_id: Option<u64>) -> Result<i64, ApiError> {
    let mut query = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_task
          WHERE status IN ('RECEIVED', 'LOCKED', 'QUEUED', 'WAITING_QUOTA', 'PROCESSING',
                           'RULE_EVALUATING', 'MEDIA_REVIEWING', 'ROUTING')",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    Ok(query.fetch_one(&state.db).await?)
}

/// 耗时分位（毫秒）。
pub async fn duration_percentiles(
    state: &AppState,
    project_id: Option<u64>,
) -> Result<(i64, i64, i64), ApiError> {
    let mut query = sqlx::query(
        "SELECT
            COALESCE(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms), 0) AS p50,
            COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms), 0) AS p95,
            COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms), 0) AS p99
           FROM audit_task WHERE duration_ms IS NOT NULL",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    let row = query.fetch_one(&state.db).await?;
    Ok((
        row.get::<Option<f64>, _>("p50").unwrap_or(0.0).round() as i64,
        row.get::<Option<f64>, _>("p95").unwrap_or(0.0).round() as i64,
        row.get::<Option<f64>, _>("p99").unwrap_or(0.0).round() as i64,
    ))
}

/// 动作执行统计。
pub async fn action_counts(
    state: &AppState,
    project_id: Option<u64>,
) -> Result<(i64, i64), ApiError> {
    let mut query = sqlx::query(
        "SELECT COUNT(*) AS total,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed
           FROM action_exec_log WHERE 1 = 1",
    );
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    let row = query.fetch_one(&state.db).await?;
    Ok((
        row.get::<Option<i64>, _>("total").unwrap_or(0),
        row.get::<Option<i64>, _>("failed").unwrap_or(0),
    ))
}

/// 时间序列（按小时聚合最近 N 小时）。
pub async fn series(
    state: &AppState,
    project_id: Option<u64>,
    hours: i64,
) -> Result<Vec<SeriesPoint>, ApiError> {
    let mut query = sqlx::query(
        "SELECT
            DATE_FORMAT(created_at, '%Y-%m-%dT%H:00:00Z') AS bucket,
            SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS pass,
            SUM(CASE WHEN result = 'REJECT' THEN 1 ELSE 0 END) AS reject,
            SUM(CASE WHEN result = 'REVIEW' THEN 1 ELSE 0 END) AS review,
            SUM(CASE WHEN status IN ('FAILED', 'DEAD_LETTER') THEN 1 ELSE 0 END) AS failed
           FROM audit_task
          WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
          GROUP BY bucket ORDER BY bucket ASC",
    )
    .bind(hours);
    if let Some(value) = project_id {
        query = query.bind(value);
    }
    let rows = query.fetch_all(&state.db).await?;

    Ok(rows
        .into_iter()
        .map(|row| SeriesPoint {
            ts: row.get::<String, _>("bucket"),
            pass: row.get::<Option<i64>, _>("pass").unwrap_or(0),
            reject: row.get::<Option<i64>, _>("reject").unwrap_or(0),
            review: row.get::<Option<i64>, _>("review").unwrap_or(0),
            failed: row.get::<Option<i64>, _>("failed").unwrap_or(0),
        })
        .collect())
}

/// 项目健康度列表。
pub async fn project_health(
    state: &AppState,
    visible_projects: Option<&[u64]>,
) -> Result<Vec<ProjectHealth>, ApiError> {
    let rows = sqlx::query(
        "SELECT p.id, p.name,
                (SELECT COUNT(*) FROM audit_task t WHERE t.project_id = p.id) AS task_total,
                (SELECT COUNT(*) FROM audit_task t
                  WHERE t.project_id = p.id
                    AND t.status IN ('QUEUED', 'WAITING_QUOTA', 'PROCESSING', 'RECEIVED')) AS backlog,
                (SELECT COUNT(*) FROM audit_task t
                  WHERE t.project_id = p.id AND t.status IN ('FAILED', 'DEAD_LETTER')) AS failed
           FROM project p
          WHERE p.deleted_at IS NULL AND p.status <> 'DELETED'
          ORDER BY p.id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let project_id = row.get::<u64, _>("id");
        if let Some(scope) = visible_projects
            && !scope.contains(&project_id)
        {
            continue;
        }
        let task_total = row.get::<Option<i64>, _>("task_total").unwrap_or(0);
        let failed = row.get::<Option<i64>, _>("failed").unwrap_or(0);
        let backlog = row.get::<Option<i64>, _>("backlog").unwrap_or(0);
        let error_rate = if task_total > 0 {
            failed as f64 / task_total as f64
        } else {
            0.0
        };
        let health = if backlog > 1000 || error_rate > 0.1 {
            "CRITICAL"
        } else if backlog > 100 || error_rate > 0.02 {
            "WARNING"
        } else {
            "HEALTHY"
        };
        result.push(ProjectHealth {
            project_id,
            project_name: row.get("name"),
            health: health.to_string(),
            task_total,
            backlog,
            error_rate,
            mysql_pool_in_use: 0,
            redis_conn_in_use: 0,
        });
    }
    Ok(result)
}

/// 活跃告警。
pub async fn active_alerts(state: &AppState, limit: i64) -> Result<Vec<AlertEventRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, project_id, rule_id, name, level, status, message, value, started_at,
                resolved_at, created_at
           FROM alert_event WHERE status = 'FIRING'
          ORDER BY started_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| AlertEventRow {
            id: row.get("id"),
            project_id: row.get("project_id"),
            rule_id: row.get("rule_id"),
            name: row.get("name"),
            level: row.get("level"),
            status: row.get("status"),
            message: row.get("message"),
            value: row.get("value"),
            started_at: row.get("started_at"),
            resolved_at: row.get("resolved_at"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// 站内通知。
pub async fn notifications(
    state: &AppState,
    user_id: Option<u64>,
    offset: u64,
    limit: u64,
) -> Result<(Vec<crate::models::ops::NotificationRow>, u64), ApiError> {
    let count_query = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM notification WHERE (user_id IS NULL OR user_id = ?)",
    )
    .bind(user_id.unwrap_or(0));
    let total = count_query.fetch_one(&state.db).await?;

    let list_query = sqlx::query(
        "SELECT id, user_id, project_id, category, title, content, link, read_at, created_at
           FROM notification
          WHERE (user_id IS NULL OR user_id = ?)
          ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(user_id.unwrap_or(0))
    .bind(limit)
    .bind(offset);
    let rows = list_query.fetch_all(&state.db).await?;

    let items = rows
        .into_iter()
        .map(|row| crate::models::ops::NotificationRow {
            id: row.get("id"),
            user_id: row.get("user_id"),
            project_id: row.get("project_id"),
            category: row.get("category"),
            title: row.get("title"),
            content: row.get("content"),
            link: row.get("link"),
            read_at: row.get("read_at"),
            created_at: row.get("created_at"),
        })
        .collect();

    Ok((items, total as u64))
}
