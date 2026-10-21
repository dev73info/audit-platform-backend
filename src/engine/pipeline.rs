//! 审核流水线：端到端 12 步。
//!
//! 步骤：接收 → 鉴权校验 → 生成 dedupe_key → 幂等锁 → 建任务 → 入队 →
//! 内容拉取 → 规则执行 → 媒体审核 → 结果判定 → 动作执行 → 收尾。
//!
//! 关键约定：
//!
//! - `status`（流程状态）与 `result`（审核结论）分离：判 REJECT 的任务终态仍是 SUCCESS。
//! - 幂等三层：Redis 锁（`SET NX EX`）、Redis 幂等标记（窗口内命中即重复）、
//!   `idempotency_record` 唯一索引（Redis 不可用时的降级兜底）。
//! - 锁处理中每 60 秒续租，结束时用 Lua 校验 value 后再删除。

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use chrono::Timelike;
use redis::Script;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::common::enums::{DedupeFlag, TaskResult, TaskStatus};
use crate::db::AppState;
use crate::engine::action;
use crate::engine::media;
use crate::engine::rule;
use crate::engine::template::TemplateContext;
use crate::error::ApiError;
use crate::models::audit::ResultRouteView;
use crate::models::common::{TaskPayload, media_types};
use crate::models::rule::{EvalContext, RuleGroupSpec, RuleGroupTrace};
use crate::models::task::TaskCommand;

/// 幂等锁存活时间（秒）。
const LOCK_TTL_SEC: i64 = 300;
/// 幂等锁续租间隔（秒）：TTL / 5。
const LOCK_RENEW_SEC: u64 = 60;
/// 默认最大重试次数。
const DEFAULT_RETRY_MAX: i32 = 3;
/// 默认去重窗口（秒）。
const DEFAULT_DEDUPE_WINDOW_SEC: i64 = 86_400;

/// 释放锁的 Lua：只有 value 一致才删除，避免误删别人的锁。
const RELEASE_SCRIPT: &str =
    "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end";
/// 续租的 Lua：只有 value 一致才刷新 TTL。
const RENEW_SCRIPT: &str = "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('expire',KEYS[1],ARGV[2]) else return 0 end";

/// 审核定义快照：执行期不再读配置，保证一次执行看到的是同一份配置。
#[derive(Debug, Clone)]
pub struct AuditSnapshot {
    pub id: u64,
    pub code: String,
    pub name: String,
    pub media_types: Vec<String>,
    pub timeout_ms: i64,
    pub dedupe_window_sec: i64,
    pub media_hash_in_key: bool,
    pub default_result: String,
    pub on_model_fail: String,
    pub media_review: Value,
    pub rules: Vec<RuleGroupSpec>,
    pub routes: HashMap<String, ResultRouteView>,
    pub concurrency: i64,
    /// 最大重试次数。
    pub retry_max: i32,
}

impl Default for AuditSnapshot {
    fn default() -> Self {
        Self {
            id: 0,
            code: String::new(),
            name: String::new(),
            media_types: Vec::new(),
            timeout_ms: 30_000,
            dedupe_window_sec: DEFAULT_DEDUPE_WINDOW_SEC,
            media_hash_in_key: true,
            default_result: "REVIEW".to_string(),
            on_model_fail: "REVIEW".to_string(),
            media_review: json!({}),
            rules: Vec::new(),
            routes: HashMap::new(),
            concurrency: 10,
            retry_max: DEFAULT_RETRY_MAX,
        }
    }
}

/// 一次审核执行的整体上下文。
#[derive(Debug, Clone)]
pub struct PipelineInput {
    pub command: TaskCommand,
    pub audit: AuditSnapshot,
    pub audit_rules: Vec<RuleGroupSpec>,
    pub routes: HashMap<String, ResultRouteView>,
}

/// 任务执行结果。
#[derive(Debug, Clone)]
pub struct PipelineOutcome {
    pub task_id: u64,
    pub task_no: String,
    pub status: TaskStatus,
    pub result: TaskResult,
    pub rule_hit: Vec<RuleGroupTrace>,
    pub model_result: Option<Value>,
    pub duration_ms: i64,
}

/// 执行期上下文：任务行建好之后逐步填充。
#[derive(Debug, Default)]
struct RunContext {
    task_id: Option<u64>,
    task_no: String,
    project_id: u64,
    /// 最大重试次数。
    retry_max: i32,
}

/// 幂等锁句柄。
struct LockGuard {
    key: String,
    value: String,
    renew: Option<tokio::task::JoinHandle<()>>,
}

/// 抢锁结果。
enum LockState {
    /// 抢到锁。
    Acquired(LockGuard),
    /// 锁被别的 Worker 占着。
    Conflict,
    /// Redis 不可用，降级为数据库唯一索引去重。
    Degraded,
}

/// 执行一次审核流水线。
pub async fn run_pipeline(
    state: &AppState,
    input: PipelineInput,
) -> Result<PipelineOutcome, ApiError> {
    let started = Instant::now();
    let mut lock: Option<LockGuard> = None;
    let mut ctx = RunContext::default();

    let result = execute_steps(state, input, &mut lock, &mut ctx, started).await;

    // 收尾：停掉续租并释放锁（成功、失败都要走）。
    if let Some(guard) = lock.take() {
        release_lock(state, guard).await;
    }

    match result {
        Ok(mut outcome) => {
            outcome.duration_ms = started.elapsed().as_millis() as i64;
            Ok(outcome)
        }
        Err(err) => {
            handle_failure(state, &ctx, &err, started.elapsed().as_millis() as i64).await;
            Err(err)
        }
    }
}

/// 12 步主流程。
async fn execute_steps(
    state: &AppState,
    input: PipelineInput,
    lock: &mut Option<LockGuard>,
    ctx: &mut RunContext,
    started: Instant,
) -> Result<PipelineOutcome, ApiError> {
    let command = input.command;
    let audit = input.audit;
    let project_id = command.project_id;
    let audit_id = command.audit_id;
    ctx.project_id = project_id;
    ctx.retry_max = audit.retry_max.max(DEFAULT_RETRY_MAX);

    // 步骤 1：接收。
    state.metrics.inc(
        "audit_task_received_total",
        vec![("project".to_string(), project_id.to_string())],
    );

    // 步骤 2：鉴权校验（项目状态 + 审核状态）。
    check_project_active(state, project_id).await?;
    check_audit_active(state, audit_id).await?;

    // 步骤 3：生成 dedupe_key。
    let media_hash = compute_media_hash(&command.media);
    let dedupe_hash = build_dedupe_hash(
        project_id,
        audit_id,
        &command.source_type,
        command.source_id,
        command.biz_key.as_deref(),
        if audit.media_hash_in_key {
            Some(media_hash.as_str())
        } else {
            None
        },
    );

    // 步骤 4：幂等锁。
    if let Some(hash) = dedupe_hash.as_ref() {
        // 窗口内已经处理过：直接判重复，不再建任务。
        if let Some(existing) = lookup_idem_task(state, project_id, hash).await? {
            state.metrics.inc(
                "audit_dedupe_hit_total",
                vec![("project".to_string(), project_id.to_string())],
            );
            return Ok(PipelineOutcome {
                task_id: existing,
                task_no: String::new(),
                status: TaskStatus::Duplicated,
                result: TaskResult::Unknown,
                rule_hit: Vec::new(),
                model_result: None,
                duration_ms: 0,
            });
        }

        match acquire_lock(state, project_id, hash).await? {
            LockState::Acquired(guard) => *lock = Some(guard),
            LockState::Conflict => {
                state.metrics.inc(
                    "audit_lock_conflict_total",
                    vec![("project".to_string(), project_id.to_string())],
                );
                return Err(ApiError::conflict(
                    "DUPLICATED_TASK",
                    "同一内容正在处理中，请稍后重试",
                ));
            }
            LockState::Degraded => {
                // Redis 不可用：依赖 idempotency_record 的唯一索引兜底。
                tracing::warn!(project_id, "Redis 不可用，幂等去重降级为数据库唯一索引");
            }
        }
    }

    // 步骤 5：建任务。
    let media_type = primary_media_type(&command.media);
    let dedupe_flag = if dedupe_hash.is_some() {
        DedupeFlag::Normal
    } else {
        DedupeFlag::NoDedupe
    };
    let task_id = state.ids.next_id();
    let task_no = build_task_no(task_id);
    let now = chrono::Utc::now().naive_utc();
    let payload = TaskPayload {
        biz_key: command.biz_key.clone(),
        media: command.media.clone(),
        ext: command.ext.clone(),
        callback: None,
        dedupe_key: command.dedupe_key.clone(),
    };

    let insert = sqlx::query(
        "INSERT INTO audit_task
            (id, task_no, project_id, audit_id, source_type, source_id, biz_key, dedupe_hash,
             media_type, status, result, dedupe_flag, payload_json, retry_count, trace_id,
             created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(task_id)
    .bind(&task_no)
    .bind(project_id)
    .bind(audit_id)
    .bind(&command.source_type)
    .bind(command.source_id)
    .bind(&command.biz_key)
    .bind(&dedupe_hash)
    .bind(&media_type)
    .bind(TaskStatus::Queued.as_str())
    .bind(TaskResult::Unknown.as_str())
    .bind(dedupe_flag.as_str())
    .bind(serde_json::to_value(&payload)?)
    .bind(0_i32)
    .bind(&command.trace_id)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(err) = insert {
        return Err(ApiError::internal(format!("创建审核任务失败：{err}")));
    }
    ctx.task_id = Some(task_id);
    ctx.task_no = task_no.clone();

    // 幂等记录：唯一索引兜底去重。
    if let Some(hash) = dedupe_hash.as_ref() {
        let expire_at = now + chrono::Duration::seconds(audit.dedupe_window_sec.max(60));
        let record = sqlx::query(
            "INSERT INTO idempotency_record
                (id, project_id, dedupe_hash, task_id, status, expire_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(state.ids.next_id())
        .bind(project_id)
        .bind(hash)
        .bind(task_id)
        .bind("PROCESSING")
        .bind(expire_at)
        .bind(now)
        .execute(&state.db)
        .await;

        if let Err(err) = record {
            if is_unique_violation(&err) {
                // 唯一索引命中：同一内容已在处理窗口内。
                state.metrics.inc(
                    "audit_dedupe_hit_total",
                    vec![("project".to_string(), project_id.to_string())],
                );
                sqlx::query(
                    "UPDATE audit_task
                        SET status = ?, dedupe_flag = ?, updated_at = ?
                      WHERE id = ?",
                )
                .bind(TaskStatus::Duplicated.as_str())
                .bind(DedupeFlag::Duplicated.as_str())
                .bind(chrono::Utc::now().naive_utc())
                .bind(task_id)
                .execute(&state.db)
                .await?;
                return Ok(PipelineOutcome {
                    task_id,
                    task_no: String::new(),
                    status: TaskStatus::Duplicated,
                    result: TaskResult::Unknown,
                    rule_hit: Vec::new(),
                    model_result: None,
                    duration_ms: 0,
                });
            }
            return Err(ApiError::internal(format!("写幂等记录失败：{err}")));
        }
    }

    write_task_event(
        state,
        task_id,
        project_id,
        None,
        TaskStatus::Queued,
        "任务已创建",
        0,
    )
    .await?;

    // 步骤 6：入队（写 Redis Stream 队列）。
    let queue_key = format!("audit:{project_id}:queue:{}", audit.code);
    let message = json!({
        "msg_id": task_id.to_string(),
        "biz_key": command.biz_key,
        "media": command.media,
        "ext": command.ext,
        "callback": Value::Null,
        "submit_at": now.and_utc().timestamp_millis(),
    });

    if state.redis_available() {
        let Some(mut conn) = state.redis.clone() else {
            return Err(ApiError::internal("Redis 连接不可用"));
        };
        let payload_text = serde_json::to_string(&message)?;
        let added = redis::cmd("XADD")
            .arg(&queue_key)
            .arg("*")
            .arg("payload")
            .arg(&payload_text)
            .query_async::<String>(&mut conn)
            .await;
        if let Err(err) = added {
            if !state.redis_degrade_allowed() {
                tracing::error!(error = %err, queue = %queue_key, "任务入队失败");
                return Err(ApiError::internal(format!("任务入队失败：{err}")));
            }
            // 队列不可用：任务已经在库里，Worker 池稍后补消费；当前请求继续内联处理。
            tracing::warn!(error = %err, queue = %queue_key, "任务入队失败，本次请求内联处理");
        }

        // 幂等标记：窗口内重复提交直接命中。
        if let Some(hash) = dedupe_hash.as_ref() {
            let idem_key = format!("audit:{project_id}:idem:{hash}");
            let ttl = audit.dedupe_window_sec.max(60);
            if let Err(err) = redis::cmd("SET")
                .arg(&idem_key)
                .arg(task_id.to_string())
                .arg("EX")
                .arg(ttl)
                .query_async::<Option<String>>(&mut conn)
                .await
            {
                tracing::warn!(error = %err, "写幂等标记失败");
            }
        }

        // 队列积压指标。
        if let Ok(length) = redis::cmd("XLEN")
            .arg(&queue_key)
            .query_async::<i64>(&mut conn)
            .await
        {
            state.metrics.set_gauge(
                "audit_queue_backlog",
                vec![("project".to_string(), project_id.to_string())],
                length as f64,
            );
        }
    } else {
        tracing::warn!(queue = %queue_key, "Redis 不可用，任务仅落库不入队");
    }

    write_task_event(
        state,
        task_id,
        project_id,
        Some(TaskStatus::Queued),
        TaskStatus::Queued,
        "任务已入队",
        0,
    )
    .await?;

    // 步骤 7：内容拉取（整理规则求值上下文）。
    let media_text = command
        .media
        .iter()
        .filter(|item| item.media_type == "text")
        .map(|item| item.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let media_size_bytes = command
        .media
        .iter()
        .filter(|item| item.media_type == "text")
        .map(|item| item.content.len() as i64)
        .sum();
    let types = media_types(&command.media);
    let ext_map = match command.ext.clone() {
        Value::Object(fields) => fields,
        _ => serde_json::Map::new(),
    };

    let eval_context = EvalContext {
        media_text: media_text.clone(),
        media_text_len: media_text.chars().count(),
        media_count: command.media.len(),
        media_types: types.clone(),
        media_size_bytes,
        media_hash: media_hash.clone(),
        ext: ext_map.clone(),
        model_label: None,
        model_score: None,
        model_risk_level: None,
        source_type: command.source_type.clone(),
        submit_hour: now.hour(),
    };

    transition(
        state,
        task_id,
        project_id,
        TaskStatus::Queued,
        TaskStatus::Processing,
        "内容拉取完成",
    )
    .await?;

    // 步骤 8：规则执行。
    let rules = if input.audit_rules.is_empty() {
        audit.rules.clone()
    } else {
        input.audit_rules.clone()
    };
    let (rule_result_text, traces) = rule::evaluate(&rules, &eval_context, &audit.default_result);
    transition(
        state,
        task_id,
        project_id,
        TaskStatus::Processing,
        TaskStatus::RuleEvaluating,
        "规则执行完成",
    )
    .await?;

    // 步骤 9：媒体审核。
    let media_outcome = media::review_media(
        state,
        project_id,
        audit_id,
        task_id,
        &command.media,
        &audit.media_review,
    )
    .await?;
    transition(
        state,
        task_id,
        project_id,
        TaskStatus::RuleEvaluating,
        TaskStatus::MediaReviewing,
        "媒体审核完成",
    )
    .await?;

    // 步骤 10：结果判定。
    let mut final_result = TaskResult::parse(&rule_result_text).unwrap_or(TaskResult::Unknown);
    if media_outcome.failed {
        // 模型不可用：取 on_model_fail；规则已判 REJECT 时保持 REJECT。
        if final_result != TaskResult::Reject {
            final_result = TaskResult::parse(&audit.on_model_fail).unwrap_or(TaskResult::Review);
        }
    } else if let Some(label) = media_outcome.label.as_ref() {
        if let Some(model_result) = TaskResult::parse(label) {
            if model_result != TaskResult::Unknown {
                // 规则与模型取更严的结论。
                final_result = final_result.stricter(model_result);
            }
        }
    }
    let result_text = final_result.as_str().to_string();
    transition(
        state,
        task_id,
        project_id,
        TaskStatus::MediaReviewing,
        TaskStatus::Routing,
        &format!("结论判定完成：{result_text}"),
    )
    .await?;

    // 步骤 11：动作执行。
    let routes = if input.routes.is_empty() {
        audit.routes.clone()
    } else {
        input.routes.clone()
    };
    let media_url = command
        .media
        .iter()
        .map(|item| item.url.clone())
        .find(|url| !url.is_empty())
        .unwrap_or_default();

    let template_context = TemplateContext {
        task_id,
        task_no: task_no.clone(),
        task_result: result_text.clone(),
        task_biz_key: command.biz_key.clone().unwrap_or_default(),
        media_url,
        media_text: media_text.clone(),
        model_label: media_outcome.label.clone().unwrap_or_default(),
        model_score: media_outcome.score.unwrap_or(0.0),
        ext: ext_map.clone(),
        now_ms: crate::common::time::now_ms(),
        now: crate::common::time::now_iso8601(),
    };

    let mut to_review = false;
    if let Some(route) = routes.get(&result_text) {
        let outcomes = action::execute_route_with_mode(
            state,
            project_id,
            task_id,
            &result_text,
            &route.actions,
            &route.exec_mode,
            &route.on_error,
            &template_context,
        )
        .await;
        to_review = outcomes.iter().any(|item| item.to_review);
    }
    transition(
        state,
        task_id,
        project_id,
        TaskStatus::Routing,
        TaskStatus::Routing,
        "动作执行完成",
    )
    .await?;

    // 步骤 12：收尾。
    let final_status = if to_review {
        TaskStatus::ReviewPending
    } else {
        TaskStatus::Success
    };
    let final_result = if to_review {
        TaskResult::Review
    } else {
        final_result
    };
    let model_result_json = json!({
        "label": media_outcome.label,
        "score": media_outcome.score,
        "risk_level": media_outcome.risk_level,
        "hits": media_outcome.hits,
        "failed": media_outcome.failed,
    });

    let duration_ms = started.elapsed().as_millis() as i64;
    sqlx::query(
        "UPDATE audit_task
            SET status = ?, result = ?, rule_hit_json = ?, model_result_json = ?,
                duration_ms = ?, finished_at = ?, updated_at = ?
          WHERE id = ?",
    )
    .bind(final_status.as_str())
    .bind(final_result.as_str())
    .bind(serde_json::to_value(&traces)?)
    .bind(&model_result_json)
    .bind(duration_ms as i32)
    .bind(chrono::Utc::now().naive_utc())
    .bind(chrono::Utc::now().naive_utc())
    .bind(task_id)
    .execute(&state.db)
    .await?;

    write_task_event(
        state,
        task_id,
        project_id,
        Some(TaskStatus::Routing),
        final_status,
        &format!("任务完成，结论 {final_result}"),
        duration_ms,
    )
    .await?;

    state.metrics.inc(
        "audit_task_result_total",
        vec![
            ("project".to_string(), project_id.to_string()),
            ("result".to_string(), final_result.as_str().to_string()),
        ],
    );
    state.metrics.observe(
        "audit_task_duration_seconds",
        vec![("project".to_string(), project_id.to_string())],
        duration_ms as f64 / 1000.0,
        vec![0.05, 0.1, 0.5, 1.0, 3.0, 5.0, 10.0, 30.0, 60.0, 120.0],
    );

    Ok(PipelineOutcome {
        task_id,
        task_no,
        status: final_status,
        result: final_result,
        rule_hit: traces,
        model_result: Some(model_result_json),
        duration_ms,
    })
}

// ---------------------------------------------------------------------------
// 幂等与锁
// ---------------------------------------------------------------------------

/// 抢幂等锁。
///
/// Redis 不可用（连不上、认证失败、命令报错）时**降级**为数据库唯一索引去重，
/// 只打告警不失败——单点依赖挂掉不应该让整条审核链路停摆。
async fn acquire_lock(
    state: &AppState,
    project_id: u64,
    hash: &str,
) -> Result<LockState, ApiError> {
    let Some(mut conn) = state.redis.clone() else {
        tracing::warn!(project_id, "Redis 不可用，幂等锁降级为数据库唯一索引");
        return Ok(LockState::Degraded);
    };

    let key = format!("audit:{project_id}:lock:{hash}");
    let value = format!("{}:{}", worker_id(), crate::common::time::now_ms());
    let reply = redis::cmd("SET")
        .arg(&key)
        .arg(&value)
        .arg("NX")
        .arg("EX")
        .arg(LOCK_TTL_SEC)
        .query_async::<Option<String>>(&mut conn)
        .await;

    let reply = match reply {
        Ok(reply) => reply,
        Err(err) => {
            if !state.redis_degrade_allowed() {
                tracing::error!(error = %err, project_id, "抢幂等锁失败");
                return Err(ApiError::internal("抢幂等锁失败"));
            }
            tracing::warn!(error = %err, project_id, "抢幂等锁失败，降级为数据库唯一索引");
            return Ok(LockState::Degraded);
        }
    };

    match reply {
        Some(_) => {
            let handle = tokio::spawn(renew_loop(state.clone(), key.clone(), value.clone()));
            Ok(LockState::Acquired(LockGuard {
                key,
                value,
                renew: Some(handle),
            }))
        }
        None => Ok(LockState::Conflict),
    }
}

/// 续租任务：每 60 秒刷新一次 TTL。
async fn renew_loop(state: AppState, key: String, value: String) {
    let mut ticker = tokio::time::interval(Duration::from_secs(LOCK_RENEW_SEC));
    // 第一次 tick 立即返回，这里先吃掉它。
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(mut conn) = state.redis.clone() else {
            return;
        };
        let result = Script::new(RENEW_SCRIPT)
            .key(&key)
            .arg(&value)
            .arg(LOCK_TTL_SEC)
            .invoke_async::<i64>(&mut conn)
            .await;
        if let Err(err) = result {
            tracing::warn!(error = %err, "幂等锁续租失败");
        }
    }
}

/// 释放幂等锁：Lua 校验 value 一致才删除。
async fn release_lock(state: &AppState, guard: LockGuard) {
    if let Some(handle) = guard.renew {
        handle.abort();
    }
    let Some(mut conn) = state.redis.clone() else {
        return;
    };
    let result = Script::new(RELEASE_SCRIPT)
        .key(&guard.key)
        .arg(&guard.value)
        .invoke_async::<i64>(&mut conn)
        .await;
    if let Err(err) = result {
        tracing::warn!(error = %err, "释放幂等锁失败");
    }
}

/// 查幂等标记：返回窗口内已存在的任务号。
async fn lookup_idem_task(
    state: &AppState,
    project_id: u64,
    hash: &str,
) -> Result<Option<u64>, ApiError> {
    // 先看数据库记录（Redis 不可用时也能命中）。
    let row = sqlx::query(
        "SELECT task_id FROM idempotency_record
          WHERE project_id = ? AND dedupe_hash = ? AND expire_at > ?
          LIMIT 1",
    )
    .bind(project_id)
    .bind(hash)
    .bind(chrono::Utc::now().naive_utc())
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = row {
        let task_id: u64 = row.get("task_id");
        return Ok(Some(task_id));
    }

    let Some(mut conn) = state.redis.clone() else {
        return Ok(None);
    };
    let key = format!("audit:{project_id}:idem:{hash}");
    let value = redis::cmd("GET")
        .arg(&key)
        .query_async::<Option<String>>(&mut conn)
        .await
        .unwrap_or(None);
    Ok(value.and_then(|text| text.trim().parse::<u64>().ok()))
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 校验项目是否处于可用状态。
async fn check_project_active(state: &AppState, project_id: u64) -> Result<(), ApiError> {
    let status = crate::modules::audit::repositories::find_project_status(state, project_id)
        .await?
        .unwrap_or_default();
    match status.trim().to_ascii_uppercase().as_str() {
        "ACTIVE" => Ok(()),
        "PAUSED" => Err(ApiError::forbidden("PROJECT_PAUSED", "项目已暂停")),
        "DISABLED" => Err(ApiError::forbidden("PROJECT_PAUSED", "项目已禁用")),
        "" => Err(ApiError::not_found("项目不存在")),
        _ => Err(ApiError::forbidden("PROJECT_DELETED", "项目不可用")),
    }
}

/// 校验审核定义是否启用。
async fn check_audit_active(state: &AppState, audit_id: u64) -> Result<(), ApiError> {
    let row = crate::modules::audit::repositories::find_audit(state, audit_id).await?;
    if row.status.trim().eq_ignore_ascii_case("ACTIVE") {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "PERM_DENIED",
            "审核定义未启用，不接受新任务",
        ))
    }
}

/// 媒体指纹：文本取内容，图片 / 视频取 URL。
pub fn compute_media_hash(media: &[crate::models::common::MediaItem]) -> String {
    if media.is_empty() {
        return String::new();
    }
    let mut buffer = String::new();
    for item in media {
        buffer.push_str(&item.fingerprint_material());
        buffer.push('\n');
    }
    sha256_hex(buffer.as_bytes())
}

/// 生成去重键：SHA256(project_id + audit_id + source_type + source_id + biz_key + [media_hash])。
pub fn build_dedupe_hash(
    project_id: u64,
    audit_id: u64,
    source_type: &str,
    source_id: Option<u64>,
    biz_key: Option<&str>,
    media_hash: Option<&str>,
) -> Option<String> {
    let biz = biz_key.unwrap_or_default().trim();
    let media = media_hash.unwrap_or_default().trim();
    // 没有业务键也没有媒体指纹时不去重。
    if biz.is_empty() && media.is_empty() {
        return None;
    }

    let mut material = String::new();
    material.push_str(&project_id.to_string());
    material.push('|');
    material.push_str(&audit_id.to_string());
    material.push('|');
    material.push_str(source_type.trim());
    material.push('|');
    material.push_str(&source_id.map(|value| value.to_string()).unwrap_or_default());
    material.push('|');
    material.push_str(biz);
    material.push('|');
    material.push_str(media);
    Some(sha256_hex(material.as_bytes()))
}

/// SHA-256 十六进制小写。
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// 主要媒体类型。
fn primary_media_type(media: &[crate::models::common::MediaItem]) -> String {
    let types = media_types(media);
    if types.len() == 1 {
        types[0].clone()
    } else if types.iter().any(|item| item == "mixed") {
        "mixed".to_string()
    } else {
        types.first().cloned().unwrap_or_else(|| "text".to_string())
    }
}

/// 任务号：时间戳 + ID 尾数，全局唯一且可读。
fn build_task_no(task_id: u64) -> String {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    format!("T{stamp}{:04}", task_id % 10_000)
}

/// 进程级 Worker ID。
fn worker_id() -> &'static str {
    static WORKER_ID: OnceLock<String> = OnceLock::new();
    WORKER_ID.get_or_init(|| {
        let raw = uuid::Uuid::new_v4().simple().to_string();
        raw[..8].to_string()
    })
}

/// 判断是否为唯一索引冲突。
fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(inner) => inner.is_unique_violation(),
        _ => false,
    }
}

/// 状态迁移：更新任务行并写一条事件流水。
async fn transition(
    state: &AppState,
    task_id: u64,
    project_id: u64,
    from: TaskStatus,
    to: TaskStatus,
    message: &str,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now().naive_utc();
    sqlx::query("UPDATE audit_task SET status = ?, updated_at = ? WHERE id = ?")
        .bind(to.as_str())
        .bind(now)
        .bind(task_id)
        .execute(&state.db)
        .await?;
    write_task_event(state, task_id, project_id, Some(from), to, message, 0).await
}

/// 写一条任务事件流水。
async fn write_task_event(
    state: &AppState,
    task_id: u64,
    project_id: u64,
    from: Option<TaskStatus>,
    to: TaskStatus,
    message: &str,
    cost_ms: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO task_event
            (id, task_id, project_id, from_status, to_status, message, cost_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(task_id)
    .bind(project_id)
    .bind(from.map(|item| item.as_str().to_string()))
    .bind(to.as_str())
    .bind(message)
    .bind(cost_ms as i32)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// 失败处理：可重试则回到 QUEUED，重试耗尽则 FAILED → DEAD_LETTER。
async fn handle_failure(state: &AppState, ctx: &RunContext, err: &ApiError, duration_ms: i64) {
    let Some(task_id) = ctx.task_id else {
        tracing::error!(error = %err, "任务在建表前失败");
        return;
    };

    let retry_max = ctx.retry_max.max(DEFAULT_RETRY_MAX);
    let current =
        sqlx::query_scalar::<_, i32>("SELECT retry_count FROM audit_task WHERE id = ? LIMIT 1")
            .bind(task_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
    let next_retry = current + 1;
    let exhausted = next_retry > retry_max;
    let status = if exhausted {
        TaskStatus::DeadLetter
    } else {
        TaskStatus::Queued
    };

    let result = sqlx::query(
        "UPDATE audit_task
            SET status = ?, retry_count = ?, error_code = ?, error_message = ?, updated_at = ?
          WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(next_retry)
    .bind(err.code())
    .bind(truncate_error(&err.to_string()))
    .bind(chrono::Utc::now().naive_utc())
    .bind(task_id)
    .execute(&state.db)
    .await;

    if let Err(db_err) = result {
        tracing::error!(error = %db_err, task_id, "回写失败状态出错");
    }

    let message = if exhausted {
        format!("任务失败且重试耗尽：{err}")
    } else {
        format!("任务失败，将重试：{err}")
    };
    if let Err(db_err) = write_task_event(
        state,
        task_id,
        ctx.project_id,
        Some(TaskStatus::Processing),
        status,
        &message,
        duration_ms,
    )
    .await
    {
        tracing::error!(error = %db_err, task_id, "写失败事件出错");
    }

    if exhausted {
        // FAILED → DEAD_LETTER：留一条终态事件，便于排查。
        if let Err(db_err) = write_task_event(
            state,
            task_id,
            ctx.project_id,
            Some(TaskStatus::Failed),
            TaskStatus::DeadLetter,
            "任务进入死信队列",
            duration_ms,
        )
        .await
        {
            tracing::error!(error = %db_err, task_id, "写死信事件出错");
        }
    }

    state.metrics.inc(
        "audit_task_result_total",
        vec![
            ("project".to_string(), ctx.project_id.to_string()),
            ("result".to_string(), "FAILED".to_string()),
        ],
    );
}

/// 错误信息截断（列宽 512）。
fn truncate_error(message: &str) -> String {
    message.chars().take(500).collect()
}
