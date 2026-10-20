//! 后台 Worker：消费 Redis Stream 队列并执行审核流水线。
//!
//! 结构：
//!
//! - 调度器每 3 秒扫一次「已启用且有触发源的审核定义」，按项目分组，
//!   每个审核起一个消费任务；调度消息走 `mpsc` 通道串行处理，避免重复起 Worker。
//! - 消费用 Redis Stream：键 `audit:{pid}:queue:{audit_code}`，
//!   消费组 `cg_{audit_code}`，`XREADGROUP` 批量拉取（批量大小取触发源配置，1~32）。
//! - 解析失败的消息写入消费错误记录并投递到 `audit:{pid}:queue:{audit_code}:dlq`，
//!   不阻塞后续消息。
//! - PEL 里超时未确认的消息用 `XAUTOCLAIM` 重新分配。
//! - 并发控制：项目级信号量（`resource_quota.max_concurrency`）+
//!   审核级信号量（`audit_definition.concurrency`）。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use actix_web::web;
use redis::streams::{StreamAutoClaimReply, StreamReadReply};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc};

use crate::db::AppState;
use crate::engine::pipeline::{self, AuditSnapshot, PipelineInput};
use crate::error::ApiError;
use crate::models::audit::{AuditConfigSnapshot, ResultRouteRow, ResultRouteView};
use crate::models::common::MediaItem;
use crate::models::rule::{ActionSpec, RuleGroupSpec, RuleItemSpec};
use crate::models::task::TaskCommand;

/// 调度扫描间隔（秒）。
const SCAN_INTERVAL_SEC: u64 = 3;
/// 单次拉取消息的上限。
const MAX_BATCH: usize = 32;
/// 单次拉取的默认批量大小。
const DEFAULT_BATCH: usize = 8;
/// PEL 空闲超时（毫秒）：超过这个时间没确认的消息会被重新分配。
const PEL_IDLE_MS: usize = 60_000;
/// 拉取阻塞时间（毫秒）。
const READ_BLOCK_MS: usize = 1_000;
/// 扫描查询结果行。
#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditWorkerRow {
    audit_id: u64,
    project_id: u64,
    code: String,
    concurrency: i32,
    trigger_id: u64,
    trigger_name: String,
    config_json: Value,
}

/// Worker 标识：项目 + 审核编码。
type WorkerKey = (u64, String);

/// 单个消费任务的配置。
#[derive(Clone)]
struct WorkerSpec {
    state: AppState,
    project_id: u64,
    audit_id: u64,
    audit_code: String,
    trigger_id: u64,
    trigger_name: String,
    batch_size: usize,
    project_sem: Arc<Semaphore>,
    audit_sem: Arc<Semaphore>,
}

/// 调度消息。
enum ScheduleMsg {
    /// 确保某个审核有消费任务。
    Ensure { key: WorkerKey, spec: WorkerSpec },
    /// 停掉某个审核的消费任务。
    Stop { key: WorkerKey },
}

/// 队列消息体。
#[derive(Debug, Clone, serde::Deserialize)]
struct QueueMessage {
    #[serde(default)]
    msg_id: Option<String>,
    #[serde(default)]
    biz_key: Option<String>,
    #[serde(default)]
    media: Vec<MediaItem>,
    #[serde(default)]
    ext: Value,
    #[serde(default)]
    callback: Option<Value>,
    #[serde(default)]
    submit_at: Option<i64>,
}

/// 启动后台 Worker。进程启动时调用一次。
pub fn spawn_workers(state: web::Data<AppState>) {
    let state = state.get_ref().clone();
    tokio::spawn(async move {
        let scheduler = Scheduler::new(state);
        scheduler.run().await;
    });
}

/// 调度器：扫描审核定义并维护消费任务。
struct Scheduler {
    state: AppState,
    /// 项目级信号量：同一项目下所有审核共享。
    project_sems: HashMap<u64, Arc<Semaphore>>,
}

impl Scheduler {
    fn new(state: AppState) -> Self {
        Self {
            state,
            project_sems: HashMap::new(),
        }
    }

    /// 调度主循环。
    async fn run(mut self) {
        let (tx, mut rx) = mpsc::channel::<ScheduleMsg>(128);

        // 单独一个任务持有消费任务集合：所有启停都通过通道串行下发，
        // 保证同一审核不会起两个消费任务。
        let _owner = tokio::spawn(async move {
            let mut workers: HashMap<WorkerKey, tokio::task::JoinHandle<()>> = HashMap::new();
            while let Some(message) = rx.recv().await {
                match message {
                    ScheduleMsg::Ensure { key, spec } => {
                        if workers.contains_key(&key) {
                            continue;
                        }
                        let handle = tokio::spawn(consume_loop(spec));
                        workers.insert(key, handle);
                    }
                    ScheduleMsg::Stop { key } => {
                        if let Some(handle) = workers.remove(&key) {
                            handle.abort();
                        }
                    }
                }
            }
        });

        let mut running: HashSet<WorkerKey> = HashSet::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(SCAN_INTERVAL_SEC));

        loop {
            ticker.tick().await;

            if !self.state.redis_available() {
                tracing::warn!("Redis 不可用，跳过队列消费");
                continue;
            }

            let desired = match self.scan().await {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(error = %err, "扫描可消费的审核定义失败");
                    continue;
                }
            };

            let desired_keys: HashSet<WorkerKey> = desired.keys().cloned().collect();

            // 不再需要的审核：停掉消费任务。
            let stale: Vec<WorkerKey> = running
                .iter()
                .filter(|key| !desired_keys.contains(*key))
                .cloned()
                .collect();
            for key in stale {
                let _ = tx.send(ScheduleMsg::Stop { key: key.clone() }).await;
                running.remove(&key);
            }

            // 新上线的审核：起消费任务。
            for (key, spec) in desired {
                if running.contains(&key) {
                    continue;
                }
                if tx
                    .send(ScheduleMsg::Ensure {
                        key: key.clone(),
                        spec,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                running.insert(key);
            }
        }
    }

    /// 扫描已启用且有触发源的审核定义。
    async fn scan(&mut self) -> Result<HashMap<WorkerKey, WorkerSpec>, ApiError> {
        let rows = sqlx::query_as::<_, AuditWorkerRow>(
            "SELECT a.id AS audit_id, a.project_id, a.code, a.concurrency,
                    t.id AS trigger_id, t.name AS trigger_name, t.config_json
               FROM audit_definition a
               JOIN trigger_source t
                 ON t.audit_id = a.id AND t.deleted_at IS NULL AND t.status = 'ACTIVE'
              WHERE a.deleted_at IS NULL AND a.status = 'ACTIVE'
              ORDER BY a.project_id, a.code, t.priority ASC",
        )
        .fetch_all(&self.state.db)
        .await?;

        let mut result: HashMap<WorkerKey, WorkerSpec> = HashMap::new();
        for row in rows {
            let key = (row.project_id, row.code.clone());
            if result.contains_key(&key) {
                // 同一个审核多个触发源时只起一个消费任务。
                continue;
            }

            let batch_size = row
                .config_json
                .get("batch_size")
                .and_then(Value::as_i64)
                .unwrap_or(DEFAULT_BATCH as i64)
                .clamp(1, MAX_BATCH as i64) as usize;

            let project_concurrency = self.project_concurrency(row.project_id).await.unwrap_or(50);
            let audit_concurrency = row.concurrency.max(1) as usize;

            let project_sem = self
                .project_sems
                .entry(row.project_id)
                .or_insert_with(|| Arc::new(Semaphore::new(project_concurrency.max(1))))
                .clone();

            result.insert(
                key,
                WorkerSpec {
                    state: self.state.clone(),
                    project_id: row.project_id,
                    audit_id: row.audit_id,
                    audit_code: row.code,
                    trigger_id: row.trigger_id,
                    trigger_name: row.trigger_name,
                    batch_size,
                    project_sem,
                    audit_sem: Arc::new(Semaphore::new(audit_concurrency)),
                },
            );
        }
        Ok(result)
    }

    /// 项目级并发上限。
    async fn project_concurrency(&self, project_id: u64) -> Result<usize, ApiError> {
        let quota =
            crate::modules::audit::repositories::load_quota(&self.state, project_id).await?;
        Ok(quota.max_concurrency.max(1) as usize)
    }
}

/// 消费循环：拉取消息 → 执行流水线 → 确认。
async fn consume_loop(spec: WorkerSpec) {
    let state = spec.state.clone();
    let group = consumer_group(&spec.audit_code);
    let queue = queue_key(spec.project_id, &spec.audit_code);
    let consumer = format!("{}-{}", worker_instance(), spec.audit_code);

    if let Err(err) = ensure_group(&state, &queue, &group).await {
        tracing::error!(error = %err, queue = %queue, "创建消费组失败");
        return;
    }

    tracing::info!(queue = %queue, group = %group, "队列消费任务已启动");

    loop {
        if !state.redis_available() {
            tracing::warn!("Redis 不可用，暂停消费");
            tokio::time::sleep(Duration::from_secs(SCAN_INTERVAL_SEC)).await;
            continue;
        }

        // 先回收 PEL 里超时未确认的消息。
        if let Err(err) = reclaim_pending(&state, &spec, &queue, &group, &consumer).await {
            tracing::warn!(error = %err, "回收超时消息失败");
        }

        match read_group(&state, &queue, &group, &consumer, spec.batch_size).await {
            Ok(Some(entries)) => {
                for entry in entries {
                    handle_entry(&state, &spec, &queue, &group, entry).await;
                }
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(error = %err, queue = %queue, "拉取队列消息失败");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// 确保消费组存在。
async fn ensure_group(state: &AppState, queue: &str, group: &str) -> Result<(), ApiError> {
    let Some(mut conn) = state.redis.clone() else {
        return Err(ApiError::internal("Redis 不可用"));
    };
    let result = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(queue)
        .arg(group)
        .arg("0")
        .arg("MKSTREAM")
        .query_async::<String>(&mut conn)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            let text = err.to_string();
            if text.contains("BUSYGROUP") {
                Ok(())
            } else {
                Err(ApiError::internal(format!("创建消费组失败：{text}")))
            }
        }
    }
}

/// 拉取一批消息。
async fn read_group(
    state: &AppState,
    queue: &str,
    group: &str,
    consumer: &str,
    batch_size: usize,
) -> Result<Option<Vec<redis::streams::StreamId>>, ApiError> {
    let Some(mut conn) = state.redis.clone() else {
        return Err(ApiError::internal("Redis 不可用"));
    };
    let reply = redis::cmd("XREADGROUP")
        .arg("GROUP")
        .arg(group)
        .arg(consumer)
        .arg("COUNT")
        .arg(batch_size.clamp(1, MAX_BATCH))
        .arg("BLOCK")
        .arg(READ_BLOCK_MS)
        .arg("STREAMS")
        .arg(queue)
        .arg(">")
        .query_async::<StreamReadReply>(&mut conn)
        .await
        .map_err(|err| ApiError::internal(format!("拉取队列消息失败：{err}")))?;

    let mut entries = Vec::new();
    for key in reply.keys {
        entries.extend(key.ids);
    }
    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(entries))
    }
}

/// 回收 PEL 里超时未确认的消息。
async fn reclaim_pending(
    state: &AppState,
    spec: &WorkerSpec,
    queue: &str,
    group: &str,
    consumer: &str,
) -> Result<(), ApiError> {
    let Some(mut conn) = state.redis.clone() else {
        return Err(ApiError::internal("Redis 不可用"));
    };
    let reply = redis::cmd("XAUTOCLAIM")
        .arg(queue)
        .arg(group)
        .arg(consumer)
        .arg(PEL_IDLE_MS)
        .arg("0-0")
        .arg("COUNT")
        .arg(spec.batch_size.clamp(1, MAX_BATCH))
        .query_async::<StreamAutoClaimReply>(&mut conn)
        .await
        .map_err(|err| ApiError::internal(format!("回收超时消息失败：{err}")))?;

    if reply.claimed.is_empty() {
        return Ok(());
    }
    for entry in reply.claimed {
        handle_entry(state, spec, queue, group, entry).await;
    }
    Ok(())
}

/// 处理一条消息。
async fn handle_entry(
    state: &AppState,
    spec: &WorkerSpec,
    queue: &str,
    group: &str,
    entry: redis::streams::StreamId,
) {
    let raw = entry.get::<String>("payload").unwrap_or_default();
    let parsed: Result<QueueMessage, _> = serde_json::from_str(&raw);

    let message = match parsed {
        Ok(value) => value,
        Err(err) => {
            // 解析失败：写错误记录 + 投死信队列，不阻塞后续消息。
            tracing::warn!(error = %err, entry = %entry.id, "队列消息解析失败");
            write_consume_log(
                state,
                spec,
                Some(&entry.id),
                "FAILED",
                Some(&err.to_string()),
            )
            .await;
            push_to_dlq(state, spec, queue, &raw, &err.to_string()).await;
            ack(state, queue, group, &entry.id).await;
            return;
        }
    };

    if message
        .biz_key
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
        && message.media.is_empty()
    {
        let reason = "消息缺少 biz_key 与媒体内容".to_string();
        tracing::warn!(entry = %entry.id, "队列消息内容为空");
        write_consume_log(state, spec, Some(&entry.id), "FAILED", Some(&reason)).await;
        push_to_dlq(state, spec, queue, &raw, &reason).await;
        ack(state, queue, group, &entry.id).await;
        return;
    }

    // 项目级 + 审核级并发控制。
    let project_permit = spec.project_sem.clone().acquire_owned().await;
    let Ok(project_permit) = project_permit else {
        return;
    };
    let audit_permit = spec.audit_sem.clone().acquire_owned().await;
    let Ok(audit_permit) = audit_permit else {
        return;
    };

    let snapshot = match load_snapshot(state, spec.audit_id).await {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, audit_id = spec.audit_id, "加载审核配置失败");
            write_consume_log(
                state,
                spec,
                Some(&entry.id),
                "FAILED",
                Some(&err.to_string()),
            )
            .await;
            push_to_dlq(state, spec, queue, &raw, &err.to_string()).await;
            ack(state, queue, group, &entry.id).await;
            return;
        }
    };

    let command = TaskCommand {
        project_id: spec.project_id,
        audit_id: spec.audit_id,
        source_type: "REDIS".to_string(),
        source_id: Some(spec.trigger_id),
        biz_key: message.biz_key.clone(),
        media: message.media.clone(),
        ext: message.ext.clone(),
        callback_url: message
            .callback
            .as_ref()
            .and_then(|item| item.get("url"))
            .and_then(Value::as_str)
            .map(|text| text.to_string()),
        dedupe_key: None,
        sync_wait_ms: None,
        trace_id: message.msg_id.clone(),
    };

    tracing::debug!(
        project_id = spec.project_id,
        audit_id = spec.audit_id,
        trigger = %spec.trigger_name,
        msg_id = ?message.msg_id,
        submit_at = ?message.submit_at,
        "开始处理队列消息"
    );

    let input = PipelineInput {
        command,
        audit: snapshot.clone(),
        audit_rules: snapshot.rules.clone(),
        routes: snapshot.routes.clone(),
    };

    let started = std::time::Instant::now();
    match pipeline::run_pipeline(state, input).await {
        Ok(outcome) => {
            let cost = started.elapsed().as_millis() as i64;
            write_consume_log(state, spec, Some(&entry.id), "SUCCESS", None).await;
            tracing::info!(
                entry = %entry.id,
                task_id = outcome.task_id,
                result = %outcome.result,
                cost_ms = cost,
                "审核任务执行完成"
            );
            ack(state, queue, group, &entry.id).await;
        }
        Err(err) => {
            let cost = started.elapsed().as_millis() as i64;
            tracing::error!(error = %err, entry = %entry.id, cost_ms = cost, "审核任务执行失败");
            write_consume_log(
                state,
                spec,
                Some(&entry.id),
                "FAILED",
                Some(&err.to_string()),
            )
            .await;
            // 不确认：消息留在 PEL 里，超时后由 XAUTOCLAIM 重新分配重试。
        }
    }

    drop(audit_permit);
    drop(project_permit);
}

/// 确认消息。
async fn ack(state: &AppState, queue: &str, group: &str, id: &str) {
    let Some(mut conn) = state.redis.clone() else {
        return;
    };
    if let Err(err) = redis::cmd("XACK")
        .arg(queue)
        .arg(group)
        .arg(id)
        .query_async::<i64>(&mut conn)
        .await
    {
        tracing::warn!(error = %err, id = %id, "确认消息失败");
    }
}

/// 投递到死信队列。
async fn push_to_dlq(state: &AppState, spec: &WorkerSpec, queue: &str, raw: &str, reason: &str) {
    let Some(mut conn) = state.redis.clone() else {
        return;
    };
    let dlq = dlq_key(spec.project_id, &spec.audit_code);
    let result = redis::cmd("XADD")
        .arg(&dlq)
        .arg("*")
        .arg("reason")
        .arg(reason)
        .arg("payload")
        .arg(raw)
        .query_async::<String>(&mut conn)
        .await;
    if let Err(err) = result {
        tracing::error!(error = %err, dlq = %dlq, "投递死信失败");
    }
    tracing::warn!(queue = %queue, dlq = %dlq, reason = %reason, "消息已投递到死信队列");
}

/// 写一条触发源消费记录。
async fn write_consume_log(
    state: &AppState,
    spec: &WorkerSpec,
    message_id: Option<&str>,
    status: &str,
    error_message: Option<&str>,
) {
    let result = sqlx::query(
        "INSERT INTO trigger_consume_log
            (id, project_id, audit_id, trigger_id, message_id, status, duration_ms,
             error_message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.ids.next_id())
    .bind(spec.project_id)
    .bind(spec.audit_id)
    .bind(spec.trigger_id)
    .bind(message_id)
    .bind(status)
    .bind(0_i32)
    .bind(error_message.map(|text| text.chars().take(500).collect::<String>()))
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await;

    if let Err(err) = result {
        tracing::error!(error = %err, "写消费记录失败");
    }
}

/// 加载审核配置快照：规则与路由以表里的最新数据为准。
pub async fn load_snapshot(state: &AppState, audit_id: u64) -> Result<AuditSnapshot, ApiError> {
    let row = crate::modules::audit::repositories::find_audit(state, audit_id).await?;
    let config: AuditConfigSnapshot = row
        .config_json
        .as_ref()
        .and_then(|value| serde_json::from_value::<AuditConfigSnapshot>(value.clone()).ok())
        .unwrap_or_default();

    let rules = load_rules(state, audit_id).await?;
    let routes = load_routes(state, audit_id).await?;

    let retry_max = row
        .retry_policy
        .as_ref()
        .and_then(|value| value.get("max_attempts"))
        .and_then(Value::as_i64)
        .unwrap_or(3) as i32;

    let media_types = row
        .media_types
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|text| text.to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(AuditSnapshot {
        id: row.id,
        code: row.code,
        name: row.name,
        media_types,
        timeout_ms: row.timeout_ms as i64,
        dedupe_window_sec: row.dedupe_window_sec as i64,
        media_hash_in_key: row.media_hash_in_key,
        default_result: config.default_result,
        on_model_fail: config.on_model_fail,
        media_review: config.media_review,
        rules,
        routes,
        concurrency: row.concurrency as i64,
        retry_max,
    })
}

/// 从规则表加载规则组。
async fn load_rules(state: &AppState, audit_id: u64) -> Result<Vec<RuleGroupSpec>, ApiError> {
    let rows = crate::modules::audit::repositories::list_rules(state, audit_id).await?;
    let rule_ids: Vec<u64> = rows.iter().map(|item| item.id).collect();
    let item_map =
        crate::modules::audit::repositories::list_rule_items_for_rules(state, &rule_ids).await?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let items = item_map
            .get(&row.id)
            .map(|list| {
                list.iter()
                    .map(|item| RuleItemSpec {
                        field: item.field.clone(),
                        operator: item.operator.clone(),
                        value: item.value_json.clone(),
                        case_sensitive: item.case_sensitive,
                        negate: item.negate,
                        sort_order: item.sort_order,
                    })
                    .collect()
            })
            .unwrap_or_default();
        result.push(RuleGroupSpec {
            id: Some(row.id),
            name: row.name,
            priority: row.priority,
            logic: row.logic,
            stop_on_hit: row.stop_on_hit,
            on_hit_result: row.on_hit_result,
            status: Some(row.status),
            items,
        });
    }
    Ok(result)
}

/// 从路由表加载结果路由。
async fn load_routes(
    state: &AppState,
    audit_id: u64,
) -> Result<HashMap<String, ResultRouteView>, ApiError> {
    let rows = crate::modules::audit::repositories::list_routes(state, audit_id).await?;
    let mut result = HashMap::new();
    for row in rows {
        result.insert(row.result_type.clone(), to_route_view(row));
    }
    Ok(result)
}

/// 路由行转视图。
fn to_route_view(row: ResultRouteRow) -> ResultRouteView {
    let actions: Vec<ActionSpec> =
        serde_json::from_value(row.actions_json.clone()).unwrap_or_default();
    ResultRouteView {
        id: Some(row.id),
        result_type: row.result_type,
        exec_mode: row.exec_mode,
        on_error: row.on_error,
        actions,
        status: Some(row.status),
    }
}

/// 消费组名。
fn consumer_group(audit_code: &str) -> String {
    format!("cg_{audit_code}")
}

/// 队列键。
fn queue_key(project_id: u64, audit_code: &str) -> String {
    format!("audit:{project_id}:queue:{audit_code}")
}

/// 死信队列键。
fn dlq_key(project_id: u64, audit_code: &str) -> String {
    format!("audit:{project_id}:queue:{audit_code}:dlq")
}

/// 进程级 Worker 实例 ID。
fn worker_instance() -> &'static str {
    static INSTANCE: OnceLock<String> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let raw = uuid::Uuid::new_v4().simple().to_string();
        raw[..8].to_string()
    })
}

/// 便于外部引用：构造一条队列消息（测试与开放 API 复用同一格式）。
pub fn build_queue_message(biz_key: Option<&str>, media: &[MediaItem], ext: &Value) -> Value {
    json!({
        "msg_id": uuid::Uuid::new_v4().to_string(),
        "biz_key": biz_key,
        "media": media,
        "ext": ext,
        "callback": Value::Null,
        "submit_at": crate::common::time::now_ms(),
    })
}
