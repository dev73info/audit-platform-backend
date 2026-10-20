//! 全链路追踪：每个请求一个 `trace_id`，日志、指标、审计三处都用它关联。
//!
//! 用 `tokio::task_local!` 而不是线程局部变量：actix 的一个连接会跨线程切换，
//! 线程局部变量在异步 handler 里会读不到值。

use std::time::Instant;

use uuid::Uuid;

tokio::task_local! {
    /// 当前请求的追踪上下文。非请求线程（后台任务、启动流程）读到的是默认值。
    static TRACE_CTX: TraceContext;
}

/// 追踪上下文。
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: String,
    pub start: Instant,
}

impl Default for TraceContext {
    fn default() -> Self {
        Self {
            trace_id: String::new(),
            start: Instant::now(),
        }
    }
}

impl TraceContext {
    pub fn new(trace_id: String) -> Self {
        Self {
            trace_id,
            start: Instant::now(),
        }
    }

    /// 已经过的毫秒数。
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// 生成一个新的 trace_id。
pub fn new_trace_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// 读取当前 trace_id。
pub fn current_trace_id() -> String {
    TRACE_CTX
        .try_with(|ctx| ctx.trace_id.clone())
        .unwrap_or_default()
}

/// 读取当前请求已经过的毫秒数。
pub fn current_cost_ms() -> u64 {
    TRACE_CTX.try_with(|ctx| ctx.elapsed_ms()).unwrap_or(0)
}

/// 在当前 task 的追踪作用域内执行。
pub async fn scope<F, T>(trace_id: String, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TRACE_CTX.scope(TraceContext::new(trace_id), future).await
}
