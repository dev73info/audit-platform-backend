//! 任务域模块：任务列表、详情、重试、停止、人工复核、待议队列与导出。
//!
//! 分层：`handlers`（HTTP）→ `service`（业务编排）→ `repositories`（SQL 与外部系统）。

pub mod handlers;
pub mod repositories;
pub mod routes;
pub mod service;
