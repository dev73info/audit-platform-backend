//! 审核执行引擎：规则求值、参数模板、动作执行与流水线。
//!
//! 各子模块职责：
//!
//! - `rule`：规则组 DSL 求值（纯函数）。
//! - `template`：`{{变量}}` 参数模板渲染与校验（纯函数）。
//! - `action`：动作 DSL 执行（HTTP / REDIS / MYSQL / WEBHOOK / MQ）。
//! - `media`：媒体解析、指纹与下载。
//! - `pipeline`：审核流水线编排。
//! - `worker`：后台任务执行器。

pub mod action;
pub mod media;
pub mod pipeline;
pub mod rule;
pub mod template;
pub mod worker;
