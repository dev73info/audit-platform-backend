//! audit-platform 后端库入口。
//!
//! 业务代码全部挂在这个库里：`main.rs` 只做启动装配，`bin/migrate.rs` 做数据库迁移。

pub mod common;
pub mod db;
pub mod engine;
pub mod error;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod modules;
pub mod response;
pub mod security;
pub mod settings;
pub mod trace;
