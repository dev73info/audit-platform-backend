//! 时间工具：统一用 UTC 存储、ISO8601 输出。

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

/// 当前毫秒时间戳。
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// 当前时间格式化（秒级精度，ISO8601）。
pub fn now_iso8601() -> String {
    format_datetime(Utc::now().naive_utc())
}

/// 把 NaiveDateTime 格式化成 `2026-10-21T10:00:00Z`。
pub fn format_datetime(value: NaiveDateTime) -> String {
    value.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// 解析 ISO8601 / `YYYY-MM-DD HH:MM:SS` 两种写法。
pub fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(value) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(value.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(value) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(Utc.from_utc_datetime(&value));
        }
    }
    None
}

/// 把毫秒时间戳转成 ISO8601 字符串。
pub fn ms_to_iso8601(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms).single() {
        Some(value) => value.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => String::new(),
    }
}
