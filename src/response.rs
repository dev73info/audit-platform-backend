//! 统一响应封装：`{ code, message, data, trace_id, cost_ms }`。

use actix_web::web::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::trace::{current_cost_ms, current_trace_id};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: T,
    pub trace_id: String,
    pub cost_ms: u64,
}

/// handler 的统一返回类型。
pub type ApiResult<T> = Result<Json<ApiResponse<T>>, ApiError>;

/// 成功响应。
pub fn ok<T: Serialize>(data: T) -> ApiResult<T> {
    Ok(Json(ApiResponse {
        code: 0,
        message: "OK".to_string(),
        data,
        trace_id: current_trace_id(),
        cost_ms: current_cost_ms(),
    }))
}

/// 无数据体的成功响应。
pub fn ok_empty() -> ApiResult<Value> {
    ok(serde_json::Value::Null)
}

/// 列表响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: u64, page: u64, page_size: u64) -> Self {
        let has_more = page.saturating_mul(page_size) < total;
        Self {
            items,
            total,
            page,
            page_size,
            has_more,
        }
    }
}

/// 列表查询的公共入参：`page` / `page_size` / `sort` / `filter[...]` / `keyword`。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub page_size: Option<u64>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(flatten)]
    pub rest: std::collections::HashMap<String, String>,
}

impl ListQuery {
    /// 当前页码，最小 1。
    pub fn page(&self) -> u64 {
        self.page.unwrap_or(1).max(1)
    }

    /// 每页条数，取值限定 20 / 50 / 100，默认 20。
    pub fn page_size(&self) -> u64 {
        match self.page_size {
            Some(20) => 20,
            Some(50) => 50,
            Some(100) => 100,
            Some(other) if other > 0 => other.min(100),
            _ => 20,
        }
    }

    /// 偏移量。
    pub fn offset(&self) -> u64 {
        (self.page() - 1) * self.page_size()
    }

    /// 取 `filter[x]` 的值。
    pub fn filter(&self, key: &str) -> Option<&str> {
        self.rest
            .get(&format!("filter[{key}]"))
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    }

    /// 取多选筛选的值（如 `filter[status]=ACTIVE,PAUSED`）。
    pub fn filter_list(&self, key: &str) -> Vec<String> {
        self.filter(key)
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 排序字段。返回 `(字段, 是否倒序)`，字段不在白名单内则忽略。
    pub fn sort_field(&self, allowed: &[&str], default: (&str, bool)) -> (String, bool) {
        let raw = self.sort.as_deref().unwrap_or("");
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (field, desc) = match part.split_once(':') {
                Some((f, d)) => (f.trim(), d.trim().eq_ignore_ascii_case("desc")),
                None => (part, false),
            };
            if allowed.contains(&field) {
                return (field.to_string(), desc);
            }
        }
        (default.0.to_string(), default.1)
    }
}

/// 简单的 `serde_json::Value` 别名，避免在签名里到处写长路径。
pub type Value = serde_json::Value;
