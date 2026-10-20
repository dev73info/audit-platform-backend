//! 跨模块共享的 DTO。

use serde::{Deserialize, Serialize};

/// 项目配额。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectQuota {
    pub max_concurrency: i64,
    pub max_qps: i64,
    pub max_mysql_pool: i64,
    pub max_redis_conn: i64,
    pub max_media_size_mb: i64,
    pub max_daily_tasks: Option<i64>,
    pub max_api_call_per_task: i64,
}

impl Default for ProjectQuota {
    fn default() -> Self {
        Self {
            max_concurrency: 50,
            max_qps: 100,
            max_mysql_pool: 20,
            max_redis_conn: 20,
            max_media_size_mb: 50,
            max_daily_tasks: None,
            max_api_call_per_task: 10,
        }
    }
}

/// 任务携带的一条媒体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaItem {
    /// `text` / `image` / `video` / `audio`。
    #[serde(rename = "type")]
    pub media_type: String,
    /// 文本内容。
    #[serde(default)]
    pub content: String,
    /// 媒体地址。
    #[serde(default)]
    pub url: String,
    /// 视频时长（秒）。
    #[serde(default)]
    pub duration: Option<f64>,
    /// 业务方自定义扩展字段。
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl MediaItem {
    /// 媒体的指纹素材：文本取内容，图片/视频取 URL。
    pub fn fingerprint_material(&self) -> String {
        if self.media_type == "text" {
            self.content.clone()
        } else {
            self.url.clone()
        }
    }
}

/// 任务载荷（提交时的原始内容）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskPayload {
    #[serde(default)]
    pub biz_key: Option<String>,
    #[serde(default)]
    pub media: Vec<MediaItem>,
    #[serde(default)]
    pub ext: serde_json::Value,
    #[serde(default)]
    pub callback: Option<CallbackSpec>,
    /// 客户端传入的显式去重键，覆盖默认计算方式。
    #[serde(default)]
    pub dedupe_key: Option<String>,
}

/// 回调配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackSpec {
    pub url: String,
    #[serde(default)]
    pub headers: serde_json::Value,
    #[serde(default)]
    pub secret_ref: Option<String>,
}

/// 媒体的媒体类型集合。
pub fn media_types(media: &[MediaItem]) -> Vec<String> {
    let mut types: Vec<String> = Vec::new();
    for item in media {
        if !types.contains(&item.media_type) {
            types.push(item.media_type.clone());
        }
    }
    if types.len() > 1 {
        types.push("mixed".to_string());
    }
    types
}

/// 分页参数上限：深分页提示。
pub const MAX_DEEP_PAGE_OFFSET: u64 = 1000;
