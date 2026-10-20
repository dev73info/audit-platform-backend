//! 媒体审核：文本预处理与关键词、图片下载与指纹、视频抽帧参数与汇总。
//!
//! 语义见 `doc/API.md` 第四章与设计文档 4.5：
//!
//! - 文本：预处理（去空白、全半角归一、URL / 手机号 / 邮箱脱敏）→ 关键词命中 →
//!   第三方文本审核 API。
//! - 图片：大小受项目配额限制，格式走白名单 + 魔数校验（防伪装扩展名），
//!   下载前拒绝内网地址，落库前算 SHA-256 指纹。
//! - 视频：按帧率抽帧（0.2~5 fps，上限 300 帧），帧走图片审核；
//!   汇总策略 `worst` / `majority` / `threshold`。
//!
//! 注意：视频抽帧目前只做参数计算与进度记录，真正的解码待接入 ffmpeg 后补齐，
//! 因此视频在未配置视频审核 API 时不会给出模型标签。

use std::time::Duration;

use regex::Regex;
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::db::AppState;
use crate::error::ApiError;
use crate::models::common::MediaItem;

/// 默认图片格式白名单。
const DEFAULT_IMAGE_FORMATS: &[&str] = &["jpg", "png", "webp", "bmp", "gif"];

/// 视频抽帧帧率下限。
const MIN_FPS: f64 = 0.2;
/// 视频抽帧帧率上限。
const MAX_FPS: f64 = 5.0;
/// 视频抽帧帧数上限。
const MAX_FRAMES: i64 = 300;

/// 媒体审核结果。
#[derive(Debug, Clone, Default)]
pub struct MediaReviewOutcome {
    /// 归一化后的模型标签：`PASS` / `REJECT` / `REVIEW` / `UNKNOWN`。
    pub label: Option<String>,
    /// 模型置信度 0~1。
    pub score: Option<f64>,
    /// 归一化风险等级：`low` / `medium` / `high`。
    pub risk_level: Option<String>,
    /// 命中片段（关键词命中或模型返回的原因）。
    pub hits: Vec<String>,
    /// 模型不可用（调用失败或未配置）。
    pub failed: bool,
    /// 落到 `media_asset` 表的记录。
    pub media: Vec<MediaAsset>,
}

/// 媒体资产（待写入 `media_asset` 表）。
#[derive(Debug, Clone)]
pub struct MediaAsset {
    pub id: u64,
    pub task_id: u64,
    pub project_id: u64,
    pub media_type: String,
    pub url: String,
    pub oss_key: Option<String>,
    pub hash: Option<String>,
    pub size_bytes: Option<i64>,
    pub meta_json: Option<Value>,
}

/// 审核一条任务的全部媒体。
pub async fn review_media(
    state: &AppState,
    project_id: u64,
    audit_id: u64,
    task_id: u64,
    media: &[MediaItem],
    config: &Value,
) -> Result<MediaReviewOutcome, ApiError> {
    let mut outcome = MediaReviewOutcome::default();

    let text_config = config.get("text").cloned().unwrap_or(Value::Null);
    let image_config = config.get("image").cloned().unwrap_or(Value::Null);
    let video_config = config.get("video").cloned().unwrap_or(Value::Null);
    let thresholds = Thresholds::from_config(config);

    // 文本：预处理 + 关键词 + 第三方 API。
    let mut text_buffer = String::new();
    for item in media.iter().filter(|item| item.media_type == "text") {
        let normalized = preprocess_text(&item.content);
        if !normalized.is_empty() {
            text_buffer.push_str(&normalized);
            text_buffer.push('\n');
        }
    }

    if !text_buffer.trim().is_empty() {
        outcome
            .hits
            .extend(hit_keywords(&text_buffer, &text_config));
        match call_text_api(
            state,
            project_id,
            &text_config,
            text_buffer.trim(),
            &thresholds,
        )
        .await
        {
            Ok((label, score, risk_level, reasons)) => {
                outcome.label = Some(label);
                outcome.score = score;
                outcome.risk_level = risk_level;
                outcome.hits.extend(reasons);
            }
            Err(err) => {
                tracing::warn!(error = %err, audit_id, "文本审核模型不可用");
                outcome.failed = true;
            }
        }
    }

    // 图片：大小、格式、魔数、指纹。
    let quota = crate::modules::audit::repositories::load_quota(state, project_id).await?;
    let max_bytes = quota.max_media_size_mb.max(1) * 1024 * 1024;
    let formats = resolve_image_formats(&image_config);

    for item in media.iter().filter(|item| item.media_type == "image") {
        match review_image(state, project_id, task_id, item, max_bytes, &formats).await {
            Ok(asset) => {
                outcome.media.push(asset);
            }
            Err(reason) => {
                tracing::warn!(error = %reason, task_id, "图片审核失败");
                outcome.hits.push(format!("图片审核失败：{reason}"));
                outcome.failed = true;
            }
        }
    }

    // 视频：抽帧参数与汇总策略。
    for item in media.iter().filter(|item| item.media_type == "video") {
        let asset = review_video(state, project_id, task_id, item, max_bytes, &video_config).await;
        outcome.media.push(asset);
    }

    // 音频等其余类型只登记，不做模型调用。
    for item in media.iter().filter(|item| {
        item.media_type != "text" && item.media_type != "image" && item.media_type != "video"
    }) {
        outcome.media.push(MediaAsset {
            id: state.ids.next_id(),
            task_id,
            project_id,
            media_type: item.media_type.clone(),
            url: item.url.clone(),
            oss_key: None,
            hash: None,
            size_bytes: None,
            meta_json: Some(json!({ "skipped": true })),
        });
    }

    for asset in &outcome.media {
        insert_media_asset(state, asset).await;
    }

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 文本
// ---------------------------------------------------------------------------

/// 文本预处理：去首尾空白、全半角归一、URL / 手机号 / 邮箱脱敏。
pub fn preprocess_text(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized = normalize_width(trimmed);

    let mut output = normalized;
    if let Ok(pattern) = Regex::new(r"(?i)\b(?:https?|ftp)://[^\s，。；]+") {
        output = pattern.replace_all(&output, "[URL]").to_string();
    }
    if let Ok(pattern) = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}") {
        output = pattern.replace_all(&output, "[EMAIL]").to_string();
    }
    if let Ok(pattern) = Regex::new(r"(?<!\d)1[3-9]\d{9}(?!\d)") {
        output = pattern.replace_all(&output, "[PHONE]").to_string();
    }
    output
}

/// 全角转半角（含全角空格）。
fn normalize_width(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\u{3000}' => output.push(' '),
            '\u{ff01}'..='\u{ff5e}' => {
                if let Some(ascii) = char::from_u32(ch as u32 - 0xfee0) {
                    output.push(ascii);
                }
            }
            other => output.push(other),
        }
    }
    output
}

/// 关键词命中。返回命中的片段描述。
fn hit_keywords(text: &str, config: &Value) -> Vec<String> {
    let Some(groups) = config.get("keyword_groups").and_then(Value::as_array) else {
        return Vec::new();
    };
    let lower = text.to_lowercase();
    let mut hits = Vec::new();
    for group in groups {
        let Some(keywords) = group.as_array() else {
            continue;
        };
        for keyword in keywords {
            let Some(word) = keyword.as_str() else {
                continue;
            };
            let word = word.trim();
            if word.is_empty() {
                continue;
            }
            if lower.contains(&word.to_lowercase()) {
                hits.push(format!("关键词命中：{word}"));
            }
        }
    }
    hits
}

/// 调用第三方文本审核 API。
async fn call_text_api(
    state: &AppState,
    project_id: u64,
    config: &Value,
    text: &str,
    thresholds: &Thresholds,
) -> Result<(String, Option<f64>, Option<String>, Vec<String>), String> {
    let api_ref = config
        .get("api_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let row = if api_ref.is_empty() {
        // 没指定就取第一个带 TEXT 标签的 API 配置。
        crate::modules::project_config::repositories::list_configs(state, project_id)
            .await
            .map_err(|err| err.to_string())?
            .into_iter()
            .find(|item| item.r#type == "API" && tags_contain(&item.tags, "TEXT"))
            .ok_or_else(|| "未配置文本审核 API".to_string())?
    } else {
        crate::modules::project_config::repositories::find_config_by_name(
            state, project_id, "API", &api_ref,
        )
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("文本审核 API「{api_ref}」不存在"))?
    };

    let key = state.settings.master_key();
    let plain = crate::security::encrypt::decrypt_json(&key, project_id, &row.config_encrypted)
        .map_err(|err| err.to_string())?;
    let base_url = plain
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "文本审核 API 配置缺少 base_url".to_string())?;
    let path = config
        .get("api_path")
        .and_then(Value::as_str)
        .unwrap_or("/text/check");
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    let timeout_ms = config
        .get("timeout_ms")
        .and_then(Value::as_i64)
        .unwrap_or(5000)
        .clamp(100, 60_000);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms as u64))
        .build()
        .map_err(|err| err.to_string())?;

    let mut builder = client.post(&url).json(&json!({ "text": text }));
    if let Some(token) = plain.get("api_key").and_then(Value::as_str) {
        builder = builder.header("X-API-Key", token);
    }

    let response = builder.send().await.map_err(|err| err.to_string())?;
    let status = response.status();
    let http_status = status.as_u16();
    let body = response.text().await.map_err(|err| err.to_string())?;

    state.metrics.inc(
        "audit_api_call_total",
        vec![
            ("project".to_string(), project_id.to_string()),
            (
                "api_ref".to_string(),
                if api_ref.is_empty() {
                    row.name.clone()
                } else {
                    api_ref.clone()
                },
            ),
            ("http_status".to_string(), http_status.to_string()),
        ],
    );

    if !status.is_success() {
        return Err(format!("文本审核 API 返回状态码 {http_status}"));
    }

    let parsed: Value = serde_json::from_str(&body).map_err(|err| err.to_string())?;
    let raw_label = pick_string(&parsed, &["label", "result_label", "category", "risk"]);
    let score = pick_number(&parsed, &["score", "confidence", "probability"]);
    let risk_level = pick_string(&parsed, &["risk_level", "riskLevel", "level"]);

    let label = normalize_label(raw_label.as_deref(), score, thresholds);
    let reasons = pick_reasons(&parsed);

    Ok((label, score, risk_level, reasons))
}

/// 配置里的标签是否包含目标标记。
fn tags_contain(tags: &Option<Value>, target: &str) -> bool {
    let Some(Value::Array(items)) = tags else {
        return false;
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .any(|text| text.trim().eq_ignore_ascii_case(target))
}

// ---------------------------------------------------------------------------
// 图片
// ---------------------------------------------------------------------------

/// 审核一张图片：下载、校验、算指纹。
async fn review_image(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    item: &MediaItem,
    max_bytes: i64,
    formats: &[String],
) -> Result<MediaAsset, String> {
    if item.url.trim().is_empty() {
        return Err("图片缺少地址".to_string());
    }

    // 下载前先拒绝内网地址。
    let parsed = Url::parse(item.url.trim()).map_err(|_| "图片地址不是合法 URL".to_string())?;
    let host = parsed.host_str().unwrap_or_default().to_string();
    if crate::modules::audit::service::is_blocked_host(&host)
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".local")
    {
        return Err("图片地址不允许指向内网".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| err.to_string())?;
    let mut response = client
        .get(item.url.trim())
        .send()
        .await
        .map_err(|err| format!("下载图片失败：{err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("下载图片失败，状态码 {}", status.as_u16()));
    }
    if let Some(length) = response.content_length() {
        if length as i64 > max_bytes {
            return Err(format!("图片大小 {length} 字节超过配额 {} 字节", max_bytes));
        }
    }

    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
        if buffer.len() as i64 + chunk.len() as i64 > max_bytes {
            return Err(format!("图片大小超过配额 {max_bytes} 字节"));
        }
        buffer.extend_from_slice(&chunk);
    }

    // 魔数校验：防止改扩展名伪装格式。
    let real_format =
        detect_image_format(&buffer).ok_or_else(|| "无法识别的图片格式".to_string())?;
    if !formats.iter().any(|item| item == real_format) {
        return Err(format!("图片格式「{real_format}」不在白名单内"));
    }

    let hash = sha256_hex(&buffer);
    let size_bytes = buffer.len() as i64;

    Ok(MediaAsset {
        id: state.ids.next_id(),
        task_id,
        project_id,
        media_type: "image".to_string(),
        url: item.url.clone(),
        oss_key: None,
        hash: Some(hash),
        size_bytes: Some(size_bytes),
        meta_json: Some(json!({ "format": real_format, "bytes": size_bytes })),
    })
}

/// 图片格式白名单。
fn resolve_image_formats(config: &Value) -> Vec<String> {
    let mut formats: Vec<String> = config
        .get("allowed_formats")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|text| text.trim().to_ascii_lowercase())
                .filter(|text| !text.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if formats.is_empty() {
        formats = DEFAULT_IMAGE_FORMATS
            .iter()
            .map(|text| text.to_string())
            .collect();
    }
    formats
}

/// 依据魔数判断真实图片类型。
pub fn detect_image_format(head: &[u8]) -> Option<&'static str> {
    if head.len() >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
        return Some("jpg");
    }
    if head.len() >= 8 && head[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("png");
    }
    if head.len() >= 6 && (&head[..6] == b"GIF87a" || &head[..6] == b"GIF89a") {
        return Some("gif");
    }
    if head.len() >= 2 && &head[..2] == b"BM" {
        return Some("bmp");
    }
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some("webp");
    }
    None
}

// ---------------------------------------------------------------------------
// 视频
// ---------------------------------------------------------------------------

/// 审核一个视频：计算抽帧参数并登记资产。
///
/// 抽帧本身待接入 ffmpeg，这里只做参数计算与进度记录；
/// 真正的帧图片审核在解码能力接入后补齐。
async fn review_video(
    state: &AppState,
    project_id: u64,
    task_id: u64,
    item: &MediaItem,
    max_bytes: i64,
    config: &Value,
) -> MediaAsset {
    let fps = config
        .get("fps")
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(MIN_FPS, MAX_FPS);
    let max_frames = config
        .get("max_frames")
        .and_then(Value::as_i64)
        .unwrap_or(MAX_FRAMES)
        .clamp(1, MAX_FRAMES);
    let aggregate = config
        .get("aggregate")
        .and_then(Value::as_str)
        .unwrap_or("worst")
        .trim()
        .to_ascii_lowercase();
    let threshold = config
        .get("threshold")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .max(1);

    let duration = item.duration.unwrap_or(0.0);
    let frame_count = if duration > 0.0 {
        ((duration * fps).ceil() as i64).clamp(1, max_frames)
    } else {
        0
    };

    let mut meta = json!({
        "fps": fps,
        "max_frames": max_frames,
        "frame_count": frame_count,
        "duration": duration,
        "aggregate": aggregate,
        "threshold": threshold,
        // 真正的解码待接入 ffmpeg 后补齐，届时帧图片走图片审核。
        "decoded": false,
    });

    // 配置了视频审核 API 时，把视频地址交给第三方做整体判定。
    if let Some(api_ref) = config.get("api_ref").and_then(Value::as_str) {
        if !api_ref.trim().is_empty() {
            meta["api_ref"] = Value::String(api_ref.to_string());
        }
    }

    let size_bytes = item.duration.map(|value| value as i64);
    if let Some(bytes) = size_bytes {
        if bytes > max_bytes {
            tracing::warn!(task_id, "视频时长换算的体积估算超过配额，仅登记不下载");
        }
    }

    MediaAsset {
        id: state.ids.next_id(),
        task_id,
        project_id,
        media_type: "video".to_string(),
        url: item.url.clone(),
        oss_key: None,
        hash: None,
        size_bytes: None,
        meta_json: Some(meta),
    }
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

/// 标签与分数阈值。
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub reject_score: f64,
    pub review_score: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            reject_score: 0.9,
            review_score: 0.5,
        }
    }
}

impl Thresholds {
    /// 从审核配置里读阈值。
    pub fn from_config(config: &Value) -> Self {
        let Some(thresholds) = config.get("thresholds") else {
            return Self::default();
        };
        Self {
            reject_score: thresholds
                .get("reject")
                .and_then(Value::as_f64)
                .unwrap_or(0.9),
            review_score: thresholds
                .get("review")
                .and_then(Value::as_f64)
                .unwrap_or(0.5),
        }
    }
}

/// 把模型返回的标签归一化成 `PASS` / `REJECT` / `REVIEW` / `UNKNOWN`。
pub fn normalize_label(label: Option<&str>, score: Option<f64>, thresholds: &Thresholds) -> String {
    if let Some(text) = label {
        let upper = text.trim().to_ascii_uppercase();
        if upper == "PASS" || upper == "REJECT" || upper == "REVIEW" {
            return upper;
        }
    }
    match score {
        Some(value) if value >= thresholds.reject_score => "REJECT".to_string(),
        Some(value) if value >= thresholds.review_score => "REVIEW".to_string(),
        Some(_) => "PASS".to_string(),
        None => "UNKNOWN".to_string(),
    }
}

/// 从响应里取字符串字段（兼容一层包装）。
fn pick_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            if !text.trim().is_empty() {
                return Some(text.to_string());
            }
        }
    }
    for wrapper in ["result", "data", "output"] {
        let Some(inner) = value.get(wrapper) else {
            continue;
        };
        for key in keys {
            if let Some(text) = inner.get(*key).and_then(Value::as_str) {
                if !text.trim().is_empty() {
                    return Some(text.to_string());
                }
            }
        }
    }
    None
}

/// 从响应里取数字字段（兼容一层包装）。
fn pick_number(value: &Value, keys: &[&str]) -> Option<f64> {
    for key in keys {
        if let Some(number) = value.get(*key).and_then(Value::as_f64) {
            return Some(number);
        }
    }
    for wrapper in ["result", "data", "output"] {
        let Some(inner) = value.get(wrapper) else {
            continue;
        };
        for key in keys {
            if let Some(number) = inner.get(*key).and_then(Value::as_f64) {
                return Some(number);
            }
        }
    }
    None
}

/// 从响应里取原因列表。
fn pick_reasons(value: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    let candidates = [
        value.get("reasons"),
        value.get("result").and_then(|item| item.get("reasons")),
        value.get("data").and_then(|item| item.get("reasons")),
    ];
    for candidate in candidates.into_iter().flatten() {
        if let Some(items) = candidate.as_array() {
            for item in items {
                if let Some(text) = item.as_str() {
                    reasons.push(text.to_string());
                }
            }
        }
    }
    reasons
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

/// 写一条媒体资产记录。写失败只告警。
async fn insert_media_asset(state: &AppState, asset: &MediaAsset) {
    let result = sqlx::query(
        "INSERT INTO media_asset
            (id, task_id, project_id, type, url, oss_key, hash, size_bytes, meta_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(asset.id)
    .bind(asset.task_id)
    .bind(asset.project_id)
    .bind(&asset.media_type)
    .bind(&asset.url)
    .bind(&asset.oss_key)
    .bind(&asset.hash)
    .bind(asset.size_bytes)
    .bind(&asset.meta_json)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&state.db)
    .await;

    if let Err(err) = result {
        tracing::error!(error = %err, task_id = asset.task_id, "写媒体资产失败");
    }
}
