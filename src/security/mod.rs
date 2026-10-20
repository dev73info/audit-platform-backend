//! 安全相关：口令哈希、JWT、配置加密、开放 API 签名。

pub mod encrypt;
pub mod jwt;
pub mod password;
pub mod signature;

use serde::{Deserialize, Serialize};

/// 开放 API 的签名请求头。
#[derive(Debug, Clone, Deserialize)]
pub struct SignatureHeaders {
    #[serde(rename = "X-Api-Key")]
    pub api_key: String,
    #[serde(rename = "X-Timestamp")]
    pub timestamp: String,
    #[serde(rename = "X-Nonce")]
    pub nonce: String,
    #[serde(rename = "X-Signature")]
    pub signature: String,
}

/// 客户端标识（AppKey 维度）。
#[derive(Debug, Clone, Serialize)]
pub struct ApiClientIdentity {
    pub client_id: u64,
    pub project_id: u64,
    pub app_key: String,
    pub secret: String,
    pub allow_ips: Vec<String>,
}
