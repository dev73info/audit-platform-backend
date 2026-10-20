//! 开放 API 签名：HMAC-SHA256 + 时间戳窗口 + Nonce 防重放。
//!
//! 规范见 `doc/API.md` 第三章。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

/// 请求体 SHA256 十六进制小写。
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 拼接规范化字符串。
pub fn canonical_string(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp,
        nonce,
        sha256_hex(body)
    )
}

/// 计算签名。
pub fn sign(secret: &str, canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC 接受任意长度密钥");
    mac.update(canonical.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 校验签名（常数时间比较）。
pub fn verify_signature(secret: &str, canonical: &str, provided: &str) -> bool {
    let expected = sign(secret, canonical);
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(provided.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 校验时间戳偏差。
pub fn check_timestamp(timestamp: &str, tolerance_sec: i64) -> Result<i64, ApiError> {
    let parsed: i64 = timestamp
        .trim()
        .parse()
        .map_err(|_| ApiError::bad_request("X-Timestamp 必须是毫秒时间戳"))?;
    let now = current_millis();
    let diff = (now - parsed).abs();
    if diff > tolerance_sec * 1000 {
        return Err(ApiError::bad_request("TIMESTAMP_EXPIRED"));
    }
    Ok(parsed)
}

fn current_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 生成 32 位随机 Nonce。
pub fn random_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 生成 AppSecret（base64）。
pub fn random_secret() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 生成 AppKey。
pub fn random_app_key() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut text = String::new();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..24 {
        let index = rng.random_range(0..CHARSET.len());
        text.push(CHARSET[index] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable() {
        let canonical = canonical_string("POST", "/open/v1/x", "1700000000000", "abc", b"{}");
        let signature = sign("secret", &canonical);
        assert_eq!(signature.len(), 64);
        assert!(verify_signature("secret", &canonical, &signature));
        assert!(!verify_signature("other", &canonical, &signature));
    }

    #[test]
    fn body_changes_change_signature() {
        let a = canonical_string("POST", "/x", "1", "n", b"{\"a\":1}");
        let b = canonical_string("POST", "/x", "1", "n", b"{\"a\":2}");
        assert_ne!(a, b);
    }

    #[test]
    fn expired_timestamp_is_rejected() {
        assert!(check_timestamp("1", 300).is_err());
        let now = current_millis();
        assert!(check_timestamp(&now.to_string(), 300).is_ok());
    }
}
