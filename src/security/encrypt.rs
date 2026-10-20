//! 连接配置加密：AES-256-GCM，主密钥 + 按项目派生子密钥。
//!
//! 密文格式：`[12 字节 nonce][密文][16 字节 tag]`，落库为 `VARBINARY`。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

/// 按项目派生子密钥：主密钥 + project_id 派生出每项目独立密钥。
pub fn derive_project_key(master_key: &[u8; 32], project_id: u64) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC 接受任意长度密钥");
    mac.update(b"audit-platform/project-key/v1");
    mac.update(&project_id.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// 加密任意 JSON 值。`project_id` 为 0 表示系统级配置（用主密钥直接加密）。
pub fn encrypt_json(
    master_key: &[u8; 32],
    project_id: u64,
    value: &serde_json::Value,
) -> Result<Vec<u8>, ApiError> {
    let key = if project_id == 0 {
        *master_key
    } else {
        derive_project_key(master_key, project_id)
    };
    encrypt_bytes(&key, &serde_json::to_vec(value)?)
}

/// 解密 JSON 值。
pub fn decrypt_json(
    master_key: &[u8; 32],
    project_id: u64,
    ciphertext: &[u8],
) -> Result<serde_json::Value, ApiError> {
    let key = if project_id == 0 {
        *master_key
    } else {
        derive_project_key(master_key, project_id)
    };
    let plaintext = decrypt_bytes(&key, ciphertext)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// 加密字节。
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ApiError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ApiError::internal("配置加密失败"))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// 解密字节。
pub fn decrypt_bytes(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, ApiError> {
    if ciphertext.len() < 12 + 16 {
        return Err(ApiError::internal("密文长度不合法"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|_| ApiError::internal("配置解密失败（密钥已变更或密文损坏）"))
}

fn random_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// 密钥脱敏展示：保留末 4 位。
pub fn mask_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().count() <= 4 {
        return "****".to_string();
    }
    let tail: String = trimmed
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let master = [7u8; 32];
        let value = serde_json::json!({ "host": "10.0.0.1", "password": "s3cret" });
        let ciphertext = encrypt_json(&master, 42, &value).unwrap();
        assert_ne!(ciphertext, serde_json::to_vec(&value).unwrap());
        let restored = decrypt_json(&master, 42, &ciphertext).unwrap();
        assert_eq!(restored, value);
    }

    #[test]
    fn different_projects_use_different_keys() {
        let master = [7u8; 32];
        let value = serde_json::json!({ "a": 1 });
        let a = encrypt_json(&master, 1, &value).unwrap();
        let b = encrypt_json(&master, 2, &value).unwrap();
        assert!(decrypt_json(&master, 2, &a).is_err());
        assert!(decrypt_json(&master, 1, &b).is_err());
    }

    #[test]
    fn mask_keeps_tail() {
        assert_eq!(mask_secret("abcdefgh"), "****efgh");
        assert_eq!(mask_secret("ab"), "****");
        assert_eq!(mask_secret(""), "");
    }
}
