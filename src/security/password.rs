//! 口令哈希：Argon2id。

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params};

use crate::error::ApiError;

/// 生成 Argon2id 哈希串。
pub fn hash_password(plain: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(plain.as_bytes(), &salt) {
        Ok(hash) => Ok(hash.to_string()),
        Err(err) => {
            tracing::error!(error = %err, "口令哈希失败");
            Err(ApiError::internal("口令哈希失败"))
        }
    }
}

/// 校验口令。哈希串非法时按不匹配处理，不泄露细节。
pub fn verify_password(plain: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let argon2 = Argon2::default();
    argon2.verify_password(plain.as_bytes(), &parsed).is_ok()
}

/// 口令强度校验：≥ 10 位，且大小写字母 / 数字 / 特殊字符中至少命中 3 类。
pub fn check_password_strength(plain: &str) -> Result<(), String> {
    let length = plain.chars().count();
    if length < 10 {
        return Err("密码长度至少 10 位".to_string());
    }
    let has_lower = plain.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = plain.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = plain.chars().any(|c| c.is_ascii_digit());
    let has_special = plain.chars().any(|c| !c.is_alphanumeric());
    let kinds = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|v| **v)
        .count();
    if kinds < 3 {
        return Err("密码需包含大写字母、小写字母、数字、特殊字符中的至少 3 类".to_string());
    }
    Ok(())
}

/// 生成带指定成本的 Argon2 参数（测试用）。
pub fn hash_password_with_params(plain: &str, m_cost: u32, t_cost: u32, p_cost: u32) -> String {
    let params = Params::new(m_cost, t_cost, p_cost, None).expect("Argon2 参数合法");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(plain.as_bytes(), &salt)
        .expect("哈希不会失败")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("Test@123456").unwrap();
        assert!(verify_password("Test@123456", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn strength_rules() {
        assert!(check_password_strength("Test@123456").is_ok());
        assert!(check_password_strength("short").is_err());
        assert!(check_password_strength("alllowercaseletters").is_err());
    }
}
