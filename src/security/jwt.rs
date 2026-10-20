//! JWT：管理端访问令牌。

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// 访问令牌载荷。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// 用户 ID。
    pub sub: u64,
    /// 用户名。
    pub username: String,
    /// 角色编码。
    pub role: String,
    /// 签发时间（秒）。
    pub iat: i64,
    /// 过期时间（秒）。
    pub exp: i64,
    /// 令牌唯一标识。
    pub jti: String,
}

/// 签发访问令牌。
pub fn encode_access_token(
    secret: &str,
    user_id: u64,
    username: &str,
    role: &str,
    ttl_seconds: i64,
) -> Result<String, ApiError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + ttl_seconds,
        jti: uuid::Uuid::new_v4().simple().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| {
        tracing::error!(error = %err, "签发令牌失败");
        ApiError::internal("签发令牌失败")
    })
}

/// 校验并解析访问令牌。
pub fn decode_access_token(secret: &str, token: &str) -> Result<Claims, ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|err| {
        tracing::debug!(error = %err, "令牌校验失败");
        ApiError::unauthorized("UNAUTHORIZED", "登录状态已失效，请重新登录")
    })
}

/// 从 `Authorization: Bearer xxx` 里取出令牌。
pub fn extract_bearer(header_value: &str) -> Option<&str> {
    let trimmed = header_value.trim();
    let (scheme, token) = trimmed.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let secret = "test-secret";
        let token = encode_access_token(secret, 7, "admin", "SUPER_ADMIN", 60).unwrap();
        let claims = decode_access_token(secret, &token).unwrap();
        assert_eq!(claims.sub, 7);
        assert_eq!(claims.username, "admin");
        assert_eq!(claims.role, "SUPER_ADMIN");
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = encode_access_token("a", 1, "u", "READONLY", 60).unwrap();
        assert!(decode_access_token("b", &token).is_err());
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(extract_bearer("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("Basic abc"), None);
        assert_eq!(extract_bearer("abc"), None);
    }
}
