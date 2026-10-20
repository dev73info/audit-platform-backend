//! 统一错误类型：所有 handler 返回 `ApiResult<T>`，错误在这里统一渲染成响应封装。

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use serde_json::{Value, json};

use crate::response::ApiResponse;
use crate::trace::{current_cost_ms, current_trace_id};

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub field: String,
    pub reason: String,
}

impl FieldError {
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// 业务错误。所有错误都带稳定错误码（见 `doc/API.md` 的错误码表）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiError {
    #[error("{message}")]
    BadRequest {
        code: &'static str,
        message: String,
        field_errors: Vec<FieldError>,
    },

    #[error("{message}")]
    Unauthorized { code: &'static str, message: String },

    #[error("{message}")]
    Forbidden {
        code: &'static str,
        message: String,
        /// 错误响应体里的补充数据（如全局连接池额度不足时的占用与上限）。
        data: Value,
    },

    #[error("{message}")]
    NotFound { message: String },

    #[error("{message}")]
    Conflict {
        code: &'static str,
        message: String,
        data: Value,
    },

    #[error("{message}")]
    Unprocessable {
        code: &'static str,
        message: String,
        data: Value,
    },

    #[error("{message}")]
    RateLimited { message: String, retry_after: u64 },

    #[error("{message}")]
    Internal { message: String },

    #[error("{message}")]
    Downstream { message: String },
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            code: "INVALID_PARAM",
            message: message.into(),
            field_errors: Vec::new(),
        }
    }

    pub fn invalid_param(message: impl Into<String>, field_errors: Vec<FieldError>) -> Self {
        Self::BadRequest {
            code: "INVALID_PARAM",
            message: message.into(),
            field_errors,
        }
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::Unauthorized {
            code,
            message: message.into(),
        }
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
            data: Value::Null,
        }
    }

    /// 带补充数据的 403（如全局连接池额度不足时给出已占用与全局上限）。
    pub fn forbidden_with(code: &'static str, message: impl Into<String>, data: Value) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn perm_denied(message: impl Into<String>) -> Self {
        Self::forbidden("PERM_DENIED", message)
    }

    pub fn out_of_scope(message: impl Into<String>) -> Self {
        Self::forbidden("PROJECT_OUT_OF_SCOPE", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn conflict_with(code: &'static str, message: impl Into<String>, data: Value) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self::Unprocessable {
            code,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn unprocessable_with(code: &'static str, message: impl Into<String>, data: Value) -> Self {
        Self::Unprocessable {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn rate_limited(message: impl Into<String>, retry_after: u64) -> Self {
        Self::RateLimited {
            message: message.into(),
            retry_after,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn downstream(message: impl Into<String>) -> Self {
        Self::Downstream {
            message: message.into(),
        }
    }

    /// 错误码字符串。
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { code, .. } => code,
            Self::Unauthorized { code, .. } => code,
            Self::Forbidden { code, .. } => code,
            Self::NotFound { .. } => "NOT_FOUND",
            Self::Conflict { code, .. } => code,
            Self::Unprocessable { code, .. } => code,
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::Internal { .. } => "INTERNAL_ERROR",
            Self::Downstream { .. } => "DOWNSTREAM_UNAVAILABLE",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Unprocessable { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Downstream { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// 错误响应体里的补充数据。
    fn data(&self) -> Value {
        match self {
            Self::BadRequest { field_errors, .. } if !field_errors.is_empty() => {
                json!({ "field_errors": field_errors })
            }
            Self::Conflict { data, .. } | Self::Unprocessable { data, .. } => data.clone(),
            Self::Forbidden { data, .. } => data.clone(),
            _ => Value::Null,
        }
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse {
        let body = ApiResponse {
            code: self.status().as_u16() as i32,
            message: self.code().to_string(),
            data: self.data(),
            trace_id: current_trace_id(),
            cost_ms: current_cost_ms(),
        };

        let mut builder = HttpResponse::build(self.status());
        if let Self::RateLimited { retry_after, .. } = self {
            builder.insert_header(("Retry-After", retry_after.to_string()));
        }
        builder.json(body)
    }
}

/// 数据库等底层错误统一转成 500，避免把 SQL 片段泄露给调用方。
impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "数据库操作失败");
        match err {
            sqlx::Error::RowNotFound => ApiError::not_found("记录不存在"),
            _ => ApiError::internal("数据库操作失败"),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        tracing::error!(error = %err, "JSON 序列化失败");
        ApiError::internal("数据序列化失败")
    }
}
