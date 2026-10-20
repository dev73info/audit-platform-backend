//! 配置加载：代码默认值 → `config/default.toml` → `config/local.toml` → `APP__` 环境变量。
//!
//! 加载顺序与 `backend_73info` 保持一致；`local.toml` 不入库，敏感值只走本机文件或环境变量。

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    /// 文件里写逗号分隔字符串即可；也接受 JSON 数组。
    #[serde(deserialize_with = "deserialize_string_list")]
    pub cors_allow_origins: Vec<String>,
}

/// 兼容「逗号分隔字符串」与「字符串数组」两种写法。
fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringList {
        One(String),
        Many(Vec<String>),
    }

    Ok(match StringList::deserialize(deserializer)? {
        StringList::One(text) => text
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        StringList::Many(items) => items
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_ms: u64,
    pub auto_migrate: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisSettings {
    pub url: String,
    pub degrade_to_db_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySettings {
    pub jwt_secret: String,
    pub encryption_key: String,
    pub bootstrap_admin_username: String,
    pub bootstrap_admin_password: String,
    pub captcha_after_failures: i32,
    pub lock_after_failures: i32,
    pub lock_minutes: i64,
    pub signature_tolerance_sec: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditSettings {
    pub lock_ttl_sec: u64,
    pub default_max_concurrency: i64,
    pub default_max_qps: i64,
    pub default_max_mysql_pool: i64,
    pub default_max_redis_conn: i64,
    pub default_max_media_size_mb: i64,
    pub default_max_api_call_per_task: i64,
    pub global_pool_ratio: f64,
    pub quota_hard_limit_mysql_pool: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsSettings {
    pub enabled: bool,
    pub retention_sec: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub redis: RedisSettings,
    pub security: SecuritySettings,
    pub audit: AuditSettings,
    pub metrics: MetricsSettings,
}

impl Settings {
    /// 从 `config/` 目录加载配置。`config_dir` 一般传 `config`（相对仓库根）。
    pub fn load(config_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config_dir = config_dir.as_ref();
        let mut settings = Self::from_toml_file(&config_dir.join("default.toml"))?;

        let local_path = config_dir.join("local.toml");
        if local_path.exists() {
            let local = Self::from_toml_file(&local_path)?;
            settings.merge(local);
        }

        settings.apply_env_overrides();
        Ok(settings)
    }

    fn from_toml_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("读取配置 {} 失败：{e}", path.display()))?;
        let value: toml::Value = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("解析配置 {} 失败：{e}", path.display()))?;
        let settings: Settings = value
            .try_into()
            .map_err(|e| anyhow::anyhow!("配置 {} 结构不合法：{e}", path.display()))?;
        Ok(settings)
    }

    fn merge(&mut self, other: Settings) {
        self.server = other.server;
        self.database = other.database;
        self.redis = other.redis;
        self.security = other.security;
        self.audit = other.audit;
        self.metrics = other.metrics;
    }

    /// `APP__SERVER__PORT=9000` 覆盖 `[server] port`。
    fn apply_env_overrides(&mut self) {
        macro_rules! env_str {
            ($section:expr, $key:expr) => {
                if let Ok(v) = std::env::var(format!("APP__{}__{}", $section, $key)) {
                    $crate::settings::set_by_path(self, &[$section, $key], v);
                }
            };
        }
        macro_rules! env_num {
            ($section:expr, $key:expr) => {
                if let Ok(v) = std::env::var(format!("APP__{}__{}", $section, $key)) {
                    if let Ok(parsed) = v.parse::<i64>() {
                        $crate::settings::set_by_path(self, &[$section, $key], parsed.to_string());
                    }
                }
            };
        }

        env_str!("SERVER", "HOST");
        env_num!("SERVER", "PORT");
        env_str!("DATABASE", "URL");
        env_num!("DATABASE", "MAX_CONNECTIONS");
        env_str!("REDIS", "URL");
        env_str!("SECURITY", "JWT_SECRET");
        env_str!("SECURITY", "ENCRYPTION_KEY");
        env_str!("SECURITY", "BOOTSTRAP_ADMIN_USERNAME");
        env_str!("SECURITY", "BOOTSTRAP_ADMIN_PASSWORD");
        env_num!("SECURITY", "SIGNATURE_TOLERANCE_SEC");
        env_num!("AUDIT", "LOCK_TTL_SEC");
        env_num!("METRICS", "RETENTION_SEC");
    }

    /// 推导加密主密钥：`encryption_key` 优先，未配置时回落到 `jwt_secret`。
    pub fn master_key(&self) -> [u8; 32] {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let raw = self.security.encryption_key.trim();
        if !raw.is_empty() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw) {
                if bytes.len() >= 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes[..32]);
                    return key;
                }
            }
            // 非 base64 时按原文哈希，长度不限
            let mut hasher = Sha256::new();
            hasher.update(raw.as_bytes());
            let digest = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(&digest);
            return key;
        }

        let mut hasher = Sha256::new();
        hasher.update(self.security.jwt_secret.as_bytes());
        hasher.update(b"audit-platform-encryption");
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }
}

/// 按 `["server", "port"]` 这样的路径写字段，避免引入反射依赖。
fn set_by_path(target: &mut Settings, path: &[&str], value: impl Into<String>) {
    let value = value.into();
    match path {
        ["server", "host"] => target.server.host = value,
        ["server", "port"] => {
            if let Ok(parsed) = value.parse::<u16>() {
                target.server.port = parsed;
            }
        }
        ["server", "cors_allow_origins"] => {
            target.server.cors_allow_origins = value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        ["database", "url"] => target.database.url = value,
        ["database", "max_connections"] => {
            if let Ok(parsed) = value.parse::<u32>() {
                target.database.max_connections = parsed;
            }
        }
        ["database", "min_connections"] => {
            if let Ok(parsed) = value.parse::<u32>() {
                target.database.min_connections = parsed;
            }
        }
        ["database", "acquire_timeout_ms"] => {
            if let Ok(parsed) = value.parse::<u64>() {
                target.database.acquire_timeout_ms = parsed;
            }
        }
        ["database", "auto_migrate"] => {
            if let Ok(parsed) = value.parse::<bool>() {
                target.database.auto_migrate = parsed;
            }
        }
        ["redis", "url"] => target.redis.url = value,
        ["redis", "degrade_to_db_only"] => {
            if let Ok(parsed) = value.parse::<bool>() {
                target.redis.degrade_to_db_only = parsed;
            }
        }
        ["security", "jwt_secret"] => target.security.jwt_secret = value,
        ["security", "encryption_key"] => target.security.encryption_key = value,
        ["security", "bootstrap_admin_username"] => {
            target.security.bootstrap_admin_username = value
        }
        ["security", "bootstrap_admin_password"] => {
            target.security.bootstrap_admin_password = value
        }
        ["security", "captcha_after_failures"] => {
            if let Ok(parsed) = value.parse::<i32>() {
                target.security.captcha_after_failures = parsed;
            }
        }
        ["security", "lock_after_failures"] => {
            if let Ok(parsed) = value.parse::<i32>() {
                target.security.lock_after_failures = parsed;
            }
        }
        ["security", "lock_minutes"] => {
            if let Ok(parsed) = value.parse::<i64>() {
                target.security.lock_minutes = parsed;
            }
        }
        ["security", "signature_tolerance_sec"] => {
            if let Ok(parsed) = value.parse::<i64>() {
                target.security.signature_tolerance_sec = parsed;
            }
        }
        ["audit", "lock_ttl_sec"] => {
            if let Ok(parsed) = value.parse::<u64>() {
                target.audit.lock_ttl_sec = parsed;
            }
        }
        ["audit", "global_pool_ratio"] => {
            if let Ok(parsed) = value.parse::<f64>() {
                target.audit.global_pool_ratio = parsed;
            }
        }
        ["metrics", "enabled"] => {
            if let Ok(parsed) = value.parse::<bool>() {
                target.metrics.enabled = parsed;
            }
        }
        ["metrics", "retention_sec"] => {
            if let Ok(parsed) = value.parse::<u64>() {
                target.metrics.retention_sec = parsed;
            }
        }
        _ => {}
    }
}

/// 仓库根目录下的 `config/` 绝对路径。
pub fn default_config_dir() -> PathBuf {
    PathBuf::from("config")
}
