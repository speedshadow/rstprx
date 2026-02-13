use crate::error::{Error, Result};
use crate::stealth::{PathSanitizer, PathType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub stealth: StealthConfig,
    pub rate_limit: RateLimitConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub domains: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub tls: TlsConfig,
    pub timeouts: TimeoutConfig,
    #[serde(default = "default_admin_path")]
    pub admin_path: String,
    #[serde(default = "default_fake_website")]
    pub fake_website_enabled: bool,
    #[serde(default = "default_fake_website_type")]
    pub fake_website_type: String,
}

fn default_admin_path() -> String {
    "/admin_elite".to_string()
}

fn default_fake_website() -> bool {
    true
}

fn default_fake_website_type() -> String {
    "construction".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub mode: String,
    pub cert_file: String,
    pub key_file: String,
    pub cert_dir: String,
    pub selfsigned_hosts: Vec<String>,
    pub autocert: AutocertConfig,
    pub ja3_spoofing: Ja3Config,
    pub ja4_spoofing: Ja4Config,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AutocertConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: String,
    pub cache_dir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ja3Config {
    pub enabled: bool,
    pub profile: String,
    pub custom_ja3: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ja4Config {
    pub enabled: bool,
    pub profile: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    pub read: u64,
    pub write: u64,
    pub idle: u64,
    pub shutdown: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub transport: TransportConfig,
    pub profiles: ProfilesConfig,
    pub streaming: StreamingConfig,
    pub http2: Http2Config,
    pub tcp_fingerprint: TcpFingerprintConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    pub max_idle_conns: usize,
    pub max_idle_conns_per_host: usize,
    pub idle_conn_timeout: u64,
    pub tls_handshake_timeout: u64,
    pub expect_continue_timeout: u64,
    pub response_header_timeout: u64,
    pub dial_timeout: u64,
    pub keep_alive: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfilesConfig {
    pub enabled: bool,
    pub rotation: String,
    pub browsers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StreamingConfig {
    pub flush_interval: u64,
    pub buffer_size: usize,
    pub chunk_size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Config {
    pub enabled: bool,
    pub akamai_fingerprint: bool,
    pub settings: Http2SettingsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2SettingsConfig {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpFingerprintConfig {
    pub enabled: bool,
    pub window_size: u32,
    pub ttl: u8,
    pub mss: u16,
    pub window_scale: u8,
    pub timestamp: bool,
    pub sack_permitted: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StealthConfig {
    pub behavioral_mimicry: BehavioralMimicryConfig,
    pub user_agents: Vec<String>,
    pub remove_headers: Vec<String>,
    pub header_order: HeaderOrderConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BehavioralMimicryConfig {
    pub enabled: bool,
    pub human_pattern: bool,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub burst_threshold: u32,
    pub burst_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderOrderConfig {
    pub preserve: bool,
    pub chrome_order: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub per_ip: u32,
    pub per_domain: u32,
    pub burst: u32,
    pub cleanup_interval: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub max_requests: u32,
    pub timeout: u64,
    pub interval: u64,
    pub failure_threshold: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry: u64,
    pub refresh_enabled: bool,
    pub refresh_expiry: u64,
    pub default_user: String,
    pub default_password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(rename = "type")]
    pub storage_type: String,
    pub path: String,
    pub cache_capacity: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub prometheus: PrometheusConfig,
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub path: String,
    pub auth_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub level: String,
    pub format: String,
    pub file: String,
    pub anonymize_ips: bool,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_str()
            .ok_or_else(|| Error::Config("Invalid path encoding".to_string()))?;
        
        // SECURITY FIX: Sanitize path to prevent traversal attacks
        let canonical_path = PathSanitizer::sanitize_config_path(path_str)?;

        PathSanitizer::validate_existing_path(&canonical_path, PathType::File)?;

        let mut file = fs::File::open(&canonical_path)
            .map_err(|e| Error::Config(format!("Failed to open config file: {}", e)))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.auth.jwt_secret.len() < 32 {
            return Err(Error::Config(
                "JWT secret must be at least 32 characters".to_string(),
            ));
        }

        if self.auth.jwt_secret.to_ascii_uppercase().contains("CHANGE_ME") {
            return Err(Error::Config(
                "JWT secret contains placeholder value; set a real production secret".to_string(),
            ));
        }

        if self.auth.default_user.trim().is_empty() {
            return Err(Error::Config(
                "Default admin username must not be empty".to_string(),
            ));
        }

        let default_password = self.auth.default_password.trim();
        if default_password.is_empty() {
            return Err(Error::Config(
                "Default admin password hash must not be empty".to_string(),
            ));
        }

        if default_password.to_ascii_uppercase().contains("CHANGE_ME") {
            return Err(Error::Config(
                "Default admin password contains placeholder value".to_string(),
            ));
        }

        if !default_password.starts_with("$argon2") {
            return Err(Error::Config(
                "auth.default_password must be an Argon2 hash (prefix: $argon2)".to_string(),
            ));
        }

        if self.server.listen_addr.parse::<SocketAddr>().is_err() {
            return Err(Error::Config(format!(
                "Invalid listen address: {}",
                self.server.listen_addr
            )));
        }

        if self.rate_limit.enabled && self.rate_limit.per_ip == 0 {
            return Err(Error::Config(
                "Rate limit per_ip must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    pub fn read_timeout(&self) -> Duration {
        Duration::from_secs(self.server.timeouts.read)
    }

    pub fn write_timeout(&self) -> Duration {
        Duration::from_secs(self.server.timeouts.write)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.server.timeouts.idle)
    }

    pub fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(self.server.timeouts.shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = Config {
            server: ServerConfig {
                listen_addr: "0.0.0.0:8443".to_string(),
                tls: TlsConfig {
                    enabled: true,
                    mode: "selfsigned".to_string(),
                    cert_file: "cert.pem".to_string(),
                    key_file: "key.pem".to_string(),
                    cert_dir: "certs/domains".to_string(),
                    selfsigned_hosts: vec![],
                    autocert: AutocertConfig {
                        enabled: false,
                        domains: vec![],
                        email: String::new(),
                        cache_dir: String::new(),
                    },
                    ja3_spoofing: Ja3Config {
                        enabled: true,
                        profile: "random".to_string(),
                        custom_ja3: String::new(),
                    },
                    ja4_spoofing: Ja4Config {
                        enabled: true,
                        profile: "chrome_120".to_string(),
                    },
                },
                timeouts: TimeoutConfig {
                    read: 30,
                    write: 30,
                    idle: 120,
                    shutdown: 30,
                },
                admin_path: "/admin_elite".to_string(),
                fake_website_enabled: true,
                fake_website_type: "construction".to_string(),
            },
            proxy: ProxyConfig {
                transport: TransportConfig {
                    max_idle_conns: 1000,
                    max_idle_conns_per_host: 100,
                    idle_conn_timeout: 90,
                    tls_handshake_timeout: 10,
                    expect_continue_timeout: 1,
                    response_header_timeout: 30,
                    dial_timeout: 10,
                    keep_alive: 30,
                },
                profiles: ProfilesConfig {
                    enabled: true,
                    rotation: "random".to_string(),
                    browsers: vec!["chrome_120".to_string()],
                },
                streaming: StreamingConfig {
                    flush_interval: 1,
                    buffer_size: 65536,
                    chunk_size: 32768,
                },
                http2: Http2Config {
                    enabled: true,
                    akamai_fingerprint: true,
                    settings: Http2SettingsConfig {
                        header_table_size: 65536,
                        max_concurrent_streams: 1000,
                        initial_window_size: 6291456,
                        max_frame_size: 16384,
                        max_header_list_size: 262144,
                    },
                },
                tcp_fingerprint: TcpFingerprintConfig {
                    enabled: true,
                    window_size: 65535,
                    ttl: 64,
                    mss: 1460,
                    window_scale: 8,
                    timestamp: true,
                    sack_permitted: true,
                },
            },
            stealth: StealthConfig {
                behavioral_mimicry: BehavioralMimicryConfig {
                    enabled: true,
                    human_pattern: true,
                    min_delay_ms: 50,
                    max_delay_ms: 500,
                    burst_threshold: 5,
                    burst_delay_ms: 2000,
                },
                user_agents: vec![],
                remove_headers: vec![],
                header_order: HeaderOrderConfig {
                    preserve: true,
                    chrome_order: true,
                },
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                per_ip: 100,
                per_domain: 1000,
                burst: 20,
                cleanup_interval: 300,
            },
            circuit_breaker: CircuitBreakerConfig {
                enabled: true,
                max_requests: 5,
                timeout: 60,
                interval: 10,
                failure_threshold: 0.6,
            },
            auth: AuthConfig {
                jwt_secret: "this_is_a_test_secret_key_32chars_minimum_required".to_string(),
                token_expiry: 86400,
                refresh_enabled: true,
                refresh_expiry: 604800,
                default_user: "admin".to_string(),
                default_password: "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRmb3J0ZXN0cw$2I9nTR9SZZf5l9S8nR6YlR6GQd4WQ9TtX7YtFQ4Wq0A".to_string(),
            },
            storage: StorageConfig {
                storage_type: "sled".to_string(),
                path: "data/test.db".to_string(),
                cache_capacity: 1024,
            },
            monitoring: MonitoringConfig {
                prometheus: PrometheusConfig {
                    enabled: true,
                    path: "/metrics".to_string(),
                    auth_required: true,
                },
                tracing: TracingConfig {
                    enabled: true,
                    level: "info".to_string(),
                    format: "json".to_string(),
                    file: "logs/test.log".to_string(),
                    anonymize_ips: true,
                },
            },
            domains: HashMap::new(),
        };

        assert!(config.validate().is_ok());

        config.auth.jwt_secret = "short".to_string();
        assert!(config.validate().is_err());
    }
}
