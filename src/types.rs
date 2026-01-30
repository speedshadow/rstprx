use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMapping {
    pub subdomain: String,
    pub target: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub total_bytes: u64,
    pub active_connections: u64,
    pub domains: HashMap<String, DomainStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStats {
    pub requests: u64,
    pub bytes: u64,
    pub last_request: i64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub name: String,
    pub ja3: String,
    pub ja4: String,
    pub user_agent: String,
    pub http2_settings: Http2Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    pub window_size: u32,
    pub ttl: u8,
    pub mss: u16,
    pub window_scale: u8,
    pub timestamp: bool,
    pub sack_permitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}
