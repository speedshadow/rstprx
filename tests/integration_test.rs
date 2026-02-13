//! Integration tests for the Elite Rama Proxy
//!
//! These tests verify end-to-end behavior: config loading, TLS cert generation,
//! storage CRUD, auth, metrics, stealth headers, and ACME directory fetch.

use rama_elite_proxy::config::Config;
use rama_elite_proxy::storage::Storage;
use rama_elite_proxy::metrics::MetricsCollector;
use rama_elite_proxy::proxy::ProxyHandler;
use rama_elite_proxy::auth::AuthManager;
use rama_elite_proxy::tls::generate_self_signed_cert;
use std::sync::Arc;
use tempfile::TempDir;

/// Helper: build a valid Config for testing
fn test_config(tmp: &TempDir) -> Config {
    let cert_path = tmp.path().join("cert.pem").to_str().unwrap().to_string();
    let key_path = tmp.path().join("key.pem").to_str().unwrap().to_string();
    let db_path = tmp.path().join("test.db").to_str().unwrap().to_string();
    let log_path = tmp.path().join("test.log").to_str().unwrap().to_string();
    let cert_dir = tmp.path().join("certs").to_str().unwrap().to_string();
    std::fs::create_dir_all(&cert_dir).unwrap();

    serde_yaml::from_str(&format!(r#"
server:
  listen_addr: "127.0.0.1:0"
  admin_path: "/admin_elite"
  fake_website_enabled: true
  fake_website_type: "construction"
  tls:
    enabled: true
    mode: "selfsigned"
    cert_file: "{cert_path}"
    key_file: "{key_path}"
    cert_dir: "{cert_dir}"
    selfsigned_hosts: ["localhost", "127.0.0.1"]
    autocert:
      enabled: false
      domains: []
      email: ""
      cache_dir: "/tmp/acme-test"
    ja3_spoofing:
      enabled: true
      profile: "random"
      custom_ja3: ""
    ja4_spoofing:
      enabled: true
      profile: "chrome_120"
  timeouts:
    read: 30
    write: 30
    idle: 120
    shutdown: 30

proxy:
  transport:
    max_idle_conns: 100
    max_idle_conns_per_host: 10
    idle_conn_timeout: 90
    tls_handshake_timeout: 10
    expect_continue_timeout: 1
    response_header_timeout: 30
    dial_timeout: 10
    keep_alive: 30
  profiles:
    enabled: true
    rotation: "random"
    browsers: ["chrome_131", "firefox_133"]
  streaming:
    flush_interval: 1
    buffer_size: 131072
    chunk_size: 32768
  http2:
    enabled: true
    akamai_fingerprint: true
    settings:
      header_table_size: 65536
      max_concurrent_streams: 1000
      initial_window_size: 6291456
      max_frame_size: 16384
      max_header_list_size: 262144
  tcp_fingerprint:
    enabled: false
    window_size: 65535
    ttl: 64
    mss: 1460
    window_scale: 8
    timestamp: true
    sack_permitted: true

stealth:
  behavioral_mimicry:
    enabled: false
    human_pattern: false
    min_delay_ms: 0
    max_delay_ms: 0
    burst_threshold: 5
    burst_delay_ms: 0
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"
  remove_headers:
    - "X-Forwarded-For"
    - "Via"
  header_order:
    preserve: true
    chrome_order: true

rate_limit:
  enabled: false
  per_ip: 10000
  per_domain: 10000
  burst: 1000
  cleanup_interval: 300

circuit_breaker:
  enabled: false
  max_requests: 100
  timeout: 60
  interval: 10
  failure_threshold: 0.6

auth:
  jwt_secret: "test_jwt_secret_for_integration_tests_minimum_32chars"
  token_expiry: 3600
  refresh_enabled: false
  refresh_expiry: 86400
  default_user: "admin"
  default_password: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$TEST_HASH"

storage:
  type: "sled"
  path: "{db_path}"
  cache_capacity: 64

monitoring:
  prometheus:
    enabled: true
    path: "/metrics"
    auth_required: false
  tracing:
    enabled: false
    level: "info"
    format: "json"
    file: "{log_path}"
    anonymize_ips: true

domains: {{}}
"#)).unwrap()
}

#[test]
fn test_config_loads_all_sections() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(&tmp);

    assert_eq!(config.server.admin_path, "/admin_elite");
    assert!(config.server.tls.enabled);
    assert_eq!(config.server.tls.mode, "selfsigned");
    assert!(config.proxy.profiles.enabled);
    assert_eq!(config.proxy.profiles.browsers.len(), 2);
    assert!(config.stealth.header_order.preserve);
    assert!(!config.rate_limit.enabled);
    assert!(!config.circuit_breaker.enabled);
    assert_eq!(config.monitoring.prometheus.path, "/metrics");
}

#[test]
fn test_self_signed_cert_generation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.pem").to_str().unwrap().to_string();
    let key_path = tmp.path().join("key.pem").to_str().unwrap().to_string();

    generate_self_signed_cert(
        &cert_path,
        &key_path,
        vec!["localhost".to_string(), "127.0.0.1".to_string()],
    ).unwrap();

    assert!(std::path::Path::new(&cert_path).exists());
    assert!(std::path::Path::new(&key_path).exists());

    let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));

    let key_pem = std::fs::read_to_string(&key_path).unwrap();
    assert!(key_pem.contains("BEGIN PRIVATE KEY") || key_pem.contains("PRIVATE KEY"));
}

#[test]
fn test_proxy_handler_creation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = TempDir::new().unwrap();
    let config = test_config(&tmp);
    let storage = Storage::new(&config.storage.path).unwrap();
    let metrics = Arc::new(MetricsCollector::new().unwrap());

    let handler = ProxyHandler::new(config, storage, metrics);
    assert!(handler.is_ok(), "ProxyHandler should be created successfully");
}

#[test]
fn test_auth_manager_creation() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(&tmp);

    let auth = AuthManager::new(
        config.auth.jwt_secret.clone(),
        config.auth.token_expiry,
        config.auth.refresh_expiry,
        config.auth.refresh_enabled,
    );
    let token = auth.generate_token("admin");
    assert!(token.is_ok(), "Token generation should succeed");
    let token_str = token.unwrap();
    assert!(!token_str.is_empty());

    let claims = auth.validate_token(&token_str);
    assert!(claims.is_ok(), "Token validation should succeed");
}

#[test]
fn test_storage_domain_crud() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test_crud.db");
    let storage = Storage::new(&db_path).unwrap();

    // Add domain
    storage.add_domain("test.local".to_string(), "https://example.com".to_string()).unwrap();

    // Get domain
    let mapping = storage.get_domain("test.local");
    assert!(mapping.is_some());
    let m = mapping.unwrap();
    assert_eq!(m.target, "https://example.com");

    // Delete domain
    storage.delete_domain("test.local").unwrap();
    assert!(storage.get_domain("test.local").is_none());
}

#[test]
fn test_metrics_collector() {
    let metrics = MetricsCollector::new().unwrap();

    metrics.increment_connections();
    metrics.record_request("example.com", 1024, 0.5);
    metrics.record_error("example.com", "timeout");
    metrics.decrement_connections();

    let report = metrics.render_metrics().unwrap();
    assert!(!report.is_empty(), "Prometheus output should not be empty");
}

#[tokio::test]
async fn test_acme_client_key_lifecycle() {
    use rama_elite_proxy::acme::AcmeClient;

    let tmp = TempDir::new().unwrap();
    let key_path = tmp.path().join("acme_account.key").to_str().unwrap().to_string();

    let client = AcmeClient::new(
        AcmeClient::letsencrypt_staging().to_string(),
        "test@example.com".to_string(),
        key_path.clone(),
    );

    assert!(!std::path::Path::new(&key_path).exists());

    // Real network call to Let's Encrypt staging directory
    let dir = client.get_directory().await;
    assert!(dir.is_ok(), "Should fetch LE staging directory: {:?}", dir.err());

    let directory = dir.unwrap();
    assert!(directory.new_account.contains("acme-staging"));
    assert!(directory.new_order.contains("acme-staging"));
    assert!(directory.new_nonce.contains("acme-staging"));
}

#[test]
fn test_rate_limiter_integration() {
    use rama_elite_proxy::rate_limit::RateLimiter;

    let limiter = RateLimiter::new(5, 100, 5, true);
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    for _ in 0..5 {
        assert!(limiter.check_ip(ip).is_ok());
    }

    for _ in 0..5 {
        assert!(limiter.check_domain("example.com").is_ok());
    }
}

#[test]
fn test_circuit_breaker_integration() {
    use rama_elite_proxy::circuit_breaker::CircuitBreaker;

    // CircuitBreaker::new(max_failures, timeout_secs, failure_threshold, enabled)
    let _cb = CircuitBreaker::new(3, 60, 0.5, true);
    // If it doesn't panic, the circuit breaker was created successfully
}

#[test]
fn test_browser_profiles_complete() {
    use rama_elite_proxy::stealth::BrowserProfiles;

    let profiles = BrowserProfiles::all_profiles();
    assert!(profiles.len() >= 4, "Should have at least 4 browser profiles");

    for p in &profiles {
        assert!(!p.name.is_empty());
        assert!(!p.user_agent.is_empty());
    }

    let chrome = BrowserProfiles::get_profile("chrome_131");
    assert!(chrome.is_some(), "chrome_131 profile should exist");
    let chrome = chrome.unwrap();
    assert!(chrome.user_agent.contains("Chrome"));
}

#[test]
fn test_header_manipulation_stealth() {
    use rama_elite_proxy::stealth::HeaderManipulator;
    use http::HeaderMap;

    let remove = vec![
        "X-Forwarded-For".to_string(),
        "Via".to_string(),
        "X-Real-IP".to_string(),
    ];
    let manipulator = HeaderManipulator::new(remove, true);

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
    headers.insert("via", "1.1 proxy".parse().unwrap());
    headers.insert("x-real-ip", "5.6.7.8".parse().unwrap());
    headers.insert("host", "example.com".parse().unwrap());

    manipulator.clean_headers(&mut headers);

    assert!(headers.get("x-forwarded-for").is_none(), "X-Forwarded-For should be stripped");
    assert!(headers.get("via").is_none(), "Via should be stripped");
    assert!(headers.get("x-real-ip").is_none(), "X-Real-IP should be stripped");
    assert!(headers.get("host").is_some(), "Host should be preserved");
}

#[test]
fn test_response_header_sanitization() {
    use rama_elite_proxy::stealth::HeaderManipulator;
    use http::HeaderMap;

    let manipulator = HeaderManipulator::new(vec![], true);

    let mut headers = HeaderMap::new();
    headers.insert("server", "Apache/2.4.51".parse().unwrap());
    headers.insert("x-powered-by", "PHP/8.1".parse().unwrap());
    headers.insert("content-type", "text/html".parse().unwrap());

    manipulator.sanitize_response_headers(&mut headers);

    assert!(headers.get("x-powered-by").is_none(), "X-Powered-By should be stripped");
    assert!(headers.get("content-type").is_some(), "Content-Type should be preserved");
}
