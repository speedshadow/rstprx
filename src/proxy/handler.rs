use crate::circuit_breaker::CircuitBreaker;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::MetricsCollector;
use crate::proxy::{IptvRewriter, RequestDirector};
use crate::rate_limit::RateLimiter;
use crate::stealth::{
    BehavioralMimicry, BrowserProfile, BrowserProfiles, ExtensionRandomizer,
    HeaderManipulator, UserAgentPool, WebSocketFingerprinter, headermap_to_ordered,
};
use rustls::ClientConfig as RustlsClientConfig;
use crate::storage::Storage;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Incoming};
use hyper_rustls::HttpsConnectorBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

/// Flexible response body: supports both buffered (Full) and streaming (Incoming)
pub type ResponseBody = BoxBody<Bytes, hyper::Error>;

/// Wrap a complete Bytes buffer into a ResponseBody
fn full(bytes: Bytes) -> ResponseBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

#[derive(Clone)]
pub struct ProxyHandler {
    config: Arc<Config>,
    storage: Storage,
    rate_limiter: RateLimiter,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<MetricsCollector>,
    behavioral_mimicry: BehavioralMimicry,
    #[allow(dead_code)]
    user_agent_pool: UserAgentPool,
    header_manipulator: HeaderManipulator,
    iptv_rewriter: Arc<RwLock<IptvRewriter>>,
    http_client: Arc<HttpsClient>,
    browser_profiles: Arc<Vec<BrowserProfile>>,
}

impl ProxyHandler {
    pub fn new(config: Config, storage: Storage, metrics: Arc<MetricsCollector>) -> Result<Self> {
        let rate_limiter = RateLimiter::new(
            config.rate_limit.per_ip,
            config.rate_limit.per_domain,
            config.rate_limit.burst,
            config.rate_limit.enabled,
        );

        if config.rate_limit.enabled && config.rate_limit.cleanup_interval > 0 {
            if let Ok(handle) = Handle::try_current() {
                let rate_limiter_clone = rate_limiter.clone();
                let cleanup_interval = config.rate_limit.cleanup_interval;
                handle.spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
                    loop {
                        interval.tick().await;
                        rate_limiter_clone.cleanup();
                    }
                });
            } else {
                warn!("Rate limiter cleanup task not started: no active Tokio runtime");
            }
        }

        let circuit_breaker = CircuitBreaker::new(
            config.circuit_breaker.max_requests,
            config.circuit_breaker.timeout,
            config.circuit_breaker.failure_threshold,
            config.circuit_breaker.enabled,
        );

        let behavioral_mimicry = BehavioralMimicry::new(
            config.stealth.behavioral_mimicry.enabled,
            config.stealth.behavioral_mimicry.human_pattern,
            config.stealth.behavioral_mimicry.min_delay_ms,
            config.stealth.behavioral_mimicry.max_delay_ms,
            config.stealth.behavioral_mimicry.burst_threshold,
            config.stealth.behavioral_mimicry.burst_delay_ms,
        );

        let user_agent_pool = UserAgentPool::new(config.stealth.user_agents.clone());

        let header_manipulator = HeaderManipulator::new(
            config.stealth.remove_headers.clone(),
            config.stealth.header_order.preserve,
        );

        let iptv_rewriter = Arc::new(RwLock::new(IptvRewriter::new()));

        // Build browser profiles from config or use all defaults
        let browser_profiles: Vec<BrowserProfile> = if config.proxy.profiles.enabled {
            config.proxy.profiles.browsers.iter()
                .filter_map(|name| BrowserProfiles::get_profile(name))
                .collect()
        } else {
            Vec::new()
        };
        let browser_profiles = if browser_profiles.is_empty() {
            Arc::new(BrowserProfiles::all_profiles())
        } else {
            Arc::new(browser_profiles)
        };

        // STEALTH: Custom rustls ClientConfig for outbound connections
        // rustls 0.23 automatically applies GREASE values to:
        //   - cipher suites (first position)
        //   - TLS extensions (first position)
        //   - supported groups/curves (first position)
        // This matches Chrome/Edge real browser behavior (RFC 8701)
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // NOTE: ECH (Encrypted Client Hello) GREASE requires HPKE support
        // which is only available with the aws-lc-rs crypto provider.
        // Current config uses ring provider for build simplicity.
        // To enable ECH GREASE, switch to aws-lc-rs and add:
        //   .with_ech(rustls::client::EchMode::Grease(
        //       rustls::client::EchGreaseConfig::new(SUITE, vec![...])
        //   ))

        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        // HTTP/2 settings from config integrated into client builder
        let mut client_builder = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
        client_builder
            .pool_idle_timeout(std::time::Duration::from_secs(config.proxy.transport.idle_conn_timeout))
            .pool_max_idle_per_host(config.proxy.transport.max_idle_conns_per_host);

        if config.proxy.http2.enabled {
            client_builder
                .http2_initial_stream_window_size(config.proxy.http2.settings.initial_window_size)
                .http2_max_frame_size(config.proxy.http2.settings.max_frame_size)
                .http2_initial_connection_window_size(config.proxy.http2.settings.initial_window_size);
        }

        let http_client = client_builder.build(https_connector);

        Ok(Self {
            config: Arc::new(config),
            storage,
            rate_limiter,
            circuit_breaker,
            metrics,
            behavioral_mimicry,
            user_agent_pool,
            header_manipulator,
            iptv_rewriter,
            http_client: Arc::new(http_client),
            browser_profiles,
        })
    }

    fn select_profile(&self) -> &BrowserProfile {
        use rand::seq::SliceRandom;
        self.browser_profiles
            .choose(&mut rand::thread_rng())
            .unwrap_or(&self.browser_profiles[0])
    }

    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let start_time = Instant::now();
        self.metrics.increment_connections();

        // Extract host before consuming request for metrics
        let req_host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string());

        let result = self.handle_request_internal(req, client_addr).await;

        self.metrics.decrement_connections();

        match result {
            Ok(response) => {
                let duration = start_time.elapsed().as_secs_f64();
                let bytes = response
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_else(|| response.body().size_hint().exact().unwrap_or(0));
                
                if let Some(host_str) = &req_host {
                    self.metrics.record_request(host_str, bytes, duration);
                }

                Ok(response)
            }
            Err(e) => {
                error!("Proxy error: {}", e);
                Err(e)
            }
        }
    }

    async fn handle_request_internal(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| Error::Proxy("Missing Host header".to_string()))?
            .to_string();

        // Remover porta do host para lookup (tv.local:8443 -> tv.local)
        let host_without_port = host.split(':').next().unwrap_or(&host).to_string();

        debug!("Handling request for host: {} from {}", host_without_port, client_addr);

        if self.rate_limiter.check_ip(client_addr.ip()).is_err() {
            warn!("Rate limit exceeded for IP: {}", client_addr.ip());
            return Ok(Self::error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
        }

        if self.rate_limiter.check_domain(&host_without_port).is_err() {
            warn!("Rate limit exceeded for domain: {}", host_without_port);
            return Ok(Self::error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
        }

        let domain_mapping = match self.storage.get_domain(&host_without_port) {
            Some(mapping) => mapping,
            None => {
                // Se localhost/127.0.0.1/IP sem domínio configurado, apenas retornar Not Found genérico
                // NÃO revelar que é um proxy!
                return Err(Error::NotFound("Not Found".to_string()));
            }
        };

        if !domain_mapping.enabled {
            return Ok(Self::error_response(StatusCode::SERVICE_UNAVAILABLE, "Domain disabled"));
        }

        let target_url = domain_mapping.target;

        self.behavioral_mimicry.apply_delay(&host_without_port).await;

        let result = self
            .circuit_breaker
            .call(&host_without_port, || self.proxy_request(req, &target_url, &host_without_port))
            .await;

        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                self.metrics.record_error(&host_without_port, "proxy_error");
                error!("Circuit breaker error for {}: {}", host_without_port, e);
                Ok(Self::error_response(StatusCode::BAD_GATEWAY, "Service temporarily unavailable"))
            }
        }
    }

    async fn proxy_request(
        &self,
        mut req: Request<Incoming>,
        target_url: &str,
        host: &str,
    ) -> Result<Response<ResponseBody>> {
        let director = RequestDirector::new(target_url)?;
        let request_path = req.uri().path().to_string();
        let request_path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string();
        
        // Select a random browser profile (atomic unit: UA + sec-ch-ua + Accept + HTTP/2 all correlated)
        let profile = self.select_profile();
        debug!("Using browser profile: {} for {}", profile.name, host);

        // STEALTH: Apply TLS GREASE temporal jitter (micro-delay to avoid timing fingerprint)
        ExtensionRandomizer::apply_temporal_jitter().await;

        // Detect WebSocket upgrade requests
        let is_websocket = req.headers().get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        if is_websocket {
            // STEALTH: Apply browser-specific WebSocket handshake headers
            let ws_fp = WebSocketFingerprinter::new(profile.clone());
            let ws_key = ws_fp.generate_ws_key();
            let ws_ext = ws_fp.build_extensions();
            if let Ok(value) = ws_key.parse() {
                req.headers_mut().insert("sec-websocket-key", value);
            }
            if let Ok(value) = "13".parse() {
                req.headers_mut().insert("sec-websocket-version", value);
            }
            if !ws_ext.is_empty() {
                if let Ok(value) = ws_ext.parse() {
                    req.headers_mut().insert("sec-websocket-extensions", value);
                }
            }
            info!("WebSocket upgrade with {} fingerprint for {}", profile.name, host);
        }

        // Clean proxy-revealing headers, then apply correlated stealth headers from profile
        self.header_manipulator.clean_headers(req.headers_mut());
        self.header_manipulator.add_stealth_headers_for_profile(req.headers_mut(), profile);

        if let Some(referer) = self.behavioral_mimicry.get_referer(host) {
            if let Ok(value) = referer.parse() {
                req.headers_mut().insert(http::header::REFERER, value);
            }
        }

        // STEALTH: Enforce browser-specific header order using headermap_to_ordered
        if self.config.stealth.header_order.preserve {
            let ordered = headermap_to_ordered(req.headers(), profile);
            debug!("Header order enforced: {} headers for profile {}", ordered.len(), profile.name);
            let headers = req.headers_mut();
            headers.clear();
            for (name, value) in &ordered {
                if !name.starts_with(':') {
                    if let (Ok(hn), Ok(hv)) = (
                        http::header::HeaderName::from_bytes(name.as_bytes()),
                        http::header::HeaderValue::from_str(value),
                    ) {
                        headers.append(hn, hv);
                    }
                }
            }
        }

        let (parts, body) = req.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to read request body: {}", e)))?
            .to_bytes();

        let new_req = director.modify_request(parts, Full::new(body_bytes))?;

        let response = self
            .http_client
            .request(new_req)
            .await
            .map_err(|e| Error::Proxy(format!("HTTP request failed: {}", e)))?;

        let current_url = format!("{}://{}{}", "https", host, request_path_and_query);
        self.behavioral_mimicry.update_referer(host, current_url);

        let (mut parts, body) = response.into_parts();

        // STEALTH: Header operations (no body access needed — works with streaming)
        self.header_manipulator.sanitize_response_headers(&mut parts.headers);
        parts.headers.insert(
            http::header::SERVER,
            "nginx/1.24.0".parse().unwrap(),
        );

        // Check if IPTV rewriting is needed BEFORE consuming the body
        let needs_rewrite = self.iptv_rewriter.read().await.should_rewrite(&request_path);
        let is_encoded = parts.headers.contains_key(http::header::CONTENT_ENCODING);

        if needs_rewrite && !is_encoded {
            // IPTV rewriting requires full body buffering
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| Error::Proxy(format!("Failed to read response body: {}", e)))?
                .to_bytes();

            let mut final_body = body_bytes.clone();
            let mut rewriter = self.iptv_rewriter.write().await;
            rewriter.set_proxy_origin("https", host);
            if let Ok(rewritten) = rewriter.rewrite_content(&body_bytes, target_url, request_path) {
                final_body = Bytes::from(rewritten);
            }

            if let Ok(content_length) = http::header::HeaderValue::from_str(&final_body.len().to_string()) {
                parts.headers.insert(http::header::CONTENT_LENGTH, content_length);
            }
            parts.headers.remove(http::header::TRANSFER_ENCODING);

            Ok(Response::from_parts(parts, full(final_body)))
        } else {
            if needs_rewrite && is_encoded {
                warn!("Skipping IPTV rewrite for encoded response on {}", host);
            }
            // TRUE STREAMING: pipe upstream body directly to client without buffering
            // This avoids loading the entire response into memory for large files/media
            Ok(Response::from_parts(parts, body.boxed()))
        }
    }

    fn error_response(status: StatusCode, _message: &str) -> Response<ResponseBody> {
        // STEALTH: All error responses mimic nginx to prevent proxy detection
        let (nginx_status, nginx_title) = match status {
            StatusCode::TOO_MANY_REQUESTS => (StatusCode::SERVICE_UNAVAILABLE, "503 Service Temporarily Unavailable"),
            StatusCode::BAD_GATEWAY => (StatusCode::BAD_GATEWAY, "502 Bad Gateway"),
            StatusCode::SERVICE_UNAVAILABLE => (StatusCode::SERVICE_UNAVAILABLE, "503 Service Temporarily Unavailable"),
            _ => (StatusCode::NOT_FOUND, "404 Not Found"),
        };
        let body = format!(
            "<html>\r\n<head><title>{}</title></head>\r\n<body>\r\n<center><h1>{}</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n",
            nginx_title, nginx_title
        );
        Response::builder()
            .status(nginx_status)
            .header(http::header::CONTENT_TYPE, "text/html")
            .header(http::header::SERVER, "nginx/1.24.0")
            .body(full(Bytes::from(body)))
            .unwrap()
    }
}
