use crate::circuit_breaker::CircuitBreaker;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::MetricsCollector;
use crate::proxy::{IptvRewriter, RequestDirector};
use crate::rate_limit::RateLimiter;
use crate::stealth::{BehavioralMimicry, HeaderManipulator, UserAgentPool};
use crate::storage::Storage;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct ProxyHandler {
    #[allow(dead_code)]
    config: Arc<Config>,
    storage: Storage,
    rate_limiter: RateLimiter,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<MetricsCollector>,
    behavioral_mimicry: BehavioralMimicry,
    user_agent_pool: UserAgentPool,
    header_manipulator: HeaderManipulator,
    iptv_rewriter: Arc<RwLock<IptvRewriter>>,
    http_client: Arc<hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >>,
}

impl ProxyHandler {
    pub fn new(config: Config, storage: Storage, metrics: Arc<MetricsCollector>) -> Result<Self> {
        let rate_limiter = RateLimiter::new(
            config.rate_limit.per_ip,
            config.rate_limit.per_domain,
            config.rate_limit.burst,
            config.rate_limit.enabled,
        );

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

        let http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let http_client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(http_connector);

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
        })
    }

    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        let start_time = Instant::now();
        self.metrics.increment_connections();

        let result = self.handle_request_internal(req, client_addr).await;

        self.metrics.decrement_connections();

        match result {
            Ok(response) => {
                let duration = start_time.elapsed().as_secs_f64();
                let bytes = response.body().size_hint().exact().unwrap_or(0);
                
                if let Some(host) = response.headers().get(http::header::HOST) {
                    if let Ok(host_str) = host.to_str() {
                        self.metrics.record_request(host_str, bytes, duration);
                    }
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
    ) -> Result<Response<Full<Bytes>>> {
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
    ) -> Result<Response<Full<Bytes>>> {
        let director = RequestDirector::new(target_url)?;
        
        let user_agent = self.user_agent_pool.random();
        self.header_manipulator.clean_headers(req.headers_mut());
        self.header_manipulator.add_stealth_headers(req.headers_mut(), &user_agent);

        if let Some(referer) = self.behavioral_mimicry.get_referer(host) {
            req.headers_mut().insert(http::header::REFERER, referer.parse().unwrap());
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

        let current_url = format!("{}://{}{}", "https", host, "/");
        self.behavioral_mimicry.update_referer(host, current_url);

        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to read response body: {}", e)))?
            .to_bytes();

        let mut final_body = body_bytes.clone();

        let path = url::Url::parse(target_url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/".to_string());
        if self.iptv_rewriter.read().await.should_rewrite(&path) {
            let mut rewriter = self.iptv_rewriter.write().await;
            rewriter.set_proxy_origin("https", host);
            
            if let Ok(rewritten) = rewriter.rewrite_content(&body_bytes, target_url, path) {
                final_body = Bytes::from(rewritten);
            }
        }

        let mut response = Response::from_parts(parts, Full::new(final_body));
        response.headers_mut().remove("content-encoding");

        Ok(response)
    }

    fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }
}
