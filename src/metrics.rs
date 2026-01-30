use crate::types::{DomainStats, ProxyStats};
use dashmap::DashMap;
use prometheus::{Counter, CounterVec, Gauge, HistogramVec, Opts, Registry, TextEncoder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct MetricsCollector {
    registry: Arc<Registry>,
    requests_total: Counter,
    requests_by_domain: CounterVec,
    bytes_total: Counter,
    bytes_by_domain: CounterVec,
    active_connections: Gauge,
    response_time: HistogramVec,
    errors_total: CounterVec,

    stats_requests: Arc<AtomicU64>,
    stats_bytes: Arc<AtomicU64>,
    stats_connections: Arc<AtomicU64>,
    domain_stats: Arc<DashMap<String, DomainStatsInternal>>,
}

#[derive(Default)]
struct DomainStatsInternal {
    requests: AtomicU64,
    bytes: AtomicU64,
    last_request: AtomicU64,
    errors: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let requests_total =
            Counter::new("proxy_requests_total", "Total number of proxy requests")?;
        registry.register(Box::new(requests_total.clone()))?;

        let requests_by_domain = CounterVec::new(
            Opts::new("proxy_requests_by_domain", "Requests by domain"),
            &["domain"],
        )?;
        registry.register(Box::new(requests_by_domain.clone()))?;

        let bytes_total = Counter::new("proxy_bytes_total", "Total bytes transferred")?;
        registry.register(Box::new(bytes_total.clone()))?;

        let bytes_by_domain = CounterVec::new(
            Opts::new("proxy_bytes_by_domain", "Bytes by domain"),
            &["domain"],
        )?;
        registry.register(Box::new(bytes_by_domain.clone()))?;

        let active_connections = Gauge::new("proxy_active_connections", "Active connections")?;
        registry.register(Box::new(active_connections.clone()))?;

        let response_time = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_response_time_seconds",
                "Response time in seconds",
            ),
            &["domain"],
        )?;
        registry.register(Box::new(response_time.clone()))?;

        let errors_total = CounterVec::new(
            Opts::new("proxy_errors_total", "Total errors"),
            &["domain", "error_type"],
        )?;
        registry.register(Box::new(errors_total.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            requests_total,
            requests_by_domain,
            bytes_total,
            bytes_by_domain,
            active_connections,
            response_time,
            errors_total,
            stats_requests: Arc::new(AtomicU64::new(0)),
            stats_bytes: Arc::new(AtomicU64::new(0)),
            stats_connections: Arc::new(AtomicU64::new(0)),
            domain_stats: Arc::new(DashMap::new()),
        })
    }

    pub fn record_request(&self, domain: &str, bytes: u64, duration_secs: f64) {
        self.requests_total.inc();
        self.requests_by_domain.with_label_values(&[domain]).inc();
        self.bytes_total.inc_by(bytes as f64);
        self.bytes_by_domain
            .with_label_values(&[domain])
            .inc_by(bytes as f64);
        self.response_time
            .with_label_values(&[domain])
            .observe(duration_secs);

        self.stats_requests.fetch_add(1, Ordering::Relaxed);
        self.stats_bytes.fetch_add(bytes, Ordering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.domain_stats
            .entry(domain.to_string())
            .or_insert_with(DomainStatsInternal::default)
            .value()
            .requests
            .fetch_add(1, Ordering::Relaxed);

        self.domain_stats
            .get(domain)
            .unwrap()
            .bytes
            .fetch_add(bytes, Ordering::Relaxed);

        self.domain_stats
            .get(domain)
            .unwrap()
            .last_request
            .store(now, Ordering::Relaxed);
    }

    pub fn record_error(&self, domain: &str, error_type: &str) {
        self.errors_total
            .with_label_values(&[domain, error_type])
            .inc();

        self.domain_stats
            .entry(domain.to_string())
            .or_insert_with(DomainStatsInternal::default)
            .value()
            .errors
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.active_connections.inc();
        self.stats_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.dec();
        self.stats_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_total_requests(&self) -> u64 {
        self.stats_requests.load(Ordering::Relaxed)
    }

    pub fn get_total_bandwidth(&self) -> u64 {
        self.stats_bytes.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> u64 {
        self.stats_connections.load(Ordering::Relaxed)
    }

    pub fn get_stats(&self) -> ProxyStats {
        let mut domain_stats = std::collections::HashMap::new();

        for entry in self.domain_stats.iter() {
            let key = entry.key().clone();
            let value = entry.value();

            domain_stats.insert(
                key,
                DomainStats {
                    requests: value.requests.load(Ordering::Relaxed),
                    bytes: value.bytes.load(Ordering::Relaxed),
                    last_request: value.last_request.load(Ordering::Relaxed) as i64,
                    errors: value.errors.load(Ordering::Relaxed),
                },
            );
        }

        ProxyStats {
            total_requests: self.stats_requests.load(Ordering::Relaxed),
            total_bytes: self.stats_bytes.load(Ordering::Relaxed),
            active_connections: self.stats_connections.load(Ordering::Relaxed),
            domains: domain_stats,
        }
    }

    pub fn render_metrics(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families)
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics collector")
    }
}
