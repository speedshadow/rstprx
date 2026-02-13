use crate::auth::AuthManager;
use crate::auth_middleware::SessionManager;
use crate::acme::AcmeClient;
use crate::config::Config;
use crate::metrics::MetricsCollector;
use crate::storage::Storage;
use crate::tls_manager::TlsManager;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use serde::Deserialize;

#[derive(Clone)]
pub struct FrontendHandler {
    config: Arc<Config>,
    storage: Storage,
    _auth: Arc<AuthManager>,
    metrics: Arc<MetricsCollector>,
    tls_manager: Arc<TlsManager>,
    session_manager: Arc<SessionManager>,
    admin_path: String,
}

impl FrontendHandler {
    pub fn new(
        config: Arc<Config>,
        storage: Storage,
        auth: Arc<AuthManager>,
        metrics: Arc<MetricsCollector>,
        tls_manager: Arc<TlsManager>,
    ) -> Self {
        let session_manager = Arc::new(SessionManager::new(auth.clone()));
        let admin_path = config.server.admin_path.clone();
        
        Self {
            config,
            storage,
            _auth: auth,
            metrics,
            tls_manager,
            session_manager,
            admin_path,
        }
    }

    fn api_delete_domain(&self, subdomain_raw: &str) -> Response<Full<Bytes>> {
        let subdomain = match urlencoding::decode(subdomain_raw) {
            Ok(decoded) => decoded.to_string(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid domain")))
                    .unwrap()
            }
        };

        if subdomain.is_empty() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Domain required")))
                .unwrap();
        }

        match self.storage.delete_domain(&subdomain) {
            Ok(_) => {
                self.tls_manager.remove_cert(&subdomain);
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(_) => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Domain not found")))
                .unwrap(),
        }
    }

    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        let path = req.uri().path();
        let metrics_path = self.config.monitoring.prometheus.path.as_str();
        
        // Normalizar path: remover trailing slash exceto root
        let normalized_path = if path.len() > 1 && path.ends_with('/') {
            &path[..path.len() - 1]
        } else {
            path
        };

        // Check if accessing admin area
        let admin_base = &self.admin_path;
        let is_admin_area = normalized_path.starts_with(admin_base) && normalized_path != format!("{}/login", admin_base);
        
        // Auth check for protected routes (admin + API + metrics)
        let metrics_requires_auth = self.config.monitoring.prometheus.enabled
            && self.config.monitoring.prometheus.auth_required
            && normalized_path == metrics_path;
        let is_protected_api = normalized_path.starts_with("/api/") || metrics_requires_auth;
        
        if (is_admin_area || is_protected_api) && !self.session_manager.is_authenticated(&req) {
            // For API/metrics, return 401 instead of redirect
            if is_protected_api {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from("{\"error\": \"Unauthorized\"}"))) 
                    .unwrap();
            }
            warn!("Unauthorized access attempt to: {}", normalized_path);
            return self.redirect_to_login();
        }

        // Dynamic admin routing
        let dashboard_path = admin_base.clone();
        let login_path = format!("{}/login", admin_base);
        let api_login_path = format!("{}/api/login", admin_base);
        
        match (req.method(), normalized_path) {
            (&http::Method::GET, p) if p == dashboard_path || p == "/" => {
                if p == "/" && !self.session_manager.is_authenticated(&req) {
                    if self.config.server.fake_website_enabled {
                        return self.page_fake_maintenance();
                    }
                    return self.redirect_to_login();
                }
                self.page_dashboard()
            },
            (&http::Method::GET, p) if p == login_path => self.page_login(),
            (&http::Method::POST, p) if p == api_login_path => self.api_login(req).await,
            (&http::Method::GET, p) if p == "/logout" || p == format!("{}/logout", admin_base) => self.logout(),
            (&http::Method::GET, p) if p == format!("{}/domains", admin_base) => self.page_domains(),
            (&http::Method::GET, p) if p == format!("{}/settings", admin_base) => self.page_settings(),
            (&http::Method::GET, p) if p == format!("{}/stats", admin_base) => self.page_stats(),
            (&http::Method::GET, p) if p == format!("{}/certificates", admin_base) => self.page_certificates(),
            (&http::Method::GET, "/health") => self.health(),
            (&http::Method::GET, "/api/stats") => self.api_stats(),
            (&http::Method::GET, "/api/stats/html") => self.api_stats_html(),
            (&http::Method::GET, "/api/stats/domains/html") => self.api_domains_stats_html(),
            (&http::Method::GET, "/api/domains") => self.api_list_domains(),
            (&http::Method::GET, "/api/domains/html") => self.api_domains_html(),
            (&http::Method::POST, "/api/domains") => self.api_add_domain(req).await,
            (&http::Method::DELETE, path) if path.starts_with("/api/domains/") => {
                let subdomain = path.trim_start_matches("/api/domains/");
                self.api_delete_domain(subdomain)
            }
            (&http::Method::GET, "/api/certificates") => self.api_certificates(),
            (&http::Method::POST, path) if path.starts_with("/api/renew/") => {
                let domain = path.trim_start_matches("/api/renew/");
                self.api_renew_certificate(domain).await
            }
            (&http::Method::POST, p) if p == format!("{}/api/test-dns", admin_base) => self.api_test_dns(req).await,
            (&http::Method::POST, p) if p == format!("{}/api/generate-certificate", admin_base) => self.api_generate_certificate(req).await,
            (&http::Method::GET, p)
                if p == metrics_path && self.config.monitoring.prometheus.enabled =>
            {
                self.metrics_endpoint()
            }
            _ => self.not_found(),
        }
    }

    fn load_template(&self, name: &str) -> String {
        let path = format!("templates/{}.html", name);
        fs::read_to_string(&path).unwrap_or_else(|e| {
            error!("Failed to load template {}: {}", name, e);
            format!("<h1>Error loading template: {}</h1>", name)
        })
    }

    fn render_page(&self, title: &str, content: &str) -> Response<Full<Bytes>> {
        let layout = self.load_template("layout");
        let html = layout
            .replace("{{TITLE}}", title)
            .replace("{{CONTENT}}", content);

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    fn page_dashboard(&self) -> Response<Full<Bytes>> {
        let content = self.load_template("dashboard");
        self.render_page("Dashboard", &content)
    }

    fn page_domains(&self) -> Response<Full<Bytes>> {
        let content = self.load_template("domains");
        self.render_page("Domains", &content)
    }

    fn page_settings(&self) -> Response<Full<Bytes>> {
        let mut content = self.load_template("settings");
        
        // Get current domain (IP or configured domain)
        let current_domain = match std::env::var("SERVER_IP") {
            Ok(ip) => format!("{}:8443", ip),
            Err(_) => "localhost:8443".to_string()
        };
        
        // Get certificate status
        let cert_status = if self.config.server.tls.mode == "autocert" {
            "✅ ACME (Let's Encrypt)"
        } else {
            "⚠️ Self-signed"
        };
        
        // Get primary domain if configured
        let primary_domain = self.config.server.tls.selfsigned_hosts
            .iter()
            .find(|h| !h.contains("localhost") && !h.contains("127.0.0.1") && !h.starts_with("*."))
            .cloned()
            .unwrap_or_default();
        
        // Get ACME email if configured
        let acme_email = &self.config.server.tls.autocert.email;
        
        // Determine which cert type is checked
        let (selfsigned_checked, acme_checked, acme_display) = if self.config.server.tls.mode == "autocert" {
            ("", "checked", "block")
        } else {
            ("checked", "", "none")
        };
        
        // Replace placeholders
        content = content
            .replace("{{CURRENT_DOMAIN}}", &current_domain)
            .replace("{{CERT_STATUS}}", cert_status)
            .replace("{{PRIMARY_DOMAIN}}", &primary_domain)
            .replace("{{SELFSIGNED_CHECKED}}", selfsigned_checked)
            .replace("{{ACME_CHECKED}}", acme_checked)
            .replace("{{ACME_DISPLAY}}", acme_display)
            .replace("{{ACME_EMAIL}}", acme_email);
        
        self.render_page("Settings", &content)
    }

    fn page_stats(&self) -> Response<Full<Bytes>> {
        let mut content = self.load_template("stats");
        
        // Obter métricas reais
        let total_requests = self.metrics.get_total_requests();
        let bandwidth_bytes = self.metrics.get_total_bandwidth();
        let _active_connections = self.metrics.get_active_connections();
        
        // Formatar bandwidth
        let bandwidth_str = if bandwidth_bytes >= 1_000_000_000 {
            format!("{:.2} GB", bandwidth_bytes as f64 / 1_000_000_000.0)
        } else if bandwidth_bytes >= 1_000_000 {
            format!("{:.2} MB", bandwidth_bytes as f64 / 1_000_000.0)
        } else if bandwidth_bytes >= 1_000 {
            format!("{:.2} KB", bandwidth_bytes as f64 / 1_000.0)
        } else {
            format!("{} B", bandwidth_bytes)
        };
        
        // Contar domínios ativos (proxy configurado)
        let active_domains = self.storage.count_domains();
        
        // Substituir placeholders
        content = content.replace("{{TOTAL_REQUESTS}}", &total_requests.to_string());
        content = content.replace("{{TOTAL_BANDWIDTH}}", &bandwidth_str);
        content = content.replace("{{ACTIVE_DOMAINS}}", &active_domains.to_string());
        
        self.render_page("Statistics", &content)
    }

    pub fn page_certificates(&self) -> Response<Full<Bytes>> {
        let content = self.load_template("certificates");
        self.render_page("Certificates", &content)
    }

    #[allow(dead_code)]
    fn old_dashboard(&self) -> Response<Full<Bytes>> {
        let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elite Rama Proxy - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            max-width: 1200px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            opacity: 0.9;
            font-size: 0.9em;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 30px;
        }
        .feature {
            background: #f7f7f7;
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .feature-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        .feature-desc {
            color: #666;
            font-size: 0.9em;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Elite Rama Proxy</h1>
        <p class="subtitle">Advanced Anonymous Reverse Proxy with 2026 Stealth Technology</p>
        
        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value" id="total-requests">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Connections</div>
                <div class="stat-value" id="active-connections">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Data Transferred</div>
                <div class="stat-value" id="data-transferred">0 MB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Domains Configured</div>
                <div class="stat-value" id="domains-count">0</div>
            </div>
        </div>

        <h2 style="margin-bottom: 20px; color: #333;">Advanced Features</h2>
        <div class="features">
            <div class="feature">
                <div class="feature-title">✅ JA3/JA4 Spoofing</div>
                <div class="feature-desc">Advanced TLS fingerprint evasion</div>
            </div>
            <div class="feature">
                <div class="feature-title">🔒 Behavioral Mimicry</div>
                <div class="feature-desc">Human-like request patterns</div>
            </div>
            <div class="feature">
                <div class="feature-title">🌐 HTTP/2 Fingerprinting</div>
                <div class="feature-desc">Akamai & Cloudflare bypass</div>
            </div>
            <div class="feature">
                <div class="feature-title">🛡️ Circuit Breaker</div>
                <div class="feature-desc">Automatic failure handling</div>
            </div>
            <div class="feature">
                <div class="feature-title">⚡ IPTV Optimization</div>
                <div class="feature-desc">M3U/M3U8 streaming support</div>
            </div>
            <div class="feature">
                <div class="feature-title">🔐 JWT Authentication</div>
                <div class="feature-desc">Secure token-based auth</div>
            </div>
        </div>

        <div class="footer">
            Elite Rama Proxy v1.0.0 | Built with Rust & Rama Framework 2026
        </div>
    </div>

    <script>
        async function updateStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                document.getElementById('total-requests').textContent = data.total_requests.toLocaleString();
                document.getElementById('active-connections').textContent = data.active_connections.toLocaleString();
                document.getElementById('data-transferred').textContent = 
                    (data.total_bytes / 1024 / 1024).toFixed(2) + ' MB';
                document.getElementById('domains-count').textContent = 
                    Object.keys(data.domains || {}).length;
            } catch (e) {
                console.error('Failed to update stats:', e);
            }
        }

        updateStats();
        setInterval(updateStats, 5000);
    </script>
</body>
</html>"#;

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    fn health(&self) -> Response<Full<Bytes>> {
        let health = serde_json::json!({
            "status": "ok",
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::SERVER, "nginx/1.24.0")
            .body(Full::new(Bytes::from(health.to_string())))
            .unwrap()
    }

    fn api_stats_html(&self) -> Response<Full<Bytes>> {
        let uptime_hours = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 3600;

        let stats_html = format!(
            r#"
        <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-medium text-gray-400">Active Connections</h3>
                <i data-lucide="activity" class="w-5 h-5 text-cyber-400"></i>
            </div>
            <p class="text-3xl font-bold">0</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-medium text-gray-400">Total Requests</h3>
                <i data-lucide="zap" class="w-5 h-5 text-purple-400"></i>
            </div>
            <p class="text-3xl font-bold">0</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-medium text-gray-400">Bandwidth</h3>
                <i data-lucide="wifi" class="w-5 h-5 text-green-400"></i>
            </div>
            <p class="text-3xl font-bold">0 MB</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-medium text-gray-400">Uptime</h3>
                <i data-lucide="clock" class="w-5 h-5 text-yellow-400"></i>
            </div>
            <p class="text-3xl font-bold">{}h</p>
        </div>
        "#,
            uptime_hours
        );

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::from(stats_html)))
            .unwrap()
    }

    fn api_domains_stats_html(&self) -> Response<Full<Bytes>> {
        let domains = self.storage.list_domains();

        let rows: Vec<String> = domains
            .iter()
            .map(|dm| {
                format!(
                    r#"
            <tr class="hover:bg-gray-700/50">
                <td class="py-3 px-4">{}</td>
                <td class="py-3 px-4">0</td>
                <td class="py-3 px-4">0 MB</td>
            </tr>
            "#,
                    dm.subdomain
                )
            })
            .collect();

        let html = if rows.is_empty() {
            r#"<tr><td colspan="3" class="py-3 px-4 text-center text-gray-400">No traffic yet</td></tr>"#.to_string()
        } else {
            rows.join("")
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    fn api_domains_html(&self) -> Response<Full<Bytes>> {
        let domains = self.storage.list_domains();

        let rows: Vec<String> = domains.iter().map(|dm| {
            format!(r#"
            <tr class="hover:bg-gray-700/50 transition-colors">
                <td class="py-4 px-6">
                    <div class="flex items-center space-x-2">
                        <i data-lucide="globe" class="w-4 h-4 text-cyber-400"></i>
                        <span class="font-medium">{}</span>
                    </div>
                </td>
                <td class="py-4 px-6">
                    <code class="text-xs bg-gray-900 px-2 py-1 rounded text-gray-300">{}</code>
                </td>
                <td class="py-4 px-6">
                    <span class="inline-flex items-center space-x-1 text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded">
                        <div class="w-1.5 h-1.5 bg-green-400 rounded-full"></div>
                        <span>Active</span>
                    </span>
                </td>
                <td class="py-4 px-6 text-right">
                    <div class="flex items-center justify-end gap-2">
                        <button class="px-3 py-1.5 text-xs bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded transition-colors">
                            Edit
                        </button>
                        <button hx-delete="/api/domains/{}" 
                                hx-confirm="Delete domain {}?"
                                hx-target="closest tr"
                                hx-swap="outerHTML swap:500ms"
                                class="px-3 py-1.5 text-xs bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded transition-colors">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
            "#, dm.subdomain, dm.target, dm.subdomain, dm.subdomain)
        }).collect();

        let html = if rows.is_empty() {
            r#"
            <tr>
                <td colspan="4" class="py-12 text-center text-gray-500">
                    <i data-lucide="inbox" class="w-12 h-12 mx-auto mb-3 text-gray-600"></i>
                    <p>No domains configured yet</p>
                    <p class="text-sm mt-1">Click "Add Domain" to get started</p>
                </td>
            </tr>
            "#
            .to_string()
        } else {
            rows.join("")
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    async fn api_add_domain<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {

        let body = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid body")))
                    .unwrap()
            }
        };

        let form_data = String::from_utf8_lossy(&body);
        let mut subdomain = String::new();
        let mut target = String::new();

        for pair in form_data.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded = urlencoding::decode(value).unwrap_or_default();
                match key {
                    "subdomain" => subdomain = decoded.to_string(),
                    "target" => target = decoded.to_string(),
                    _ => {}
                }
            }
        }

        if subdomain.is_empty() || target.is_empty() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Subdomain and target required")))
                .unwrap();
        }

        match self.storage.add_domain(subdomain.clone(), target) {
            Ok(_) => {
                // 🔥 Auto-gerar certificado TLS para o novo domínio (HOT-RELOAD!)
                if let Err(e) = self.tls_manager.generate_and_load_cert(&subdomain).await {
                    error!("Failed to generate TLS cert for {}: {}", subdomain, e);
                } else {
                    info!("✅ TLS certificate auto-generated for: {}", subdomain);
                }

                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from("OK")))
                    .unwrap()
            }
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Failed to add domain")))
                .unwrap(),
        }
    }

    fn api_stats(&self) -> Response<Full<Bytes>> {
        let stats = self.metrics.get_stats();
        let json = serde_json::to_string(&stats).unwrap();

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .unwrap()
    }

    fn api_list_domains(&self) -> Response<Full<Bytes>> {
        let domains = self.storage.list_domains();
        let json = serde_json::to_string(&domains).unwrap();

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .unwrap()
    }

    fn page_login(&self) -> Response<Full<Bytes>> {
        let html = self.load_template("login");
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    fn redirect_to_login(&self) -> Response<Full<Bytes>> {
        let login_url = format!("{}/login", self.admin_path);
        Response::builder()
            .status(StatusCode::FOUND)
            .header(http::header::LOCATION, login_url)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn page_fake_maintenance(&self) -> Response<Full<Bytes>> {
        // Carregar template baseado na configuração
        let template_name = match self.config.server.fake_website_type.as_str() {
            "nginx" => "fake_nginx",
            "apache" => "fake_apache",
            "construction" => "fake_construction",
            _ => "fake_maintenance",
        };
        
        let html = self.load_template(template_name);
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }

    async fn api_login<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        #[derive(Deserialize)]
        struct LoginRequest {
            username: String,
            password: String,
        }

        // Parse request body
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from("{\"error\": \"Invalid request\"}")))
                    .unwrap()
            }
        };

        let login_req: LoginRequest = match serde_json::from_slice(&body_bytes) {
            Ok(req) => req,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from("{\"error\": \"Invalid JSON\"}")))
                    .unwrap()
            }
        };

        // Verify credentials against config
        let config_user = &self.config.auth.default_user;
        let config_pass_hash = &self.config.auth.default_password;

        if login_req.username != *config_user {
            warn!("Failed login attempt for user: {}", login_req.username);
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from("{\"error\": \"Invalid credentials\"}")))
                .unwrap();
        }

        if !AuthManager::verify_password(&login_req.password, config_pass_hash) {
            warn!("Failed password verification for user: {}", login_req.username);
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from("{\"error\": \"Invalid credentials\"}")))
                .unwrap();
        }

        // Generate session cookie
        let session_cookie = match self.session_manager.generate_session_cookie(&login_req.username) {
            Ok(cookie) => cookie,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from("{\"error\": \"Failed to create session\"}")))
                    .unwrap()
            }
        };

        info!("Successful login for user: {}", login_req.username);

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SET_COOKIE, session_cookie)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from("{\"success\": true}")))
            .unwrap()
    }

    fn logout(&self) -> Response<Full<Bytes>> {
        let logout_cookie = SessionManager::generate_logout_cookie();
        let login_url = format!("{}/login", self.admin_path);
        
        Response::builder()
            .status(StatusCode::FOUND)
            .header(http::header::SET_COOKIE, logout_cookie)
            .header(http::header::LOCATION, login_url)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn metrics_endpoint(&self) -> Response<Full<Bytes>> {
        match self.metrics.render_metrics() {
            Ok(metrics) => Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(metrics)))
                .unwrap(),
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Failed to render metrics")))
                .unwrap(),
        }
    }

    fn not_found(&self) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap()
    }

    /// API endpoint para listar certificados REAIS do filesystem
    fn api_certificates(&self) -> Response<Full<Bytes>> {
        use serde_json::json;
        use std::fs;
        use std::path::Path;

        let cert_dir = Path::new("certs/domains");
        let mut certificates = Vec::new();
        let mut total = 0;
        let mut valid = 0;
        let mut expiring = 0;
        let mut expired = 0;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Ler certificados do filesystem
        if cert_dir.exists() && cert_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(cert_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                        if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                            total += 1;
                            
                            // Parse real certificate expiry from PEM/DER
                            let (days_remaining, expiry_date) = match fs::read_to_string(&path) {
                                Ok(pem_str) => {
                                    Self::parse_cert_expiry(&pem_str, now)
                                }
                                Err(_) => (365, "Read error".to_string()),
                            };

                            let status = if days_remaining < 0 {
                                expired += 1;
                                "Expired"
                            } else if days_remaining <= 30 {
                                expiring += 1;
                                "Expiring"
                            } else {
                                valid += 1;
                                "Valid"
                            };

                            let cert_type = if domain.starts_with('*') { "Wildcard" } else { "Standard" };
                            
                            certificates.push(json!({
                                "domain": domain,
                                "type": cert_type,
                                "expiry_date": expiry_date,
                                "days_remaining": days_remaining,
                                "status": status
                            }));
                        }
                    }
                }
            }
        }

        let response = json!({
            "total": total,
            "valid": valid,
            "expiring": expiring,
            "expired": expired,
            "certificates": certificates
        });

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(response.to_string())))
            .unwrap()
    }

    /// Parse certificate expiry from PEM string using pure Rust (no cmake deps)
    fn parse_cert_expiry(pem_str: &str, now_epoch: i64) -> (i64, String) {
        match pem::parse(pem_str) {
            Ok(pem_block) => {
                let der = pem_block.contents();
                // X.509 DER: SEQUENCE { tbsCertificate SEQUENCE { ... validity SEQUENCE { notBefore, notAfter } } }
                // Parse notAfter from DER-encoded certificate
                match Self::extract_not_after_from_der(der) {
                    Some(not_after_epoch) => {
                        let remaining = (not_after_epoch - now_epoch) / 86400;
                        let dt = chrono::DateTime::from_timestamp(not_after_epoch, 0)
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        (remaining, dt)
                    }
                    None => (365, "DER parse error".to_string()),
                }
            }
            Err(_) => (365, "PEM parse error".to_string()),
        }
    }

    /// Extract notAfter timestamp from DER-encoded X.509 certificate
    /// Minimal ASN.1 parser — walks the DER structure to find validity dates
    fn extract_not_after_from_der(der: &[u8]) -> Option<i64> {
        // Skip outer SEQUENCE tag+length
        let inner = Self::skip_asn1_tag_length(der, 0x30)?;
        // Skip tbsCertificate SEQUENCE tag+length
        let tbs = Self::skip_asn1_tag_length(inner, 0x30)?;
        
        let mut pos = tbs;
        // Skip version (context tag [0] if present)
        if !pos.is_empty() && pos[0] == 0xa0 {
            let (_, rest) = Self::read_asn1_tlv(pos)?;
            pos = rest;
        }
        // Skip serialNumber (INTEGER)
        let (_, pos) = Self::read_asn1_tlv(pos)?;
        // Skip signature (SEQUENCE)
        let (_, pos) = Self::read_asn1_tlv(pos)?;
        // Skip issuer (SEQUENCE)
        let (_, pos) = Self::read_asn1_tlv(pos)?;
        // validity SEQUENCE { notBefore, notAfter }
        let validity = Self::skip_asn1_tag_length(pos, 0x30)?;
        // Skip notBefore
        let (_, after_not_before) = Self::read_asn1_tlv(validity)?;
        // notAfter is next
        let (not_after_bytes, _) = Self::read_asn1_tlv(after_not_before)?;
        
        // Parse UTCTime or GeneralizedTime
        let time_str = std::str::from_utf8(not_after_bytes).ok()?;
        Self::parse_asn1_time(time_str)
    }

    fn skip_asn1_tag_length(data: &[u8], expected_tag: u8) -> Option<&[u8]> {
        if data.is_empty() || data[0] != expected_tag {
            return None;
        }
        let (_, _rest) = Self::read_asn1_tlv(data)?;
        // We need the content, not the rest after. Re-parse to get content.
        let (content, _) = Self::read_asn1_content(&data[1..])?;
        Some(content)
    }

    fn read_asn1_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
        if data.is_empty() {
            return None;
        }
        let (content, rest) = Self::read_asn1_content(&data[1..])?;
        Some((content, rest))
    }

    fn read_asn1_content(data: &[u8]) -> Option<(&[u8], &[u8])> {
        if data.is_empty() {
            return None;
        }
        let (length, header_len) = if data[0] < 0x80 {
            (data[0] as usize, 1)
        } else if data[0] == 0x81 {
            if data.len() < 2 { return None; }
            (data[1] as usize, 2)
        } else if data[0] == 0x82 {
            if data.len() < 3 { return None; }
            (((data[1] as usize) << 8) | (data[2] as usize), 3)
        } else if data[0] == 0x83 {
            if data.len() < 4 { return None; }
            (((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize), 4)
        } else {
            return None;
        };
        
        let start = header_len;
        let end = start + length;
        if end > data.len() {
            return None;
        }
        Some((&data[start..end], &data[end..]))
    }

    fn parse_asn1_time(s: &str) -> Option<i64> {
        // UTCTime: YYMMDDHHMMSSZ  or  GeneralizedTime: YYYYMMDDHHMMSSZ
        let s = s.trim_end_matches('Z');
        let (year, rest) = if s.len() >= 14 {
            // GeneralizedTime
            (s[..4].parse::<i32>().ok()?, &s[4..])
        } else if s.len() >= 12 {
            // UTCTime
            let y: i32 = s[..2].parse().ok()?;
            let year = if y >= 50 { 1900 + y } else { 2000 + y };
            (year, &s[2..])
        } else {
            return None;
        };
        
        let month: u32 = rest[..2].parse().ok()?;
        let day: u32 = rest[2..4].parse().ok()?;
        let hour: u32 = rest[4..6].parse().ok()?;
        let min: u32 = rest[6..8].parse().ok()?;
        let sec: u32 = rest[8..10].parse().ok()?;
        
        let dt = chrono::NaiveDate::from_ymd_opt(year, month, day)?
            .and_hms_opt(hour, min, sec)?;
        Some(dt.and_utc().timestamp())
    }

    fn is_valid_domain_name(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 253 || domain.contains("..") {
            return false;
        }
        if domain
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '\\' || c == '\0')
        {
            return false;
        }
        domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && domain.contains('.')
    }

    async fn issue_acme_certificate(&self, domain: &str, email: &str) -> std::result::Result<(), String> {
        if !Self::is_valid_domain_name(domain) {
            return Err("Invalid domain format".to_string());
        }
        if email.is_empty() {
            return Err("ACME email is required".to_string());
        }

        let directory_url = std::env::var("ACME_DIRECTORY_URL")
            .unwrap_or_else(|_| AcmeClient::letsencrypt_production().to_string());

        let cache_dir = self.config.server.tls.autocert.cache_dir.trim_end_matches('/');
        let account_key_path = format!("{}/account.key", cache_dir);
        let acme_client = AcmeClient::new(directory_url, email.to_string(), account_key_path);

        let webroot_path = format!("webroot/{}", domain);
        let (cert_pem, key_pem) = acme_client
            .request_certificate(vec![domain.to_string()], &webroot_path)
            .await
            .map_err(|e| format!("ACME request failed: {}", e))?;

        let cert_dir = PathBuf::from(&self.config.server.tls.cert_dir);
        tokio::fs::create_dir_all(&cert_dir)
            .await
            .map_err(|e| format!("Failed to create certificate directory: {}", e))?;

        let cert_path = cert_dir.join(format!("{}.pem", domain));
        let key_path = cert_dir.join(format!("{}.key", domain));

        tokio::fs::write(&cert_path, cert_pem)
            .await
            .map_err(|e| format!("Failed to write certificate: {}", e))?;
        tokio::fs::write(&key_path, key_pem)
            .await
            .map_err(|e| format!("Failed to write private key: {}", e))?;

        self.tls_manager
            .load_certificate(domain, &cert_path, &key_path)
            .await
            .map_err(|e| format!("Failed to hot-reload certificate: {}", e))?;

        Ok(())
    }

    /// API endpoint para forçar renovação de certificado
    async fn api_renew_certificate(&self, domain: &str) -> Response<Full<Bytes>> {
        use serde_json::json;

        let decoded_domain = match urlencoding::decode(domain) {
            Ok(value) => value.to_string(),
            Err(_) => {
                let response = json!({
                    "success": false,
                    "error": "Invalid domain encoding"
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap();
            }
        };

        info!("Force renewal requested for domain: {}", decoded_domain);

        if !self.config.server.tls.autocert.enabled {
            let response = json!({
                "success": false,
                "error": "Autocert is disabled in configuration"
            });
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response.to_string())))
                .unwrap();
        }

        let email = self.config.server.tls.autocert.email.trim();
        match self.issue_acme_certificate(&decoded_domain, email).await {
            Ok(_) => {
                let response = json!({
                    "success": true,
                    "domain": decoded_domain,
                    "message": "Certificate renewed successfully"
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap()
            }
            Err(err_msg) => {
                let response = json!({
                    "success": false,
                    "domain": decoded_domain,
                    "error": err_msg
                });
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap()
            }
        }
    }

    /// API endpoint para testar configuração DNS
    async fn api_test_dns<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        use serde::Deserialize;
        use serde_json::json;
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
        use trust_dns_resolver::TokioAsyncResolver;

        #[derive(Deserialize)]
        struct TestDnsRequest {
            domain: String,
        }

        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                let response = json!({
                    "success": false,
                    "error": "Invalid request body"
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap();
            }
        };

        let test_req: TestDnsRequest = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(_) => {
                let response = json!({
                    "success": false,
                    "error": "Invalid JSON"
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap();
            }
        };

        info!("Testing DNS for domain: {}", test_req.domain);

        if !Self::is_valid_domain_name(&test_req.domain) {
            let response = json!({
                "success": false,
                "error": "Invalid domain format"
            });

            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response.to_string())))
                .unwrap();
        }

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let (ipv4_lookup, ipv6_lookup) = tokio::join!(
            resolver.ipv4_lookup(test_req.domain.as_str()),
            resolver.ipv6_lookup(test_req.domain.as_str())
        );

        let ipv4: Vec<String> = ipv4_lookup
            .ok()
            .map(|lookup| lookup.iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default();
        let ipv6: Vec<String> = ipv6_lookup
            .ok()
            .map(|lookup| lookup.iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default();

        let success = !(ipv4.is_empty() && ipv6.is_empty());
        let response = if success {
            json!({
                "success": true,
                "message": format!("DNS resolved successfully for {}", test_req.domain),
                "ipv4": ipv4,
                "ipv6": ipv6
            })
        } else {
            json!({
                "success": false,
                "error": format!("DNS lookup failed for {}", test_req.domain)
            })
        };

        Response::builder()
            .status(if success { StatusCode::OK } else { StatusCode::BAD_GATEWAY })
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(response.to_string())))
            .unwrap()
    }

    /// API endpoint para gerar certificado SSL
    async fn api_generate_certificate<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        use serde::Deserialize;
        use serde_json::json;

        #[derive(Deserialize)]
        struct GenerateCertRequest {
            domain: String,
            cert_type: String,
            email: String,
        }

        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                let response = json!({
                    "success": false,
                    "error": "Invalid request body"
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap();
            }
        };

        let cert_req: GenerateCertRequest = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(_) => {
                let response = json!({
                    "success": false,
                    "error": "Invalid JSON"
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(response.to_string())))
                    .unwrap();
            }
        };

        info!("Certificate generation requested for domain: {} (type: {})", 
              cert_req.domain, cert_req.cert_type);

        // Validação básica
        if cert_req.domain.is_empty() {
            let response = json!({
                "success": false,
                "error": "Domain cannot be empty"
            });
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response.to_string())))
                .unwrap();
        }

        if (cert_req.cert_type == "acme" || cert_req.cert_type == "autocert") && cert_req.email.is_empty() {
            let response = json!({
                "success": false,
                "error": "Email is required for ACME certificates"
            });
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response.to_string())))
                .unwrap();
        }

        if cert_req.cert_type == "acme" || cert_req.cert_type == "autocert" {
            match self.issue_acme_certificate(&cert_req.domain, cert_req.email.trim()).await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": format!("ACME certificate generated for {}", cert_req.domain),
                        "domain": cert_req.domain,
                        "type": cert_req.cert_type
                    });

                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(response.to_string())))
                        .unwrap()
                }
                Err(err_msg) => {
                    let response = json!({
                        "success": false,
                        "error": err_msg,
                        "domain": cert_req.domain,
                        "type": cert_req.cert_type
                    });

                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(response.to_string())))
                        .unwrap()
                }
            }
        } else {
            match self.tls_manager.generate_and_load_cert(&cert_req.domain).await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": format!("Self-signed certificate generated for {}", cert_req.domain),
                        "domain": cert_req.domain,
                        "type": "selfsigned"
                    });

                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(response.to_string())))
                        .unwrap()
                }
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to generate certificate: {}", e)
                    });

                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(response.to_string())))
                        .unwrap()
                }
            }
        }
    }
}
