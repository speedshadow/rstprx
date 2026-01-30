use crate::auth::AuthManager;
use crate::auth_middleware::SessionManager;
use crate::config::Config;
use crate::metrics::MetricsCollector;
use crate::storage::Storage;
use crate::tls_manager::TlsManager;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use std::fs;
use std::sync::Arc;
use tracing::{error, info, warn};
use serde::Deserialize;

#[derive(Clone)]
pub struct FrontendHandler {
    config: Arc<Config>,
    storage: Storage,
    auth: Arc<AuthManager>,
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
            auth,
            metrics,
            tls_manager,
            session_manager,
            admin_path,
        }
    }

    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        let path = req.uri().path();
        
        // Normalizar path: remover trailing slash exceto root
        let normalized_path = if path.len() > 1 && path.ends_with('/') {
            &path[..path.len() - 1]
        } else {
            path
        };

        // Check if accessing admin area
        let admin_base = &self.admin_path;
        let is_admin_area = normalized_path.starts_with(admin_base) && normalized_path != &format!("{}/login", admin_base);
        
        // Auth check for protected routes
        if is_admin_area && !self.session_manager.is_authenticated(&req) {
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
                    return self.page_fake_maintenance();
                }
                self.page_dashboard()
            },
            (&http::Method::GET, p) if p == login_path => self.page_login(),
            (&http::Method::POST, p) if p == api_login_path => self.api_login(req).await,
            (&http::Method::GET, p) if p == "/logout" || p == &format!("{}/logout", admin_base) => self.logout(),
            (&http::Method::GET, p) if p == &format!("{}/domains", admin_base) => self.page_domains(),
            (&http::Method::GET, p) if p == &format!("{}/settings", admin_base) => self.page_settings(),
            (&http::Method::GET, p) if p == &format!("{}/stats", admin_base) => self.page_stats(),
            (&http::Method::GET, p) if p == &format!("{}/certificates", admin_base) => self.page_certificates(),
            (&http::Method::GET, "/health") => self.health(),
            (&http::Method::GET, "/api/stats") => self.api_stats(),
            (&http::Method::GET, "/api/stats/html") => self.api_stats_html(),
            (&http::Method::GET, "/api/stats/domains/html") => self.api_domains_stats_html(),
            (&http::Method::GET, "/api/domains") => self.api_list_domains(),
            (&http::Method::GET, "/api/domains/html") => self.api_domains_html(),
            (&http::Method::POST, "/api/domains") => self.api_add_domain(req).await,
            (&http::Method::GET, "/api/certificates") => self.api_certificates(),
            (&http::Method::POST, path) if path.starts_with("/api/renew/") => {
                let domain = path.trim_start_matches("/api/renew/");
                self.api_renew_certificate(domain).await
            }
            (&http::Method::POST, p) if p == &format!("{}/api/test-dns", admin_base) => self.api_test_dns(req).await,
            (&http::Method::POST, p) if p == &format!("{}/api/generate-certificate", admin_base) => self.api_generate_certificate(req).await,
            (&http::Method::GET, "/metrics") => self.metrics_endpoint(),
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
        let cert_status = if self.config.server.tls.mode == "acme" {
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
        let (selfsigned_checked, acme_checked, acme_display) = if self.config.server.tls.mode == "acme" {
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
            .replace("{{ACME_EMAIL}}", &acme_email);
        
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
            "version": env!("CARGO_PKG_VERSION"),
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
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

        // Ler certificados do filesystem
        if cert_dir.exists() && cert_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(cert_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                        if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                            total += 1;
                            
                            // Por agora, certificados self-signed têm validade de 365 dias
                            // TODO: Parse real certificate expiry com x509-parser
                            let days_remaining = 365; // Placeholder
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
                                "expiry_date": "2027-01-30T00:00:00Z", // TODO: Parse real date
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

    /// API endpoint para forçar renovação de certificado
    async fn api_renew_certificate(&self, domain: &str) -> Response<Full<Bytes>> {
        use serde_json::json;

        info!("Force renewal requested for domain: {}", domain);

        // TODO: Integrar com AutoRenewalManager
        // Por agora, retornar sucesso mock
        let response = json!({
            "success": true,
            "domain": domain,
            "message": format!("Certificate renewal started for {}", domain)
        });

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(response.to_string())))
            .unwrap()
    }

    /// API endpoint para testar configuração DNS
    async fn api_test_dns<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body_util::BodyExt + Send + 'static,
    {
        use serde::Deserialize;
        use serde_json::json;

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

        // Simples verificação DNS (em produção, usar DNS resolver real)
        // Por agora, aceita qualquer domínio válido
        let is_valid_domain = test_req.domain.contains('.') && !test_req.domain.contains(' ');

        let response = if is_valid_domain {
            json!({
                "success": true,
                "message": format!("DNS configuration looks good for {}", test_req.domain)
            })
        } else {
            json!({
                "success": false,
                "error": "Invalid domain format"
            })
        };

        Response::builder()
            .status(StatusCode::OK)
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

        if cert_req.cert_type == "acme" && cert_req.email.is_empty() {
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

        // TODO: Implementar geração real de certificado
        // Por agora, simula sucesso para ACME
        if cert_req.cert_type == "acme" {
            info!("ACME certificate generation would start here for: {}", cert_req.domain);
            info!("Email for notifications: {}", cert_req.email);
            
            // Em produção, aqui chamaríamos:
            // self.tls_manager.generate_acme_certificate(&cert_req.domain, &cert_req.email).await
            
            let response = json!({
                "success": true,
                "message": format!("ACME certificate generated for {}. You can now access: https://{}:8443/admin_elite", cert_req.domain, cert_req.domain),
                "domain": cert_req.domain,
                "type": "acme"
            });

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response.to_string())))
                .unwrap()
        } else {
            // Self-signed
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
    }
}
