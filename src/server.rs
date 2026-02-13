use crate::auth::AuthManager;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::stealth::PathSanitizer;
use crate::frontend::FrontendHandler;
use crate::metrics::MetricsCollector;
use crate::proxy::{ProxyHandler, handler::ResponseBody};
use crate::storage::Storage;
use crate::tls::{generate_self_signed_cert, load_tls_config};
use crate::tls_manager::TlsManager;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub struct Server {
    config: Arc<Config>,
    storage: Storage,
    #[allow(dead_code)]
    metrics: Arc<MetricsCollector>,
    #[allow(dead_code)]
    auth: Arc<AuthManager>,
    proxy_handler: Arc<ProxyHandler>,
    frontend_handler: Arc<FrontendHandler>,
    #[allow(dead_code)]
    tls_manager: Arc<TlsManager>,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self> {
        let storage = Storage::new(&config.storage.path)?;

        let metrics = Arc::new(
            MetricsCollector::new().map_err(|e| crate::error::Error::Internal(e.to_string()))?,
        );

        let auth = Arc::new(AuthManager::new(
            config.auth.jwt_secret.clone(),
            config.auth.token_expiry,
            config.auth.refresh_expiry,
            config.auth.refresh_enabled,
        ));

        let proxy_handler = Arc::new(ProxyHandler::new(
            config.clone(),
            storage.clone(),
            metrics.clone(),
        )?);

        // SECURITY FIX: Sanitize cert_dir path and create it if missing
        let cert_dir = PathSanitizer::sanitize_or_create_dir(&config.server.tls.cert_dir)?;

        let tls_manager = Arc::new(TlsManager::new(cert_dir));

        if config.server.tls.enabled {
            Self::ensure_tls_material(&config).await?;
            let cert_path = PathSanitizer::sanitize_cert_path(&config.server.tls.cert_file)?;
            let key_path = PathSanitizer::sanitize_cert_path(&config.server.tls.key_file)?;
            tls_manager.load_default_certificate(
                &cert_path,
                &key_path,
            )?;
        }

        // Carregar certificados existentes
        if let Err(e) = tls_manager.load_all_existing_certs().await {
            warn!("Failed to pre-load existing TLS certificates: {}", e);
        }

        let frontend_handler = Arc::new(FrontendHandler::new(
            Arc::new(config.clone()),
            storage.clone(),
            auth.clone(),
            metrics.clone(),
            tls_manager.clone(),
        ));

        Ok(Self {
            config: Arc::new(config),
            storage,
            metrics,
            auth,
            proxy_handler,
            frontend_handler,
            tls_manager,
        })
    }

    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr =
            self.config.server.listen_addr.parse().map_err(|e| {
                crate::error::Error::Config(format!("Invalid listen address: {}", e))
            })?;

        info!("Starting Elite Rama Proxy on {}", addr);
        info!("TLS Mode: {}", self.config.server.tls.mode);

        let listener = TcpListener::bind(addr).await?;

        if self.config.server.tls.enabled {
            self.run_tls(listener).await
        } else {
            self.run_http(listener).await
        }
    }

    async fn run_tls(self, listener: TcpListener) -> Result<()> {
        let tls_config = self.tls_manager.build_server_config()?;
        let acceptor = TlsAcceptor::from(tls_config);
        let max_connections = self.config.proxy.transport.max_idle_conns.max(100);
        let connection_limiter = Arc::new(Semaphore::new(max_connections));

        info!("TLS server ready, accepting connections");

        let server = Arc::new(self);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let permit = match connection_limiter.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!("Connection limit reached ({}), dropping incoming TLS connection", max_connections);
                                    continue;
                                }
                            };
                            let acceptor = acceptor.clone();
                            let server = server.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        let io = TokioIo::new(tls_stream);

                                        let service = service_fn(move |req: Request<Incoming>| {
                                            let server = server.clone();
                                            async move {
                                                server.handle_connection(req, peer_addr).await
                                            }
                                        });

                                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            error!("Error serving connection: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("TLS handshake failed: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received, gracefully shutting down...");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn run_http(self, listener: TcpListener) -> Result<()> {
        info!("HTTP server ready, accepting connections");
        let max_connections = self.config.proxy.transport.max_idle_conns.max(100);
        let connection_limiter = Arc::new(Semaphore::new(max_connections));

        let server = Arc::new(self);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let permit = match connection_limiter.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!("Connection limit reached ({}), dropping incoming HTTP connection", max_connections);
                                    continue;
                                }
                            };
                            let server = server.clone();
                            let io = TokioIo::new(stream);

                            tokio::spawn(async move {
                                let _permit = permit;
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let server = server.clone();
                                    async move {
                                        server.handle_connection(req, peer_addr).await
                                    }
                                });

                                if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Error serving connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received, gracefully shutting down...");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
    ) -> std::result::Result<Response<ResponseBody>, std::convert::Infallible> {
        let path = req.uri().path();

        if path.starts_with("/.well-known/acme-challenge/") {
            return Ok(self.serve_acme_challenge(&req).await);
        }
        
        // Normalizar path: remover trailing slash exceto root
        let normalized_path = if path.len() > 1 && path.ends_with('/') {
            &path[..path.len() - 1]
        } else {
            path
        };

        let admin_path = &self.config.server.admin_path;
        let metrics_path = self.config.monitoring.prometheus.path.as_str();

        if normalized_path.starts_with(admin_path)
            || normalized_path.starts_with("/api")
            || normalized_path == "/health"
            || normalized_path == metrics_path
            || normalized_path == "/logout"
            || normalized_path == "/"  // Root path goes to frontend (fake website or dashboard)
        {
            // Convert Full<Bytes> from frontend to ResponseBody
            let resp = self.frontend_handler.handle(req).await;
            Ok(resp.map(|b| b.map_err(|never| match never {}).boxed()))
        } else {
            match self.proxy_handler.handle_request(req, peer_addr).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!("Proxy error: {}", e);
                    // STEALTH: Return generic nginx-like error, never reveal proxy identity
                    Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .header(http::header::SERVER, "nginx/1.24.0")
                        .header(http::header::CONTENT_TYPE, "text/html")
                        .body(Full::new(Bytes::from(
                            "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n"
                        )).map_err(|never| match never {}).boxed())
                        .unwrap())
                }
            }
        }
    }

    async fn serve_acme_challenge(&self, req: &Request<Incoming>) -> Response<ResponseBody> {
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default();

        let token = req
            .uri()
            .path()
            .trim_start_matches("/.well-known/acme-challenge/");

        let valid_host = !host.is_empty()
            && !host.contains("..")
            && !host.contains('/')
            && !host.contains('\\')
            && !host.chars().any(|c| c.is_whitespace() || c == '\0');

        let valid_token = !token.is_empty()
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

        if !valid_host || !valid_token {
            return Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .header(http::header::SERVER, "nginx/1.24.0")
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from("Not Found")).map_err(|never| match never {}).boxed())
                .unwrap();
        }

        let challenge_path = PathBuf::from("webroot")
            .join(&host)
            .join(".well-known")
            .join("acme-challenge")
            .join(token);

        match tokio::fs::read(challenge_path).await {
            Ok(content) => Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::SERVER, "nginx/1.24.0")
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from(content)).map_err(|never| match never {}).boxed())
                .unwrap(),
            Err(_) => Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .header(http::header::SERVER, "nginx/1.24.0")
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from("Not Found")).map_err(|never| match never {}).boxed())
                .unwrap(),
        }
    }

    async fn ensure_tls_material(config: &Config) -> Result<()> {
        let cert_path = &config.server.tls.cert_file;
        let key_path = &config.server.tls.key_file;

        if cert_path.contains("..") || key_path.contains("..") || cert_path.contains('\0') || key_path.contains('\0') {
            return Err(Error::Security("Invalid certificate path".to_string()));
        }

        let cert_exists = PathSanitizer::sanitize_cert_path(cert_path).is_ok();
        let key_exists = PathSanitizer::sanitize_cert_path(key_path).is_ok();

        if !cert_exists || !key_exists {
            let can_bootstrap_selfsigned = config.server.tls.mode == "selfsigned"
                || (config.server.tls.mode == "autocert" && config.server.tls.autocert.enabled);
            if !can_bootstrap_selfsigned {
                return Err(Error::Tls(format!(
                    "Certificate files not found and mode cannot bootstrap TLS materials: {} / {}",
                    cert_path, key_path
                )));
            }

            info!("Generating self-signed bootstrap certificate");
            let hosts = if config.server.tls.selfsigned_hosts.is_empty() {
                vec!["localhost".to_string(), "127.0.0.1".to_string()]
            } else {
                config.server.tls.selfsigned_hosts.clone()
            };
            generate_self_signed_cert(cert_path, key_path, hosts)?;
            info!("Bootstrap certificate generated successfully");
        }

        // SECURITY FIX: Sanitize cert paths after files exist
        let _ = PathSanitizer::sanitize_cert_path(cert_path)?;
        let _ = PathSanitizer::sanitize_cert_path(key_path)?;

        // Validate certificate and key are loadable
        let _ = load_tls_config(cert_path, key_path)?;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        info!("Server shutting down, flushing storage...");
        let _ = self.storage.flush();
    }
}
