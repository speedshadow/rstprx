use crate::auth::AuthManager;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::stealth::PathSanitizer;
use crate::frontend::FrontendHandler;
use crate::metrics::MetricsCollector;
use crate::proxy::ProxyHandler;
use crate::storage::Storage;
use crate::tls::{generate_self_signed_cert, load_tls_config};
use crate::tls_manager::TlsManager;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
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

        // Inicializar TLS Manager
        let default_tls_config = if config.server.tls.enabled {
            Self::setup_tls_config(&config).await?
        } else {
            Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![],
                        rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()),
                    )
                    .unwrap(),
            )
        };

        // SECURITY FIX: Sanitize cert_dir path
        let cert_dir = PathSanitizer::sanitize(&config.server.tls.cert_dir)?;
        
        let tls_manager = Arc::new(TlsManager::new(
            cert_dir,
            default_tls_config,
        ));

        // Carregar certificados existentes
        tls_manager.load_all_existing_certs().await.ok();

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
        let tls_config = self.setup_tls().await?;
        let acceptor = TlsAcceptor::from(tls_config);

        info!("TLS server ready, accepting connections");

        let server = Arc::new(self);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let acceptor = acceptor.clone();
                            let server = server.clone();

                            tokio::spawn(async move {
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

        let server = Arc::new(self);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let server = server.clone();
                            let io = TokioIo::new(stream);

                            tokio::spawn(async move {
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
    ) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let path = req.uri().path();
        
        // Normalizar path: remover trailing slash exceto root
        let normalized_path = if path.len() > 1 && path.ends_with('/') {
            &path[..path.len() - 1]
        } else {
            path
        };

        let admin_path = &self.config.server.admin_path;

        if normalized_path.starts_with(admin_path)
            || normalized_path.starts_with("/api")
            || normalized_path == "/health"
            || normalized_path == "/metrics"
            || normalized_path == "/logout"
            || normalized_path == "/"  // Root path goes to frontend (fake website or dashboard)
        {
            Ok(self.frontend_handler.handle(req).await)
        } else {
            match self.proxy_handler.handle_request(req, peer_addr).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!("Proxy error: {}", e);
                    Ok(Response::builder()
                        .status(http::StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from("Bad Gateway")))
                        .unwrap())
                }
            }
        }
    }

    async fn setup_tls_config(config: &Config) -> Result<Arc<rustls::ServerConfig>> {
        // SECURITY FIX: Sanitize cert paths
        let cert_path_sanitized = PathSanitizer::sanitize_cert_path(&config.server.tls.cert_file)?;
        let key_path_sanitized = PathSanitizer::sanitize_cert_path(&config.server.tls.key_file)?;
        
        let cert_path = &config.server.tls.cert_file;
        let key_path = &config.server.tls.key_file;

        if !cert_path_sanitized.exists() || !key_path_sanitized.exists() {
            if config.server.tls.mode == "selfsigned" {
                info!("Generating self-signed certificate");
                generate_self_signed_cert(
                    cert_path,
                    key_path,
                    config.server.tls.selfsigned_hosts.clone(),
                )?;
                info!("Self-signed certificate generated successfully");
            } else {
                return Err(Error::Tls(format!(
                    "Certificate files not found and mode is not selfsigned: {} / {}",
                    cert_path, key_path
                )));
            }
        }

        load_tls_config(cert_path, key_path)
    }

    async fn setup_tls(&self) -> Result<Arc<rustls::ServerConfig>> {
        let cert_path = &self.config.server.tls.cert_file;
        let key_path = &self.config.server.tls.key_file;

        match self.config.server.tls.mode.as_str() {
            "selfsigned" => {
                if !Path::new(cert_path).exists() {
                    info!("Generating self-signed certificate");
                    let hosts = if self.config.server.tls.selfsigned_hosts.is_empty() {
                        vec!["localhost".to_string(), "127.0.0.1".to_string()]
                    } else {
                        self.config.server.tls.selfsigned_hosts.clone()
                    };

                    generate_self_signed_cert(cert_path, key_path, hosts)?;
                    info!("Self-signed certificate generated successfully");
                }

                load_tls_config(cert_path, key_path)
            }
            "autocert" => {
                warn!("Autocert not yet implemented, falling back to self-signed");
                Box::pin(self.setup_tls()).await
            }
            _ => load_tls_config(cert_path, key_path),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        info!("Server shutting down, flushing storage...");
        let _ = self.storage.flush();
    }
}
