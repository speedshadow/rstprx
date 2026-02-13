use crate::error::{Error, Result};
use crate::tls::generate_self_signed_cert;
use dashmap::DashMap;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info};

#[derive(Debug, Default)]
struct DynamicCertResolver {
    certs: DashMap<String, Arc<CertifiedKey>>,
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
}

impl DynamicCertResolver {
    fn set_default(&self, cert: Arc<CertifiedKey>) {
        if let Ok(mut guard) = self.default_cert.write() {
            *guard = Some(cert);
        }
    }

    fn insert(&self, domain: &str, cert: Arc<CertifiedKey>) {
        self.certs.insert(domain.to_ascii_lowercase(), cert);
    }

    fn remove(&self, domain: &str) {
        self.certs.remove(&domain.to_ascii_lowercase());
    }

    fn has_cert(&self, domain: &str) -> bool {
        self.certs.contains_key(&domain.to_ascii_lowercase())
    }

    fn domains(&self) -> Vec<String> {
        self.certs.iter().map(|entry| entry.key().clone()).collect()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            let host = server_name.to_ascii_lowercase();

            if let Some(cert) = self.certs.get(&host) {
                return Some(cert.value().clone());
            }

            for entry in self.certs.iter() {
                let pattern = entry.key();
                if pattern.starts_with("*.") && host.ends_with(&pattern[1..]) {
                    return Some(entry.value().clone());
                }
            }
        }

        self.default_cert
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().cloned())
    }
}

/// TLS Manager com hot-reload e SNI (Server Name Indication) para múltiplos domínios
#[derive(Clone)]
pub struct TlsManager {
    resolver: Arc<DynamicCertResolver>,
    /// Diretório base para certificados
    certs_dir: PathBuf,
}

impl TlsManager {
    pub fn new(certs_dir: PathBuf) -> Self {
        fs::create_dir_all(&certs_dir).ok();

        Self {
            resolver: Arc::new(DynamicCertResolver::default()),
            certs_dir,
        }
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());
        Ok(Arc::new(config))
    }

    pub fn load_default_certificate(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        let cert = build_certified_key(cert_path, key_path)?;
        self.resolver.set_default(cert);
        info!("Loaded default TLS certificate: {}", cert_path.display());
        Ok(())
    }

    /// Gera certificado automaticamente para um domínio e carrega no cache
    pub async fn generate_and_load_cert(&self, domain: &str) -> Result<()> {
        validate_domain(domain)?;
        info!("Generating TLS certificate for domain: {}", domain);

        let cert_path = self.certs_dir.join(format!("{}.pem", domain));
        let key_path = self.certs_dir.join(format!("{}.key", domain));

        // Gerar certificado self-signed
        let cert_path_str = cert_path
            .to_str()
            .ok_or_else(|| Error::Tls("Invalid cert path encoding".to_string()))?;
        let key_path_str = key_path
            .to_str()
            .ok_or_else(|| Error::Tls("Invalid key path encoding".to_string()))?;
        generate_self_signed_cert(
            cert_path_str,
            key_path_str,
            vec![domain.to_string()],
        )?;

        // Carregar certificado
        self.load_cert_for_domain(domain, &cert_path, &key_path).await?;

        info!("✅ TLS certificate generated and loaded for: {}", domain);
        Ok(())
    }

    /// Carrega um certificado existente para um domínio específico
    pub async fn load_cert_for_domain(
        &self,
        domain: &str,
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<()> {
        validate_domain(domain)?;
        debug!("Loading TLS cert for {}: {:?}", domain, cert_path);

        let certified_key = build_certified_key(cert_path, key_path)?;
        self.resolver.insert(domain, certified_key);

        debug!("✅ Loaded TLS config for domain: {}", domain);
        Ok(())
    }

    /// Remove certificado do cache (quando domínio é deletado)
    pub fn remove_cert(&self, domain: &str) {
        if validate_domain(domain).is_err() {
            return;
        }
        if self.resolver.has_cert(domain) {
            self.resolver.remove(domain);
            info!("Removed TLS config for domain: {}", domain);
        }

        // Deletar arquivos de certificado
        let cert_path = self.certs_dir.join(format!("{}.pem", domain));
        let key_path = self.certs_dir.join(format!("{}.key", domain));

        fs::remove_file(cert_path).ok();
        fs::remove_file(key_path).ok();
    }

    /// Carrega todos os certificados existentes no diretório
    pub async fn load_all_existing_certs(&self) -> Result<()> {
        info!("Loading existing certificates from: {:?}", self.certs_dir);

        let entries = fs::read_dir(&self.certs_dir)?;
        let mut loaded = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "pem" {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let key_path = self.certs_dir.join(format!("{}.key", stem));
                        if key_path.exists() {
                            match self.load_cert_for_domain(stem, &path, &key_path).await {
                                Ok(_) => {
                                    loaded += 1;
                                    info!("✅ Pre-loaded cert for: {}", stem);
                                }
                                Err(e) => error!("Failed to load cert for {}: {}", stem, e),
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} existing certificates", loaded);
        Ok(())
    }

    /// Lista todos os domínios com certificados
    pub fn list_domains_with_certs(&self) -> Vec<String> {
        self.resolver.domains()
    }

    /// Verifica se um domínio tem certificado
    pub fn has_cert(&self, domain: &str) -> bool {
        self.resolver.has_cert(domain)
    }

    /// Load/reload certificate para um domínio (usado pelo auto-renewal)
    pub async fn load_certificate(&self, domain: &str, cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<()> {
        validate_domain(domain)?;
        info!("Loading/reloading certificate for domain: {}", domain);

        let certified_key = build_certified_key(cert_path, key_path)?;
        self.resolver.insert(domain, certified_key);

        info!("✅ Certificate loaded for domain: {}", domain);
        Ok(())
    }
}

fn build_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let signing_key = any_supported_type(&key)
        .map_err(|e| Error::Tls(format!("Unsupported private key: {}", e)))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let safe_path = validate_cert_file_path(path)?;
    let cert_file = fs::File::open(&safe_path)?;
    let mut reader = std::io::BufReader::new(cert_file);

    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| Error::Tls(format!("Failed to load certificates: {}", e)))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let safe_path = validate_cert_file_path(path)?;
    let key_file = fs::File::open(&safe_path)?;
    let mut reader = std::io::BufReader::new(key_file);

    let keys: std::result::Result<Vec<_>, _> =
        rustls_pemfile::pkcs8_private_keys(&mut reader).collect();
    let mut keys = keys.map_err(|e| Error::Tls(format!("Failed to load private key: {}", e)))?;

    if keys.is_empty() {
        return Err(Error::Tls("No private key found".to_string()));
    }

    Ok(PrivateKeyDer::Pkcs8(keys.remove(0)))
}

fn validate_cert_file_path(path: &Path) -> Result<PathBuf> {
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(Error::Security("Path traversal attempt detected".to_string()));
        }
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| Error::Security(format!("Failed to canonicalize cert path: {}", e)))?;

    let extension = canonical
        .extension()
        .and_then(|ext| ext.to_str())
        .ok_or_else(|| Error::Security("Certificate path must have valid extension".to_string()))?;

    match extension {
        "pem" | "key" | "crt" | "cert" | "ca" => Ok(canonical),
        _ => Err(Error::Security(format!("Invalid certificate path extension: {}", extension))),
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(Error::InvalidInput("Invalid domain length".to_string()));
    }
    if domain.contains('/') || domain.contains('\\') || domain.contains('\0') || domain.contains("..") {
        return Err(Error::Security("Invalid domain format".to_string()));
    }
    if domain.chars().any(|c| c.is_whitespace()) {
        return Err(Error::InvalidInput("Domain must not contain whitespace".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_tls_manager_auto_gen() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp_dir = TempDir::new().unwrap();
        let certs_dir = temp_dir.path().to_path_buf();

        let manager = TlsManager::new(certs_dir.clone());

        // Gerar cert para domínio
        let result = manager.generate_and_load_cert("test.example.com").await;
        assert!(result.is_ok());

        // Verificar se cert existe
        assert!(manager.has_cert("test.example.com"));

        // Verificar arquivos foram criados
        assert!(certs_dir.join("test.example.com.pem").exists());
        assert!(certs_dir.join("test.example.com.key").exists());

        // Build server config with resolver
        assert!(manager.build_server_config().is_ok());
    }
}
