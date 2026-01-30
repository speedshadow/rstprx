use crate::error::{Error, Result};
use crate::tls::generate_self_signed_cert;
use dashmap::DashMap;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug};

/// TLS Manager com hot-reload e SNI (Server Name Indication) para múltiplos domínios
#[derive(Clone)]
pub struct TlsManager {
    /// Cache de configurações TLS por domínio (SNI)
    configs: Arc<DashMap<String, Arc<ServerConfig>>>,
    /// Configuração TLS padrão (fallback)
    default_config: Arc<RwLock<Arc<ServerConfig>>>,
    /// Diretório base para certificados
    certs_dir: PathBuf,
}

impl TlsManager {
    pub fn new(certs_dir: PathBuf, default_config: Arc<ServerConfig>) -> Self {
        fs::create_dir_all(&certs_dir).ok();
        
        Self {
            configs: Arc::new(DashMap::new()),
            default_config: Arc::new(RwLock::new(default_config)),
            certs_dir,
        }
    }

    /// Gera certificado automaticamente para um domínio e carrega no cache
    pub async fn generate_and_load_cert(&self, domain: &str) -> Result<()> {
        info!("Generating TLS certificate for domain: {}", domain);

        let cert_path = self.certs_dir.join(format!("{}.pem", domain));
        let key_path = self.certs_dir.join(format!("{}.key", domain));

        // Gerar certificado self-signed
        generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
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
        debug!("Loading TLS cert for {}: {:?}", domain, cert_path);

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Tls(format!("Failed to create TLS config for {}: {}", domain, e)))?;

        self.configs.insert(domain.to_string(), Arc::new(config));

        debug!("✅ Loaded TLS config for domain: {}", domain);
        Ok(())
    }

    /// Remove certificado do cache (quando domínio é deletado)
    pub fn remove_cert(&self, domain: &str) {
        if let Some(_) = self.configs.remove(domain) {
            info!("Removed TLS config for domain: {}", domain);
        }

        // Deletar arquivos de certificado
        let cert_path = self.certs_dir.join(format!("{}.pem", domain));
        let key_path = self.certs_dir.join(format!("{}.key", domain));
        
        fs::remove_file(cert_path).ok();
        fs::remove_file(key_path).ok();
    }

    /// Obtém configuração TLS para um domínio específico (SNI)
    pub fn get_config(&self, server_name: &ServerName) -> Arc<ServerConfig> {
        let domain = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            ServerName::IpAddress(_ip) => {
                // Para IPs, usar config padrão já que normalmente não geramos certs por IP
                debug!("IP address detected, using default TLS config");
                return self.get_default_config_sync();
            },
            _ => return self.get_default_config_sync(),
        };

        debug!("SNI lookup for domain: {}", domain);

        // Procurar config específica do domínio
        if let Some(config) = self.configs.get(&domain) {
            debug!("✅ Found SNI config for: {}", domain);
            return config.value().clone();
        }

        // Fallback para config padrão
        debug!("Using default TLS config for: {}", domain);
        self.get_default_config_sync()
    }

    /// Obtém config padrão de forma síncrona
    fn get_default_config_sync(&self) -> Arc<ServerConfig> {
        // Usamos try_read para não bloquear
        self.default_config.try_read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| {
                // Se não conseguir lock, criar config básica
                Arc::new(ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![], PrivateKeyDer::Pkcs8(vec![].into()))
                    .unwrap())
            })
    }

    /// Atualiza a configuração TLS padrão
    pub async fn update_default_config(&self, config: Arc<ServerConfig>) {
        let mut default = self.default_config.write().await;
        *default = config;
        info!("Default TLS config updated");
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
        self.configs.iter().map(|e| e.key().clone()).collect()
    }

    /// Verifica se um domínio tem certificado
    pub fn has_cert(&self, domain: &str) -> bool {
        self.configs.contains_key(domain)
    }

    /// Load/reload certificate para um domínio (usado pelo auto-renewal)
    pub async fn load_certificate(&self, domain: &str, cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<()> {
        info!("Loading/reloading certificate for domain: {}", domain);
        
        // Load TLS config
        let tls_config = crate::tls::load_tls_config(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )?;

        // Insert/update in cache
        self.configs.insert(domain.to_string(), tls_config);
        
        info!("✅ Certificate loaded for domain: {}", domain);
        Ok(())
    }
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let cert_file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(cert_file);

    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| Error::Tls(format!("Failed to load certificates: {}", e)))
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let key_file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(key_file);

    let keys: std::result::Result<Vec<_>, _> =
        rustls_pemfile::pkcs8_private_keys(&mut reader).collect();
    let mut keys = keys.map_err(|e| Error::Tls(format!("Failed to load private key: {}", e)))?;

    if keys.is_empty() {
        return Err(Error::Tls("No private key found".to_string()));
    }

    Ok(PrivateKeyDer::Pkcs8(keys.remove(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_tls_manager_auto_gen() {
        let temp_dir = TempDir::new().unwrap();
        let certs_dir = temp_dir.path().to_path_buf();

        // Config padrão mínima
        let default_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![], PrivateKeyDer::Pkcs8(vec![].into()))
                .unwrap(),
        );

        let manager = TlsManager::new(certs_dir.clone(), default_config);

        // Gerar cert para domínio
        let result = manager.generate_and_load_cert("test.example.com").await;
        assert!(result.is_ok());

        // Verificar se cert existe
        assert!(manager.has_cert("test.example.com"));

        // Verificar arquivos foram criados
        assert!(certs_dir.join("test.example.com.pem").exists());
        assert!(certs_dir.join("test.example.com.key").exists());
    }
}
