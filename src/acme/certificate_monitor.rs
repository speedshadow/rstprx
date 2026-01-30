use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Certificate Monitor - Monitora certificados e dispara auto-renovação
pub struct CertificateMonitor {
    pub cert_dir: PathBuf,
    renewal_threshold_days: i64,
    certificates: Arc<RwLock<Vec<CertificateInfo>>>,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub expiry_date: DateTime<Utc>,
    pub status: CertificateStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStatus {
    Valid,
    Expiring,      // Dentro do threshold de renovação
    Expired,
    Invalid,
}

impl CertificateMonitor {
    /// Cria novo certificate monitor
    /// 
    /// # Arguments
    /// * `cert_dir` - Diretório onde certificados estão armazenados
    /// * `renewal_threshold_days` - Quantos dias antes de expirar para renovar (ex: 30 dias)
    pub fn new(cert_dir: PathBuf, renewal_threshold_days: i64) -> Self {
        Self {
            cert_dir,
            renewal_threshold_days,
            certificates: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Inicia monitoring em background
    /// Verifica certificados a cada 6 horas
    pub async fn start_monitoring(self: Arc<Self>) {
        info!("🔍 Starting certificate monitoring (check interval: 6h, renewal threshold: {} days)", 
              self.renewal_threshold_days);

        let mut check_interval = interval(Duration::from_secs(6 * 60 * 60)); // 6 horas

        loop {
            check_interval.tick().await;
            
            if let Err(e) = self.check_all_certificates().await {
                error!("Certificate check failed: {}", e);
            }
        }
    }

    /// Verifica todos os certificados
    pub async fn check_all_certificates(&self) -> Result<()> {
        debug!("Checking all certificates in {}", self.cert_dir.display());

        let mut certificates = Vec::new();

        // Scan cert directory
        if !self.cert_dir.exists() {
            warn!("Certificate directory does not exist: {}", self.cert_dir.display());
            return Ok(());
        }

        // Read all .pem files
        let mut entries = tokio::fs::read_dir(&self.cert_dir)
            .await
            .map_err(|e| Error::Internal(format!("Failed to read cert dir: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| Error::Internal(format!("Failed to read dir entry: {}", e)))?
        {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                if let Some(file_name) = path.file_stem().and_then(|s| s.to_str()) {
                    // Certificado deve ter formato: domain.com.pem
                    // Chave privada: domain.com.key
                    
                    let domain = file_name.to_string();
                    let cert_path = path.clone();
                    let key_path = self.cert_dir.join(format!("{}.key", domain));

                    if key_path.exists() {
                        match self.check_certificate(&cert_path).await {
                            Ok(cert_info) => {
                                info!("Certificate for {}: {:?} (expires: {})", 
                                      domain, cert_info.status, cert_info.expiry_date);
                                certificates.push(cert_info);
                            }
                            Err(e) => {
                                warn!("Failed to check certificate {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        }

        // Update internal state
        *self.certificates.write().await = certificates;

        Ok(())
    }

    /// Verifica um certificado específico
    async fn check_certificate(&self, cert_path: &Path) -> Result<CertificateInfo> {
        let domain = cert_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Internal("Invalid cert filename".to_string()))?
            .to_string();

        // Ler certificado
        let cert_pem = tokio::fs::read_to_string(cert_path)
            .await
            .map_err(|e| Error::Internal(format!("Failed to read cert: {}", e)))?;

        // Parse expiry date
        let expiry_date = Self::parse_expiry_from_pem(&cert_pem)?;

        // Determinar status
        let now = Utc::now();
        let days_until_expiry = (expiry_date - now).num_days();

        let status = if days_until_expiry < 0 {
            CertificateStatus::Expired
        } else if days_until_expiry <= self.renewal_threshold_days {
            CertificateStatus::Expiring
        } else {
            CertificateStatus::Valid
        };

        Ok(CertificateInfo {
            domain: domain.clone(),
            cert_path: cert_path.to_path_buf(),
            key_path: self.cert_dir.join(format!("{}.key", domain)),
            expiry_date,
            status,
        })
    }

    /// Parse expiry date do certificado PEM
    /// Implementação simplificada - na produção usar openssl/x509-parser
    fn parse_expiry_from_pem(cert_pem: &str) -> Result<DateTime<Utc>> {
        // TODO: Usar biblioteca de parsing de certificados X.509
        // Por agora, retornar data fictícia (90 dias no futuro)
        
        if cert_pem.contains("PLACEHOLDER") {
            // Certificado placeholder/self-signed
            Ok(Utc::now() + chrono::Duration::days(90))
        } else {
            // Parse real certificate
            // Implementar com x509-parser ou openssl
            Ok(Utc::now() + chrono::Duration::days(90))
        }
    }

    /// Retorna certificados que precisam renovação
    pub async fn get_expiring_certificates(&self) -> Vec<CertificateInfo> {
        self.certificates
            .read()
            .await
            .iter()
            .filter(|cert| {
                matches!(cert.status, CertificateStatus::Expiring | CertificateStatus::Expired)
            })
            .cloned()
            .collect()
    }

    /// Retorna todos os certificados
    pub async fn get_all_certificates(&self) -> Vec<CertificateInfo> {
        self.certificates.read().await.clone()
    }

    /// Força check imediato de um domínio específico
    pub async fn check_domain(&self, domain: &str) -> Result<CertificateInfo> {
        let cert_path = self.cert_dir.join(format!("{}.pem", domain));
        self.check_certificate(&cert_path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_certificate_monitor_creation() {
        let temp_dir = TempDir::new().unwrap();
        let monitor = CertificateMonitor::new(temp_dir.path().to_path_buf(), 30);

        assert_eq!(monitor.renewal_threshold_days, 30);
    }

    #[tokio::test]
    async fn test_check_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let monitor = CertificateMonitor::new(temp_dir.path().to_path_buf(), 30);

        let result = monitor.check_all_certificates().await;
        assert!(result.is_ok());

        let certs = monitor.get_all_certificates().await;
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn test_certificate_status() {
        let status = CertificateStatus::Expiring;
        assert_eq!(status, CertificateStatus::Expiring);
    }
}
