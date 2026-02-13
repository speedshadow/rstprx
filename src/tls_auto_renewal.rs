use crate::acme::{AcmeClient, CertificateMonitor, CertificateInfo};
use crate::error::{Error, Result};
use crate::tls_manager::TlsManager;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Auto-Renewal Manager - Combina Certificate Monitor + ACME Client + TlsManager
/// Para renovação automática de certificados
pub struct AutoRenewalManager {
    certificate_monitor: Arc<CertificateMonitor>,
    acme_client: Arc<AcmeClient>,
    tls_manager: Arc<TlsManager>,
    renewal_enabled: bool,
}

impl AutoRenewalManager {
    pub fn new(
        cert_dir: PathBuf,
        renewal_threshold_days: i64,
        acme_directory_url: String,
        acme_email: String,
        acme_account_key_path: String,
        tls_manager: Arc<TlsManager>,
    ) -> Self {
        let certificate_monitor = Arc::new(CertificateMonitor::new(
            cert_dir.clone(),
            renewal_threshold_days,
        ));

        let acme_client = Arc::new(AcmeClient::new(
            acme_directory_url,
            acme_email,
            acme_account_key_path,
        ));

        Self {
            certificate_monitor,
            acme_client,
            tls_manager,
            renewal_enabled: true,
        }
    }

    /// Inicia serviço de auto-renovação em background
    /// 
    /// Este serviço:
    /// 1. Monitora certificados a cada 6 horas
    /// 2. Detecta certificados expirando (30 dias antes)
    /// 3. Renova automaticamente via ACME/Let's Encrypt
    /// 4. Hot-reload do certificado renovado no TlsManager
    pub async fn start_auto_renewal_service(self: Arc<Self>) {
        info!("🔄 Starting Auto-Renewal Service");
        info!("   └─ Check interval: 6 hours");
        info!("   └─ Renewal threshold: 30 days before expiry");
        info!("   └─ ACME provider: Let's Encrypt");

        // Start certificate monitoring task
        let monitor_clone = self.certificate_monitor.clone();
        tokio::spawn(async move {
            monitor_clone.start_monitoring().await;
        });

        // Start renewal task
        let mut renewal_interval = interval(Duration::from_secs(6 * 60 * 60)); // 6 horas

        loop {
            renewal_interval.tick().await;

            if !self.renewal_enabled {
                continue;
            }

            if let Err(e) = self.check_and_renew_certificates().await {
                error!("Auto-renewal check failed: {}", e);
            }
        }
    }

    /// Verifica e renova certificados que precisam
    async fn check_and_renew_certificates(&self) -> Result<()> {
        info!("🔍 Checking certificates for renewal...");

        // Obter certificados expirando
        let expiring_certs = self.certificate_monitor.get_expiring_certificates().await;

        if expiring_certs.is_empty() {
            info!("✅ All certificates are valid");
            return Ok(());
        }

        warn!("⚠️  Found {} certificate(s) requiring renewal", expiring_certs.len());

        // Renovar cada certificado
        for cert_info in expiring_certs {
            info!("🔄 Renewing certificate for: {}", cert_info.domain);

            match self.renew_certificate(&cert_info.domain).await {
                Ok(_) => {
                    info!("✅ Successfully renewed certificate for: {}", cert_info.domain);
                }
                Err(e) => {
                    error!("❌ Failed to renew certificate for {}: {}", cert_info.domain, e);
                }
            }
        }

        Ok(())
    }

    /// Renova um certificado específico
    async fn renew_certificate(&self, domain: &str) -> Result<()> {
        info!("Requesting new certificate for {} via ACME", domain);

        // Step 1: Request certificate via ACME
        let webroot_path = format!("./webroot/{}", domain);
        let (cert_pem, key_pem) = self.acme_client
            .request_certificate(vec![domain.to_string()], &webroot_path)
            .await?;

        // Step 2: Save new certificate
        let cert_dir = self.certificate_monitor.cert_dir.clone();
        let cert_path = cert_dir.join(format!("{}.pem", domain));
        let key_path = cert_dir.join(format!("{}.key", domain));

        tokio::fs::write(&cert_path, cert_pem)
            .await
            .map_err(|e| Error::Internal(format!("Failed to write cert: {}", e)))?;

        tokio::fs::write(&key_path, key_pem)
            .await
            .map_err(|e| Error::Internal(format!("Failed to write key: {}", e)))?;

        info!("💾 Saved renewed certificate to: {}", cert_path.display());

        // Step 3: Hot-reload certificate in TlsManager
        self.tls_manager.load_certificate(domain, &cert_path, &key_path).await?;

        info!("🔥 Hot-reloaded certificate for: {}", domain);

        Ok(())
    }

    /// Força renovação de um domínio específico (manual)
    pub async fn force_renew_domain(&self, domain: &str) -> Result<()> {
        info!("🔧 Force renewal triggered for: {}", domain);
        self.renew_certificate(domain).await
    }

    /// Desabilita auto-renewal (para maintenance)
    pub fn disable_auto_renewal(&mut self) {
        warn!("⚠️  Auto-renewal disabled");
        self.renewal_enabled = false;
    }

    /// Habilita auto-renewal
    pub fn enable_auto_renewal(&mut self) {
        info!("✅ Auto-renewal enabled");
        self.renewal_enabled = true;
    }

    /// Retorna status de todos os certificados
    pub async fn get_certificate_status(&self) -> Vec<CertificateInfo> {
        self.certificate_monitor.get_all_certificates().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_auto_renewal_creation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("default.pem");
        let key_path = temp_dir.path().join("default.key");

        crate::tls::generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            vec!["localhost".to_string()],
        )
        .unwrap();

        let tls_manager = Arc::new(TlsManager::new(temp_dir.path().to_path_buf()));
        tls_manager
            .load_default_certificate(&cert_path, &key_path)
            .unwrap();

        let manager = AutoRenewalManager::new(
            temp_dir.path().to_path_buf(),
            30,
            AcmeClient::letsencrypt_staging().to_string(),
            "test@example.com".to_string(),
            "/tmp/acme_test.key".to_string(),
            tls_manager,
        );

        assert!(manager.renewal_enabled);
    }
}
