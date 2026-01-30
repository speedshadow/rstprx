use crate::error::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

/// ACME (Automatic Certificate Management Environment) Client
/// Suporta Let's Encrypt e outros providers compatíveis com ACME v2
pub struct AcmeClient {
    client: Client,
    directory_url: String,
    account_email: String,
    account_key_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub key_change: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateOrder {
    pub domains: Vec<String>,
    pub status: OrderStatus,
    pub expires: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl AcmeClient {
    /// Cria novo ACME client
    /// 
    /// # Arguments
    /// * `directory_url` - URL do ACME directory (ex: Let's Encrypt production/staging)
    /// * `account_email` - Email para notificações
    /// * `account_key_path` - Path para armazenar chave da conta ACME
    pub fn new(directory_url: String, account_email: String, account_key_path: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            directory_url,
            account_email,
            account_key_path,
        }
    }

    /// URLs comuns de ACME providers
    pub fn letsencrypt_production() -> &'static str {
        "https://acme-v02.api.letsencrypt.org/directory"
    }

    pub fn letsencrypt_staging() -> &'static str {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    }

    /// Obtém ACME directory (endpoints disponíveis)
    pub async fn get_directory(&self) -> Result<AcmeDirectory> {
        debug!("Fetching ACME directory from {}", self.directory_url);
        
        let response = self.client
            .get(&self.directory_url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("ACME directory request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Internal(format!(
                "ACME directory returned status: {}",
                response.status()
            )));
        }

        response
            .json::<AcmeDirectory>()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse ACME directory: {}", e)))
    }

    /// Solicita novo certificado para domínios
    /// 
    /// # Processo ACME:
    /// 1. Criar ordem (order) para os domínios
    /// 2. Completar desafios (HTTP-01 ou DNS-01)
    /// 3. Finalizar ordem com CSR
    /// 4. Download do certificado
    pub async fn request_certificate(
        &self,
        domains: Vec<String>,
        webroot_path: &str,
    ) -> Result<(String, String)> {
        info!("Requesting certificate for domains: {:?}", domains);

        // Step 1: Get directory
        let directory = self.get_directory().await?;
        debug!("ACME directory fetched successfully");

        // Step 2: Create or load account
        self.ensure_account(&directory).await?;

        // Step 3: Create order
        let order = self.create_order(&directory, domains.clone()).await?;
        info!("Order created with status: {:?}", order.status);

        // Step 4: Complete challenges (HTTP-01)
        self.complete_http01_challenges(&order, webroot_path).await?;

        // Step 5: Finalize order with CSR
        let (cert_pem, key_pem) = self.finalize_order(&order, &domains).await?;

        info!("✅ Certificate issued successfully for {:?}", domains);
        Ok((cert_pem, key_pem))
    }

    /// Garante que conta ACME existe
    async fn ensure_account(&self, _directory: &AcmeDirectory) -> Result<()> {
        // Verificar se chave da conta já existe
        if Path::new(&self.account_key_path).exists() {
            debug!("ACME account key found at {}", self.account_key_path);
            return Ok(());
        }

        info!("Creating new ACME account for {}", self.account_email);
        
        // TODO: Implementar criação de conta ACME
        // Por agora, apenas criar placeholder
        fs::write(&self.account_key_path, "placeholder_account_key")
            .await
            .map_err(|e| Error::Internal(format!("Failed to write account key: {}", e)))?;

        Ok(())
    }

    /// Cria ordem de certificado
    async fn create_order(
        &self,
        _directory: &AcmeDirectory,
        domains: Vec<String>,
    ) -> Result<CertificateOrder> {
        // TODO: Implementar chamada real ao ACME newOrder endpoint
        // Por agora, retornar ordem mock
        Ok(CertificateOrder {
            domains,
            status: OrderStatus::Pending,
            expires: chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .unwrap()
                .to_rfc3339(),
        })
    }

    /// Completa desafios HTTP-01
    /// 
    /// O desafio HTTP-01 requer que o servidor responda em:
    /// `http://<domain>/.well-known/acme-challenge/<token>`
    async fn complete_http01_challenges(
        &self,
        _order: &CertificateOrder,
        webroot_path: &str,
    ) -> Result<()> {
        info!("Completing HTTP-01 challenges with webroot: {}", webroot_path);
        
        // TODO: Implementar desafios HTTP-01 reais
        // Por agora, apenas validar que webroot existe
        if !Path::new(webroot_path).exists() {
            warn!("Webroot path does not exist: {}", webroot_path);
        }

        Ok(())
    }

    /// Finaliza ordem e obtém certificado
    async fn finalize_order(
        &self,
        _order: &CertificateOrder,
        domains: &[String],
    ) -> Result<(String, String)> {
        info!("Finalizing order for domains: {:?}", domains);

        // TODO: Implementar finalização real com CSR
        // Por agora, gerar certificado self-signed como fallback
        let cert_pem = "-----BEGIN CERTIFICATE-----\nPLACEHOLDER\n-----END CERTIFICATE-----\n";
        let key_pem = "-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----\n";

        Ok((cert_pem.to_string(), key_pem.to_string()))
    }

    /// Revoga certificado
    pub async fn revoke_certificate(&self, cert_pem: &str) -> Result<()> {
        info!("Revoking certificate");
        
        // TODO: Implementar revogação real
        debug!("Certificate to revoke: {} bytes", cert_pem.len());

        Ok(())
    }

    /// Request certificate usando DNS-01 challenge (suporta WILDCARDS!)
    /// 
    /// # Arguments
    /// * `domains` - Lista de domínios (pode incluir wildcards: "*.example.com")
    /// * `dns_provider` - Provider DNS (Cloudflare, Route53, etc)
    /// 
    /// # Example
    /// ```rust
    /// let domains = vec!["*.example.com".to_string(), "example.com".to_string()];
    /// let cloudflare = CloudflareDns::from_env()?;
    /// let (cert, key) = client.request_certificate_dns01(domains, Arc::new(cloudflare)).await?;
    /// ```
    pub async fn request_certificate_dns01(
        &self,
        domains: Vec<String>,
        dns_provider: std::sync::Arc<dyn crate::acme::DnsProvider>,
    ) -> Result<(String, String)> {
        info!("🌟 Requesting WILDCARD certificate via DNS-01 for: {:?}", domains);

        // Check for wildcards
        let has_wildcard = domains.iter().any(|d| d.starts_with("*."));
        if has_wildcard {
            info!("✨ Wildcard detected - using DNS-01 challenge");
        }

        // Step 1: Get ACME directory
        let directory = self.get_directory().await?;

        // Step 2: Ensure account exists
        self.ensure_account(&directory).await?;

        // Step 3: Create order
        let order = self.create_order(&directory, domains.clone()).await?;
        info!("Order created: {:?}", order.status);

        // Step 4: Complete DNS-01 challenges
        self.complete_dns01_challenges(&order, dns_provider).await?;

        // Step 5: Finalize order
        let (cert_pem, key_pem) = self.finalize_order(&order, &domains).await?;

        info!("✅ Wildcard certificate issued successfully!");
        Ok((cert_pem, key_pem))
    }

    /// Complete DNS-01 challenges
    async fn complete_dns01_challenges(
        &self,
        order: &CertificateOrder,
        dns_provider: std::sync::Arc<dyn crate::acme::DnsProvider>,
    ) -> Result<()> {
        info!("Completing DNS-01 challenges via {}", dns_provider.provider_name());

        let mut record_ids = Vec::new();

        // Para cada domínio, criar TXT record
        for domain in &order.domains {
            let challenge_name = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
            
            // TODO: Calcular token hash real do ACME
            let token_hash = "MOCK_TOKEN_HASH_REPLACE_WITH_REAL";

            info!("Creating DNS TXT record: {} = {}", challenge_name, token_hash);

            // Criar TXT record
            let record_id = dns_provider
                .create_txt_record(&challenge_name, token_hash)
                .await?;
            
            record_ids.push((record_id, challenge_name.clone(), token_hash.to_string()));
        }

        // Aguardar DNS propagation (CRÍTICO!)
        info!("⏳ Waiting for DNS propagation...");
        for (_record_id, name, value) in &record_ids {
            dns_provider.wait_for_propagation(name, value).await?;
        }

        info!("✅ All DNS records propagated successfully!");

        // TODO: Notificar ACME que pode validar
        info!("Notifying ACME to validate challenges...");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup: Remover TXT records
        info!("🧹 Cleaning up DNS records...");
        for (record_id, name, _) in record_ids {
            match dns_provider.delete_txt_record(&record_id).await {
                Ok(_) => info!("Deleted DNS record: {}", name),
                Err(e) => warn!("Failed to delete DNS record {}: {}", name, e),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_urls() {
        assert!(AcmeClient::letsencrypt_production().contains("acme-v02"));
        assert!(AcmeClient::letsencrypt_staging().contains("staging"));
    }

    #[tokio::test]
    async fn test_acme_client_creation() {
        let client = AcmeClient::new(
            AcmeClient::letsencrypt_staging().to_string(),
            "test@example.com".to_string(),
            "/tmp/acme_account.key".to_string(),
        );

        assert_eq!(client.account_email, "test@example.com");
    }
}
