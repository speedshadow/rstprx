use crate::error::{Error, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// DNS Provider trait - Abstração para diferentes providers (Cloudflare, Route53, etc)
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Cria TXT record para ACME challenge
    async fn create_txt_record(&self, name: &str, value: &str) -> Result<String>;
    
    /// Remove TXT record após validação
    async fn delete_txt_record(&self, record_id: &str) -> Result<()>;
    
    /// Aguarda DNS propagation (crítico para DNS-01!)
    async fn wait_for_propagation(&self, name: &str, expected_value: &str) -> Result<()>;
    
    /// Nome do provider (para logs)
    fn provider_name(&self) -> &str;
}

/// Cloudflare DNS Provider (Recomendado!)
pub struct CloudflareDns {
    api_token: String,
    zone_id: String,
    client: Client,
}

#[derive(Debug, Serialize)]
struct CloudflareCreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CloudflareRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
}

impl CloudflareDns {
    /// Cria novo Cloudflare DNS provider
    /// 
    /// # Arguments
    /// * `api_token` - Cloudflare API Token (requer Zone:DNS:Edit)
    /// * `zone_id` - Zone ID do domínio (ex: "abc123...")
    pub fn new(api_token: String, zone_id: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            api_token,
            zone_id,
            client,
        })
    }

    /// Obtém API token de variável de ambiente
    pub fn from_env() -> Result<Self> {
        let api_token = std::env::var("CLOUDFLARE_API_TOKEN")
            .map_err(|_| Error::Config("CLOUDFLARE_API_TOKEN not set".to_string()))?;
        
        let zone_id = std::env::var("CLOUDFLARE_ZONE_ID")
            .map_err(|_| Error::Config("CLOUDFLARE_ZONE_ID not set".to_string()))?;

        Self::new(api_token, zone_id)
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn create_txt_record(&self, name: &str, value: &str) -> Result<String> {
        info!("Creating Cloudflare TXT record: {} = {}", name, value);

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let request_body = CloudflareCreateRecordRequest {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            content: value.to_string(),
            ttl: 120, // 2 minutos (rápido para ACME)
        };

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Cloudflare API request failed: {}", e)))?;

        let _status = response.status();
        let body: CloudflareResponse<CloudflareRecord> = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse Cloudflare response: {}", e)))?;

        if !body.success {
            let errors: Vec<String> = body.errors
                .iter()
                .map(|e| format!("{} ({})", e.message, e.code))
                .collect();
            return Err(Error::Internal(format!(
                "Cloudflare API error: {}",
                errors.join(", ")
            )));
        }

        let record = body.result
            .ok_or_else(|| Error::Internal("Cloudflare returned no record".to_string()))?;

        info!("✅ Cloudflare TXT record created: {}", record.id);
        Ok(record.id)
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<()> {
        info!("Deleting Cloudflare TXT record: {}", record_id);

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, record_id
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Cloudflare delete failed: {}", e)))?;

        if !response.status().is_success() {
            warn!("Failed to delete Cloudflare record {}: {}", record_id, response.status());
        } else {
            info!("✅ Cloudflare TXT record deleted");
        }

        Ok(())
    }

    async fn wait_for_propagation(&self, name: &str, expected_value: &str) -> Result<()> {
        info!("Waiting for DNS propagation: {} = {}", name, expected_value);

        let max_attempts = 60; // 5 minutos (5s interval)
        let check_interval = Duration::from_secs(5);

        for attempt in 1..=max_attempts {
            debug!("DNS propagation check attempt {}/{}", attempt, max_attempts);

            // Query DNS via trust-dns-resolver
            match self.query_txt_record(name).await {
                Ok(values) => {
                    if values.contains(&expected_value.to_string()) {
                        info!("✅ DNS propagated successfully after {} attempts ({} seconds)", 
                              attempt, attempt * 5);
                        return Ok(());
                    }
                    debug!("DNS not yet propagated. Got: {:?}", values);
                }
                Err(e) => {
                    debug!("DNS query failed: {} (attempt {})", e, attempt);
                }
            }

            tokio::time::sleep(check_interval).await;
        }

        Err(Error::Internal(format!(
            "DNS propagation timeout after {} seconds. Record may not be visible yet.",
            max_attempts * 5
        )))
    }

    fn provider_name(&self) -> &str {
        "Cloudflare"
    }
}

impl CloudflareDns {
    /// Query TXT record via DNS (para verificar propagation)
    async fn query_txt_record(&self, name: &str) -> Result<Vec<String>> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let response = resolver
            .txt_lookup(name)
            .await
            .map_err(|e| Error::Internal(format!("DNS TXT lookup failed: {}", e)))?;

        let values: Vec<String> = response
            .iter()
            .flat_map(|txt| {
                txt.iter().map(|data| {
                    String::from_utf8_lossy(data).to_string()
                })
            })
            .collect();

        Ok(values)
    }
}

/// AWS Route53 DNS Provider (TODO: Implementar)
pub struct Route53Dns {
    // aws_config: aws_config::SdkConfig,
    // hosted_zone_id: String,
}

#[async_trait]
impl DnsProvider for Route53Dns {
    async fn create_txt_record(&self, _name: &str, _value: &str) -> Result<String> {
        Err(Error::Internal("Route53 not yet implemented".to_string()))
    }

    async fn delete_txt_record(&self, _record_id: &str) -> Result<()> {
        Err(Error::Internal("Route53 not yet implemented".to_string()))
    }

    async fn wait_for_propagation(&self, _name: &str, _expected_value: &str) -> Result<()> {
        Err(Error::Internal("Route53 not yet implemented".to_string()))
    }

    fn provider_name(&self) -> &str {
        "AWS Route53"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_creation() {
        let cf = CloudflareDns::new("test_token".to_string(), "test_zone".to_string())
            .unwrap();
        assert_eq!(cf.provider_name(), "Cloudflare");
    }

    #[tokio::test]
    async fn test_dns_provider_trait() {
        // Mock provider para testes
        struct MockDns;

        #[async_trait]
        impl DnsProvider for MockDns {
            async fn create_txt_record(&self, _name: &str, _value: &str) -> Result<String> {
                Ok("mock_record_id".to_string())
            }

            async fn delete_txt_record(&self, _record_id: &str) -> Result<()> {
                Ok(())
            }

            async fn wait_for_propagation(&self, _name: &str, _expected_value: &str) -> Result<()> {
                Ok(())
            }

            fn provider_name(&self) -> &str {
                "Mock"
            }
        }

        let mock = MockDns;
        let record_id = mock.create_txt_record("test", "value").await.unwrap();
        assert_eq!(record_id, "mock_record_id");
    }
}
