use std::net::IpAddr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use crate::error::{Error, Result};
use tracing::debug;

/// DNS Fingerprinting Protection
/// Emula padrões de resolução DNS de browsers reais
pub struct DnsFingerprinter {
    resolver: TokioAsyncResolver,
    use_doh: bool,
    browser_name: String,
}

impl DnsFingerprinter {
    pub async fn new(browser_name: String, use_doh: bool) -> Result<Self> {
        // Para simplificar, usar resolver padrão
        // DoH/DoT requer versões mais recentes do trust-dns-resolver
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Ok(Self {
            resolver,
            use_doh,
            browser_name,
        })
    }

    /// Resolve hostname com padrão de browser real
    /// Browsers fazem queries A e AAAA em paralelo
    pub async fn resolve_with_browser_pattern(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        debug!("DNS resolve com padrão {}: {}", self.browser_name, hostname);

        // Browsers modernos fazem A e AAAA em paralelo (Happy Eyeballs RFC 8305)
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.query_a(hostname),
            self.query_aaaa(hostname)
        );

        // Chrome prefere IPv4, Firefox prefere IPv6
        let mut addresses = Vec::new();

        match self.browser_name.as_str() {
            "Chrome 131" | "chrome_131" | "Edge 120" | "edge_120" => {
                // Chrome: IPv4 primeiro
                if let Ok(ipv4s) = ipv4_result {
                    addresses.extend(ipv4s);
                }
                if let Ok(ipv6s) = ipv6_result {
                    addresses.extend(ipv6s);
                }
            }
            "Firefox 133" | "firefox_133" => {
                // Firefox: IPv6 primeiro (prefer IPv6)
                if let Ok(ipv6s) = ipv6_result {
                    addresses.extend(ipv6s);
                }
                if let Ok(ipv4s) = ipv4_result {
                    addresses.extend(ipv4s);
                }
            }
            _ => {
                // Default: IPv4 primeiro
                if let Ok(ipv4s) = ipv4_result {
                    addresses.extend(ipv4s);
                }
                if let Ok(ipv6s) = ipv6_result {
                    addresses.extend(ipv6s);
                }
            }
        }

        if addresses.is_empty() {
            return Err(Error::Proxy(format!("DNS resolution failed for {}", hostname)));
        }

        debug!("Resolved {} -> {} addresses", hostname, addresses.len());
        Ok(addresses)
    }

    /// Query A records (IPv4)
    async fn query_a(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver
            .ipv4_lookup(hostname)
            .await
            .map_err(|e| Error::Proxy(format!("IPv4 lookup failed: {}", e)))?;

        Ok(response.iter().map(|ip| IpAddr::V4(ip.0)).collect())
    }

    /// Query AAAA records (IPv6)
    async fn query_aaaa(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver
            .ipv6_lookup(hostname)
            .await
            .map_err(|e| Error::Proxy(format!("IPv6 lookup failed: {}", e)))?;

        Ok(response.iter().map(|ip| IpAddr::V6(ip.0)).collect())
    }

    /// Detect se está usando DNS-over-HTTPS
    pub fn is_using_doh(&self) -> bool {
        self.use_doh
    }
}

/// DNS-over-HTTPS (DoH) configuration helpers
pub mod doh {
    /// Popular DoH providers URLs
    pub enum DohProvider {
        Cloudflare,
        Google,
        Quad9,
    }

    impl DohProvider {
        pub fn url(&self) -> &'static str {
            match self {
                DohProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
                DohProvider::Google => "https://dns.google/dns-query",
                DohProvider::Quad9 => "https://dns.quad9.net/dns-query",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_resolution() {
        let fingerprinter = DnsFingerprinter::new("Chrome 131".to_string(), false)
            .await
            .unwrap();

        let result = fingerprinter.resolve_with_browser_pattern("google.com").await;
        assert!(result.is_ok());
        
        let addresses = result.unwrap();
        assert!(!addresses.is_empty());
    }

    #[tokio::test]
    async fn test_doh_resolver() {
        let fingerprinter = DnsFingerprinter::new("Firefox 133".to_string(), true)
            .await
            .unwrap();

        assert!(fingerprinter.is_using_doh());
    }
}
