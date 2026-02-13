use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, info, warn};

/// ACME v2 Client — Real implementation with ES256 JWS signing
/// Supports Let's Encrypt and any RFC 8555 compatible provider
pub struct AcmeClient {
    client: Client,
    directory_url: String,
    account_email: String,
    account_key_path: String,
    account_kid: Mutex<Option<String>>,
    rng: SystemRandom,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeOrder {
    pub status: String,
    #[serde(default)]
    pub authorizations: Vec<String>,
    #[serde(default)]
    pub finalize: String,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub expires: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeAuthorization {
    pub status: String,
    pub identifier: AcmeIdentifier,
    pub challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub token: Option<String>,
    pub status: String,
}

// Keep backward compat
pub type CertificateOrder = AcmeOrder;

impl AcmeClient {
    /// Create new ACME client
    pub fn new(directory_url: String, account_email: String, account_key_path: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            directory_url,
            account_email,
            account_key_path,
            account_kid: Mutex::new(None),
            rng: SystemRandom::new(),
        }
    }

    pub fn letsencrypt_production() -> &'static str {
        "https://acme-v02.api.letsencrypt.org/directory"
    }

    pub fn letsencrypt_staging() -> &'static str {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    }

    // ── Directory + Nonce ────────────────────────────────────────────

    pub async fn get_directory(&self) -> Result<AcmeDirectory> {
        debug!("Fetching ACME directory from {}", self.directory_url);
        let response = self.client
            .get(&self.directory_url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("ACME directory request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Internal(format!(
                "ACME directory returned status: {}", response.status()
            )));
        }
        response
            .json::<AcmeDirectory>()
            .await
            .map_err(|e| Error::Internal(format!("Failed to parse ACME directory: {}", e)))
    }

    async fn get_nonce(&self, directory: &AcmeDirectory) -> Result<String> {
        let resp = self.client
            .head(&directory.new_nonce)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Nonce request failed: {}", e)))?;

        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Internal("No replay-nonce header".to_string()))
    }

    // ── Account Key Management ───────────────────────────────────────

    fn load_or_generate_key(&self) -> Result<EcdsaKeyPair> {
        let path = Path::new(&self.account_key_path);
        if path.exists() {
            let der = std::fs::read(path)
                .map_err(|e| Error::Internal(format!("Failed to read account key: {}", e)))?;
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &self.rng)
                .map_err(|e| Error::Internal(format!("Failed to parse account key: {}", e)))
        } else {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.rng)
                .map_err(|e| Error::Internal(format!("Key generation failed: {}", e)))?;
            let der = pkcs8.as_ref().to_vec();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, &der)
                .map_err(|e| Error::Internal(format!("Failed to write account key: {}", e)))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)
                    .map_err(|e| Error::Internal(format!("Failed to read account key metadata: {}", e)))?
                    .permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms)
                    .map_err(|e| Error::Internal(format!("Failed to set account key permissions: {}", e)))?;
            }
            info!("Generated new ACME account key at {}", self.account_key_path);
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &self.rng)
                .map_err(|e| Error::Internal(format!("Failed to load generated key: {}", e)))
        }
    }

    /// Compute JWK thumbprint (SHA-256) per RFC 7638
    fn jwk_thumbprint(&self, key: &EcdsaKeyPair) -> String {
        let public = key.public_key().as_ref();
        // P-256 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
        let x = URL_SAFE_NO_PAD.encode(&public[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public[33..65]);
        let jwk_json = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            x, y
        );
        let hash = Sha256::digest(jwk_json.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Build JWK object for the account key
    fn build_jwk(&self, key: &EcdsaKeyPair) -> serde_json::Value {
        let public = key.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&public[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public[33..65]);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
    }

    // ── JWS Signing (RFC 7515 / ACME) ───────────────────────────────

    fn sign_jws(
        &self,
        key: &EcdsaKeyPair,
        url: &str,
        nonce: &str,
        payload: &str,
        kid: Option<&str>,
    ) -> Result<String> {
        // Build protected header
        let protected = if let Some(kid) = kid {
            serde_json::json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url
            })
        } else {
            serde_json::json!({
                "alg": "ES256",
                "jwk": self.build_jwk(key),
                "nonce": nonce,
                "url": url
            })
        };

        let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string().as_bytes());
        let payload_b64 = if payload.is_empty() {
            String::new() // POST-as-GET
        } else {
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        };

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let sig = key.sign(&self.rng, signing_input.as_bytes())
            .map_err(|e| Error::Internal(format!("JWS signing failed: {}", e)))?;

        // ECDSA_P256_SHA256_FIXED_SIGNING produces raw r||s (64 bytes)
        // which is exactly what ES256 JWS expects (no DER decoding needed)
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let jws = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64
        });

        Ok(jws.to_string())
    }

    /// Send a signed ACME request, returns (response_body, new_nonce, location_header)
    async fn acme_post(
        &self,
        key: &EcdsaKeyPair,
        url: &str,
        nonce: &str,
        payload: &str,
        kid: Option<&str>,
    ) -> Result<(String, String, Option<String>)> {
        let body = self.sign_jws(key, url, nonce, payload, kid)?;

        let resp = self.client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("ACME POST failed: {}", e)))?;

        let new_nonce = resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let location = resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let status = resp.status();
        let text = resp.text().await
            .map_err(|e| Error::Internal(format!("Failed to read ACME response: {}", e)))?;

        if !status.is_success() && status.as_u16() != 201 {
            return Err(Error::Internal(format!(
                "ACME request to {} failed ({}): {}", url, status, text
            )));
        }

        Ok((text, new_nonce, location))
    }

    // ── Account Registration ─────────────────────────────────────────

    async fn register_account(&self, directory: &AcmeDirectory) -> Result<String> {
        let key = self.load_or_generate_key()?;
        let nonce = self.get_nonce(directory).await?;

        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.account_email)]
        });

        let (_body, _nonce, location) = self.acme_post(
            &key,
            &directory.new_account,
            &nonce,
            &payload.to_string(),
            None, // Use JWK for first request
        ).await?;

        let kid = location
            .ok_or_else(|| Error::Internal("No Location header in account response".to_string()))?;

        info!("ACME account registered: {}", kid);
        *self.account_kid.lock().unwrap() = Some(kid.clone());
        Ok(kid)
    }

    async fn ensure_account(&self, directory: &AcmeDirectory) -> Result<String> {
        {
            let kid = self.account_kid.lock().unwrap();
            if let Some(ref k) = *kid {
                return Ok(k.clone());
            }
        }
        self.register_account(directory).await
    }

    // ── Certificate Request (HTTP-01) ────────────────────────────────

    /// Request certificate via HTTP-01 challenge
    pub async fn request_certificate(
        &self,
        domains: Vec<String>,
        webroot_path: &str,
    ) -> Result<(String, String)> {
        info!("Requesting certificate for domains: {:?}", domains);

        let webroot_base = Self::sanitize_webroot_path(webroot_path)?;

        let directory = self.get_directory().await?;
        let kid = self.ensure_account(&directory).await?;
        let key = self.load_or_generate_key()?;

        // Create order
        let identifiers: Vec<serde_json::Value> = domains.iter()
            .map(|d| serde_json::json!({"type": "dns", "value": d}))
            .collect();
        let order_payload = serde_json::json!({"identifiers": identifiers});

        let nonce = self.get_nonce(&directory).await?;
        let (order_body, mut nonce, order_location) = self.acme_post(
            &key, &directory.new_order, &nonce,
            &order_payload.to_string(), Some(&kid),
        ).await?;

        let order: AcmeOrder = serde_json::from_str(&order_body)
            .map_err(|e| Error::Internal(format!("Failed to parse order: {}", e)))?;
        let order_url = order_location
            .ok_or_else(|| Error::Internal("No order URL".to_string()))?;
        info!("Order created: status={}, url={}", order.status, order_url);

        // Process authorizations
        for auth_url in &order.authorizations {
            // POST-as-GET to fetch authorization
            let (auth_body, new_nonce, _) = self.acme_post(
                &key, auth_url, &nonce, "", Some(&kid),
            ).await?;
            nonce = new_nonce;

            let auth: AcmeAuthorization = serde_json::from_str(&auth_body)
                .map_err(|e| Error::Internal(format!("Failed to parse auth: {}", e)))?;

            // Find HTTP-01 challenge
            let challenge = auth.challenges.iter()
                .find(|c| c.challenge_type == "http-01")
                .ok_or_else(|| Error::Internal("No HTTP-01 challenge found".to_string()))?;

            let token = challenge.token.as_ref()
                .ok_or_else(|| Error::Internal("No token in challenge".to_string()))?;

            if !Self::is_valid_challenge_token(token) {
                return Err(Error::Security("Invalid ACME challenge token format".to_string()));
            }

            // key authorization = token.thumbprint
            let thumbprint = self.jwk_thumbprint(&key);
            let key_auth = format!("{}.{}", token, thumbprint);

            // Write challenge file to webroot
            let challenge_dir = webroot_base.join(".well-known").join("acme-challenge");
            tokio::fs::create_dir_all(&challenge_dir).await
                .map_err(|e| Error::Internal(format!("Failed to create challenge dir: {}", e)))?;
            let challenge_file = challenge_dir.join(token);
            tokio::fs::write(&challenge_file, key_auth.as_bytes()).await
                .map_err(|e| Error::Internal(format!("Failed to write challenge file: {}", e)))?;
            info!("HTTP-01 challenge file written: {}", challenge_file.display());

            // Notify ACME server to validate
            let (_, new_nonce, _) = self.acme_post(
                &key, &challenge.url, &nonce, "{}", Some(&kid),
            ).await?;
            nonce = new_nonce;

            // Poll until validated
            self.poll_challenge_status(&key, &challenge.url, &kid, &mut nonce).await?;

            // Cleanup challenge file
            tokio::fs::remove_file(&challenge_file).await.ok();
        }

        // Generate CSR with rcgen
        let cert_key_pair = rcgen::KeyPair::generate()
            .map_err(|e| Error::Internal(format!("CSR key generation failed: {}", e)))?;
        let mut params = rcgen::CertificateParams::default();
        for domain in &domains {
            let ia5 = rcgen::string::Ia5String::try_from(domain.clone())
                .map_err(|e| Error::Internal(format!("Invalid domain name: {}", e)))?;
            params.subject_alt_names.push(rcgen::SanType::DnsName(ia5));
        }
        let csr = params.serialize_request(&cert_key_pair)
            .map_err(|e| Error::Internal(format!("CSR generation failed: {}", e)))?;
        let csr_der = csr.der();
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der);

        // Finalize order
        let finalize_payload = serde_json::json!({"csr": csr_b64});
        let (finalize_body, mut nonce, _) = self.acme_post(
            &key, &order.finalize, &nonce,
            &finalize_payload.to_string(), Some(&kid),
        ).await?;

        // Poll order until valid
        let final_order = self.poll_order_status(&key, &order_url, &kid, &mut nonce).await?;

        // Download certificate
        let cert_url = final_order.certificate
            .or_else(|| {
                serde_json::from_str::<AcmeOrder>(&finalize_body).ok()
                    .and_then(|o| o.certificate)
            })
            .ok_or_else(|| Error::Internal("No certificate URL in order".to_string()))?;

        let (cert_pem, _, _) = self.acme_post(
            &key, &cert_url, &nonce, "", Some(&kid),
        ).await?;

        let key_pem = cert_key_pair.serialize_pem();

        info!("Certificate issued successfully for {:?}", domains);
        Ok((cert_pem, key_pem))
    }

    fn sanitize_webroot_path(path: &str) -> Result<PathBuf> {
        if path.is_empty() || path.contains('\0') || path.contains("..") {
            return Err(Error::Security("Invalid webroot path".to_string()));
        }
        let path_buf = PathBuf::from(path);
        if path_buf.is_absolute() {
            return Err(Error::Security("Absolute webroot paths are not allowed".to_string()));
        }
        Ok(path_buf)
    }

    fn is_valid_challenge_token(token: &str) -> bool {
        !token.is_empty()
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    // ── DNS-01 Challenge (Wildcard Support) ──────────────────────────

    /// Request certificate via DNS-01 challenge (supports wildcards)
    ///
    /// # Example
    /// ```rust,ignore
    /// use rama_elite_proxy::acme::{AcmeClient, CloudflareDns};
    /// use std::sync::Arc;
    ///
    /// let client = AcmeClient::new(
    ///     "https://acme-v02.api.letsencrypt.org/directory".to_string(),
    ///     "admin@example.com".to_string(),
    ///     "acme.key".to_string(),
    /// );
    /// let domains = vec!["*.example.com".to_string(), "example.com".to_string()];
    /// let cloudflare = CloudflareDns::from_env()?;
    /// let (cert, key) = client.request_certificate_dns01(domains, Arc::new(cloudflare)).await?;
    /// ```
    pub async fn request_certificate_dns01(
        &self,
        domains: Vec<String>,
        dns_provider: std::sync::Arc<dyn crate::acme::DnsProvider>,
    ) -> Result<(String, String)> {
        info!("Requesting certificate via DNS-01 for: {:?}", domains);

        let directory = self.get_directory().await?;
        let kid = self.ensure_account(&directory).await?;
        let key = self.load_or_generate_key()?;

        // Create order
        let identifiers: Vec<serde_json::Value> = domains.iter()
            .map(|d| serde_json::json!({"type": "dns", "value": d}))
            .collect();
        let order_payload = serde_json::json!({"identifiers": identifiers});

        let nonce = self.get_nonce(&directory).await?;
        let (order_body, mut nonce, order_location) = self.acme_post(
            &key, &directory.new_order, &nonce,
            &order_payload.to_string(), Some(&kid),
        ).await?;

        let order: AcmeOrder = serde_json::from_str(&order_body)
            .map_err(|e| Error::Internal(format!("Failed to parse order: {}", e)))?;
        let order_url = order_location
            .ok_or_else(|| Error::Internal("No order URL".to_string()))?;

        let mut record_ids = Vec::new();

        // Process authorizations with DNS-01
        for auth_url in &order.authorizations {
            let (auth_body, new_nonce, _) = self.acme_post(
                &key, auth_url, &nonce, "", Some(&kid),
            ).await?;
            nonce = new_nonce;

            let auth: AcmeAuthorization = serde_json::from_str(&auth_body)
                .map_err(|e| Error::Internal(format!("Failed to parse auth: {}", e)))?;

            let challenge = auth.challenges.iter()
                .find(|c| c.challenge_type == "dns-01")
                .ok_or_else(|| Error::Internal("No DNS-01 challenge found".to_string()))?;

            let token = challenge.token.as_ref()
                .ok_or_else(|| Error::Internal("No token".to_string()))?;

            let thumbprint = self.jwk_thumbprint(&key);
            let key_auth = format!("{}.{}", token, thumbprint);
            let digest = Sha256::digest(key_auth.as_bytes());
            let dns_value = URL_SAFE_NO_PAD.encode(digest);

            let challenge_name = format!(
                "_acme-challenge.{}",
                auth.identifier.value.trim_start_matches("*.")
            );

            info!("Creating DNS TXT: {} = {}", challenge_name, dns_value);
            let record_id = dns_provider
                .create_txt_record(&challenge_name, &dns_value)
                .await?;
            record_ids.push((record_id, challenge_name.clone(), dns_value.clone()));
        }

        // Wait for DNS propagation
        info!("Waiting for DNS propagation...");
        for (_, name, value) in &record_ids {
            dns_provider.wait_for_propagation(name, value).await?;
        }

        // Notify ACME to validate each challenge
        for auth_url in &order.authorizations {
            let (auth_body, new_nonce, _) = self.acme_post(
                &key, auth_url, &nonce, "", Some(&kid),
            ).await?;
            nonce = new_nonce;

            let auth: AcmeAuthorization = serde_json::from_str(&auth_body)
                .map_err(|e| Error::Internal(format!("Parse auth: {}", e)))?;

            if let Some(ch) = auth.challenges.iter().find(|c| c.challenge_type == "dns-01") {
                let (_, new_nonce, _) = self.acme_post(
                    &key, &ch.url, &nonce, "{}", Some(&kid),
                ).await?;
                nonce = new_nonce;
                self.poll_challenge_status(&key, &ch.url, &kid, &mut nonce).await?;
            }
        }

        // Cleanup DNS records
        for (record_id, name, _) in record_ids {
            match dns_provider.delete_txt_record(&record_id).await {
                Ok(_) => info!("Deleted DNS record: {}", name),
                Err(e) => warn!("Failed to delete DNS record {}: {}", name, e),
            }
        }

        // Generate CSR + finalize (same as HTTP-01)
        let cert_key_pair = rcgen::KeyPair::generate()
            .map_err(|e| Error::Internal(format!("CSR key gen failed: {}", e)))?;
        let mut params = rcgen::CertificateParams::default();
        for domain in &domains {
            let ia5 = rcgen::string::Ia5String::try_from(domain.clone())
                .map_err(|e| Error::Internal(format!("Invalid domain: {}", e)))?;
            params.subject_alt_names.push(rcgen::SanType::DnsName(ia5));
        }
        let csr = params.serialize_request(&cert_key_pair)
            .map_err(|e| Error::Internal(format!("CSR failed: {}", e)))?;
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr.der());

        let finalize_payload = serde_json::json!({"csr": csr_b64});
        let (finalize_body, mut nonce, _) = self.acme_post(
            &key, &order.finalize, &nonce,
            &finalize_payload.to_string(), Some(&kid),
        ).await?;

        let final_order = self.poll_order_status(&key, &order_url, &kid, &mut nonce).await?;

        let cert_url = final_order.certificate
            .or_else(|| serde_json::from_str::<AcmeOrder>(&finalize_body).ok().and_then(|o| o.certificate))
            .ok_or_else(|| Error::Internal("No certificate URL".to_string()))?;

        let (cert_pem, _, _) = self.acme_post(
            &key, &cert_url, &nonce, "", Some(&kid),
        ).await?;
        let key_pem = cert_key_pair.serialize_pem();

        info!("Wildcard certificate issued for {:?}", domains);
        Ok((cert_pem, key_pem))
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, cert_pem: &str) -> Result<()> {
        info!("Revoking certificate ({} bytes)", cert_pem.len());
        let directory = self.get_directory().await?;
        let kid = self.ensure_account(&directory).await?;
        let key = self.load_or_generate_key()?;
        let nonce = self.get_nonce(&directory).await?;

        // Parse PEM to DER
        let pem_parsed = pem::parse(cert_pem)
            .map_err(|e| Error::Internal(format!("Invalid PEM: {}", e)))?;
        let cert_b64 = URL_SAFE_NO_PAD.encode(pem_parsed.contents());

        let payload = serde_json::json!({"certificate": cert_b64});
        self.acme_post(
            &key, &directory.revoke_cert, &nonce,
            &payload.to_string(), Some(&kid),
        ).await?;

        info!("Certificate revoked successfully");
        Ok(())
    }

    // ── Polling Helpers ──────────────────────────────────────────────

    async fn poll_challenge_status(
        &self,
        key: &EcdsaKeyPair,
        challenge_url: &str,
        kid: &str,
        nonce: &mut String,
    ) -> Result<()> {
        for attempt in 1..=30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            let (body, new_nonce, _) = self.acme_post(
                key, challenge_url, nonce, "", Some(kid),
            ).await?;
            *nonce = new_nonce;

            let ch: AcmeChallenge = serde_json::from_str(&body)
                .map_err(|e| Error::Internal(format!("Parse challenge: {}", e)))?;

            match ch.status.as_str() {
                "valid" => {
                    info!("Challenge validated (attempt {})", attempt);
                    return Ok(());
                }
                "invalid" => {
                    return Err(Error::Internal(format!(
                        "Challenge validation failed: {}", body
                    )));
                }
                _ => {
                    debug!("Challenge status: {} (attempt {})", ch.status, attempt);
                }
            }
        }
        Err(Error::Internal("Challenge validation timed out".to_string()))
    }

    async fn poll_order_status(
        &self,
        key: &EcdsaKeyPair,
        order_url: &str,
        kid: &str,
        nonce: &mut String,
    ) -> Result<AcmeOrder> {
        for attempt in 1..=30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            let (body, new_nonce, _) = self.acme_post(
                key, order_url, nonce, "", Some(kid),
            ).await?;
            *nonce = new_nonce;

            let order: AcmeOrder = serde_json::from_str(&body)
                .map_err(|e| Error::Internal(format!("Parse order: {}", e)))?;

            match order.status.as_str() {
                "valid" => {
                    info!("Order valid (attempt {})", attempt);
                    return Ok(order);
                }
                "invalid" => {
                    return Err(Error::Internal(format!(
                        "Order invalid: {}", body
                    )));
                }
                _ => {
                    debug!("Order status: {} (attempt {})", order.status, attempt);
                }
            }
        }
        Err(Error::Internal("Order polling timed out".to_string()))
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
            "/tmp/acme_test_account.key".to_string(),
        );
        assert_eq!(client.account_email, "test@example.com");
    }

    #[test]
    fn test_key_generation_and_thumbprint() {
        let client = AcmeClient::new(
            "https://example.com".to_string(),
            "test@example.com".to_string(),
            "/tmp/acme_test_keygen.key".to_string(),
        );
        // Clean up any leftover test key
        let _ = std::fs::remove_file("/tmp/acme_test_keygen.key");

        let key = client.load_or_generate_key().unwrap();
        let thumbprint = client.jwk_thumbprint(&key);
        // Thumbprint should be base64url-encoded SHA-256 (43 chars)
        assert!(thumbprint.len() == 43, "Thumbprint length: {}", thumbprint.len());

        // Clean up
        let _ = std::fs::remove_file("/tmp/acme_test_keygen.key");
    }

    #[test]
    fn test_jws_signing() {
        let client = AcmeClient::new(
            "https://example.com".to_string(),
            "test@example.com".to_string(),
            "/tmp/acme_test_jws.key".to_string(),
        );
        let _ = std::fs::remove_file("/tmp/acme_test_jws.key");

        let key = client.load_or_generate_key().unwrap();
        let jws = client.sign_jws(
            &key,
            "https://example.com/acme/new-order",
            "test-nonce-123",
            r#"{"identifiers":[{"type":"dns","value":"example.com"}]}"#,
            None,
        ).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        assert!(parsed["protected"].is_string());
        assert!(parsed["payload"].is_string());
        assert!(parsed["signature"].is_string());

        let _ = std::fs::remove_file("/tmp/acme_test_jws.key");
    }

    #[test]
    fn test_jws_signature_length() {
        // ES256 with FIXED_SIGNING produces raw r||s = 64 bytes
        let client = AcmeClient::new(
            "https://example.com".to_string(),
            "test@example.com".to_string(),
            "/tmp/acme_test_siglen.key".to_string(),
        );
        let _ = std::fs::remove_file("/tmp/acme_test_siglen.key");

        let key = client.load_or_generate_key().unwrap();
        let rng = SystemRandom::new();
        let sig = key.sign(&rng, b"test message").unwrap();
        // P-256 FIXED signing: 32 bytes r + 32 bytes s = 64
        assert_eq!(sig.as_ref().len(), 64);

        let _ = std::fs::remove_file("/tmp/acme_test_siglen.key");
    }
}
