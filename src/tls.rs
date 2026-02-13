use crate::error::{Error, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use rcgen::string::Ia5String;
use rustls::ServerConfig;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

fn validate_cert_path(path: &str) -> Result<PathBuf> {
    // Security checks for cert paths (allows absolute paths for internal use)
    if path.contains("..") {
        return Err(Error::Security("Path traversal attempt detected (..)".to_string()));
    }
    if path.contains('\0') {
        return Err(Error::Security("Null byte injection detected".to_string()));
    }
    // SAFETY: path already validated against traversal above
    let p = PathBuf::from(path);
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
    match ext {
        "pem" | "key" | "crt" | "cert" | "ca" => Ok(p),
        _ => Err(Error::Security(format!(
            "Invalid certificate file extension: {}. Allowed: pem, key, crt, cert, ca", ext
        ))),
    }
}

pub fn generate_self_signed_cert(
    cert_path: &str,
    key_path: &str,
    hosts: Vec<String>,
) -> Result<()> {
    validate_cert_path(cert_path)?;
    validate_cert_path(key_path)?;

    // SAFETY: cert_path validated by validate_cert_path above
    if let Some(parent) = Path::new(cert_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Elite Proxy");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Elite Proxy Service");

    // Certificado válido por 365 dias
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + Duration::days(365);
    params.not_before = not_before;
    params.not_after = not_after;

    for host in hosts {
        if host.parse::<std::net::IpAddr>().is_ok() {
            params
                .subject_alt_names
                .push(SanType::IpAddress(host.parse().unwrap()));
        } else {
            params.subject_alt_names.push(SanType::DnsName(
                Ia5String::try_from(host.to_string())
                    .map_err(|e| Error::Tls(format!("Invalid DNS name: {}", e)))?,
            ));
        }
    }

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| Error::Tls(format!("Failed to generate keypair: {}", e)))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Tls(format!("Failed to generate certificate: {}", e)))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, cert_pem)?;
    fs::write(key_path, key_pem)?;

    Ok(())
}

pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    validate_cert_path(cert_path)?;
    validate_cert_path(key_path)?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(format!("Failed to create TLS config: {}", e)))?;

    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let validated_path = validate_cert_path(path)?;
    // SAFETY: path validated against traversal/null/extension
    let cert_file = fs::File::open(&validated_path)?;
    let mut reader = std::io::BufReader::new(cert_file);

    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| Error::Tls(format!("Failed to load certificates: {}", e)))
}

fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let validated_path = validate_cert_path(path)?;
    // SAFETY: path validated against traversal/null/extension
    let key_file = fs::File::open(&validated_path)?;
    let mut reader = std::io::BufReader::new(key_file);

    let keys: std::result::Result<Vec<_>, _> =
        rustls_pemfile::pkcs8_private_keys(&mut reader).collect();
    let mut keys = keys.map_err(|e| Error::Tls(format!("Failed to load private key: {}", e)))?;

    if keys.is_empty() {
        return Err(Error::Tls("No private key found".to_string()));
    }

    Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_self_signed_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let result = generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            vec!["localhost".to_string(), "127.0.0.1".to_string()],
        );

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }
}
