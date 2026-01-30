use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Path Traversal Protection (CRITICAL SECURITY FIX!)
/// Previne ataques de path traversal (.., absolute paths, symlinks maliciosos)
pub struct PathSanitizer;

impl PathSanitizer {
    /// Sanitiza e valida path para prevenir path traversal
    pub fn sanitize(path: &str) -> Result<PathBuf> {
        // Check 1: Rejeitar paths absolutos
        let path_buf = PathBuf::from(path);
        if path_buf.is_absolute() {
            return Err(Error::Security(
                "Absolute paths are not allowed for security reasons".to_string()
            ));
        }

        // Check 2: Rejeitar .. (parent directory)
        if path.contains("..") {
            return Err(Error::Security(
                "Path traversal attempt detected (..)".to_string()
            ));
        }

        // Check 3: Rejeitar ~ (home directory)
        if path.contains('~') {
            return Err(Error::Security(
                "Home directory expansion (~) is not allowed".to_string()
            ));
        }

        // Check 4: Rejeitar null bytes
        if path.contains('\0') {
            return Err(Error::Security(
                "Null byte injection detected".to_string()
            ));
        }

        // Check 5: Canonicalize para resolver symlinks
        let current_dir = std::env::current_dir()
            .map_err(|e| Error::Internal(format!("Failed to get current directory: {}", e)))?;
        
        let full_path = current_dir.join(&path_buf);
        
        // Canonicalize detecta symlinks maliciosos
        let canonical = full_path.canonicalize()
            .map_err(|e| Error::Security(format!("Path canonicalization failed: {}", e)))?;

        // Check 6: Verificar que canonical ainda está dentro do current_dir
        if !canonical.starts_with(&current_dir) {
            return Err(Error::Security(
                "Path escapes working directory".to_string()
            ));
        }

        Ok(canonical)
    }

    /// Sanitiza path de certificado com validações adicionais
    pub fn sanitize_cert_path(path: &str) -> Result<PathBuf> {
        let sanitized = Self::sanitize(path)?;

        // Validar extensão
        let extension = sanitized
            .extension()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Security("Certificate file must have an extension".to_string()))?;

        match extension {
            "pem" | "key" | "crt" | "cert" | "ca" => Ok(sanitized),
            _ => Err(Error::Security(format!(
                "Invalid certificate file extension: {}. Allowed: pem, key, crt, cert, ca",
                extension
            ))),
        }
    }

    /// Sanitiza path de config com validações adicionais
    pub fn sanitize_config_path(path: &str) -> Result<PathBuf> {
        let sanitized = Self::sanitize(path)?;

        // Validar extensão
        let extension = sanitized
            .extension()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Security("Config file must have an extension".to_string()))?;

        match extension {
            "yaml" | "yml" | "toml" | "json" => Ok(sanitized),
            _ => Err(Error::Security(format!(
                "Invalid config file extension: {}. Allowed: yaml, yml, toml, json",
                extension
            ))),
        }
    }

    /// Sanitiza path de database
    pub fn sanitize_db_path(path: &str) -> Result<PathBuf> {
        let sanitized = Self::sanitize(path)?;

        // Database paths podem ser diretórios ou arquivos
        if !sanitized.exists() {
            // Se não existe, criar parent directory
            if let Some(parent) = sanitized.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Storage(format!("Failed to create db directory: {}", e)))?;
            }
        }

        Ok(sanitized)
    }

    /// Valida se path existe e é do tipo esperado
    pub fn validate_existing_path(path: &Path, expected_type: PathType) -> Result<()> {
        if !path.exists() {
            return Err(Error::Config(format!("Path does not exist: {:?}", path)));
        }

        match expected_type {
            PathType::File => {
                if !path.is_file() {
                    return Err(Error::Config(format!("Path is not a file: {:?}", path)));
                }
            }
            PathType::Directory => {
                if !path.is_dir() {
                    return Err(Error::Config(format!("Path is not a directory: {:?}", path)));
                }
            }
            PathType::Any => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PathType {
    File,
    Directory,
    Any,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_reject_absolute_path() {
        let result = PathSanitizer::sanitize("/etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Absolute paths"));
    }

    #[test]
    fn test_reject_parent_directory() {
        let result = PathSanitizer::sanitize("../../../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn test_reject_home_directory() {
        let result = PathSanitizer::sanitize("~/secret.key");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Home directory"));
    }

    #[test]
    fn test_reject_null_byte() {
        let result = PathSanitizer::sanitize("file\0.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Null byte"));
    }

    #[test]
    fn test_valid_relative_path() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();
        
        // Criar arquivo válido
        std::fs::write("test.txt", "content").unwrap();
        
        let result = PathSanitizer::sanitize("test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_path_validation() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();
        
        std::fs::write("cert.pem", "cert").unwrap();
        assert!(PathSanitizer::sanitize_cert_path("cert.pem").is_ok());
        
        std::fs::write("bad.txt", "bad").unwrap();
        assert!(PathSanitizer::sanitize_cert_path("bad.txt").is_err());
    }
}
