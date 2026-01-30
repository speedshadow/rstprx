use crate::error::{Error, Result};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub refresh: bool,
}

#[derive(Clone)]
pub struct AuthManager {
    secret: Arc<Vec<u8>>,
    token_expiry: i64,
    refresh_expiry: i64,
    refresh_enabled: bool,
}

impl AuthManager {
    pub fn new(secret: String, token_expiry: u64, refresh_expiry: u64, refresh_enabled: bool) -> Self {
        Self {
            secret: Arc::new(secret.into_bytes()),
            token_expiry: token_expiry as i64,
            refresh_expiry: refresh_expiry as i64,
            refresh_enabled,
        }
    }

    pub fn generate_token(&self, username: &str) -> Result<String> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: username.to_string(),
            exp: now + self.token_expiry,
            iat: now,
            refresh: false,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.secret),
        )
        .map_err(|e| Error::Auth(format!("Failed to generate token: {}", e)))
    }

    pub fn generate_refresh_token(&self, username: &str) -> Result<String> {
        if !self.refresh_enabled {
            return Err(Error::Auth("Refresh tokens are disabled".to_string()));
        }

        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: username.to_string(),
            exp: now + self.refresh_expiry,
            iat: now,
            refresh: true,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.secret),
        )
        .map_err(|e| Error::Auth(format!("Failed to generate refresh token: {}", e)))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::default();
        
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.secret),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|e| Error::Auth(format!("Invalid token: {}", e)))
    }

    /// Hash password com Argon2 (CRITICAL SECURITY FIX!)
    /// Argon2 é resistente a timing attacks e GPU cracking
    pub fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string()
    }

    /// Verifica password com constant-time comparison
    pub fn verify_password(password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_validation() {
        let manager = AuthManager::new(
            "test_secret_key_minimum_32_characters_long".to_string(),
            3600,
            86400,
            true,
        );

        let token = manager.generate_token("testuser").unwrap();
        let claims = manager.validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, "testuser");
        assert!(!claims.refresh);
    }

    #[test]
    fn test_refresh_token() {
        let manager = AuthManager::new(
            "test_secret_key_minimum_32_characters_long".to_string(),
            3600,
            86400,
            true,
        );

        let refresh_token = manager.generate_refresh_token("testuser").unwrap();
        let claims = manager.validate_token(&refresh_token).unwrap();
        
        assert_eq!(claims.sub, "testuser");
        assert!(claims.refresh);
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure_password_123";
        let hash = AuthManager::hash_password(password);
        
        assert!(AuthManager::verify_password(password, &hash));
        assert!(!AuthManager::verify_password("wrong_password", &hash));
    }
}
