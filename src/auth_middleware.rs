use crate::auth::AuthManager;
use crate::error::{Error, Result};
use http::{Request, StatusCode};
use std::sync::Arc;

/// Session cookie management
pub struct SessionManager {
    auth: Arc<AuthManager>,
}

impl SessionManager {
    pub fn new(auth: Arc<AuthManager>) -> Self {
        Self { auth }
    }

    /// Extract and validate session from cookie
    pub fn validate_session<B>(&self, req: &Request<B>) -> Result<String> {
        // Extract cookie header
        let cookie_header = req
            .headers()
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| Error::Auth("No session cookie".to_string()))?;

        // Parse session token from cookies
        let session_token = cookie_header
            .split(';')
            .find_map(|cookie| {
                let cookie = cookie.trim();
                if cookie.starts_with("session=") {
                    Some(cookie.trim_start_matches("session="))
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Auth("Session cookie not found".to_string()))?;

        // Validate JWT token
        let claims = self.auth.validate_token(session_token)?;
        
        Ok(claims.sub)
    }

    /// Check if request is authenticated
    pub fn is_authenticated<B>(&self, req: &Request<B>) -> bool {
        self.validate_session(req).is_ok()
    }

    /// Generate session cookie header
    pub fn generate_session_cookie(&self, username: &str) -> Result<String> {
        let token = self.auth.generate_token(username)?;
        
        // Secure, HttpOnly, SameSite=Strict cookie
        Ok(format!(
            "session={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400",
            token
        ))
    }

    /// Generate logout cookie (expires immediately)
    pub fn generate_logout_cookie() -> String {
        "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cookie_generation() {
        let auth = Arc::new(AuthManager::new(
            "test_secret_key_minimum_32_characters_long".to_string(),
            3600,
            86400,
            true,
        ));
        let session_mgr = SessionManager::new(auth);

        let cookie = session_mgr.generate_session_cookie("testuser").unwrap();
        
        assert!(cookie.contains("session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn test_logout_cookie() {
        let cookie = SessionManager::generate_logout_cookie();
        assert!(cookie.contains("Max-Age=0"));
    }
}
