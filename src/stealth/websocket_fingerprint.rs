use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use crate::stealth::BrowserProfile;

/// WebSocket Fingerprinting Protection
/// WAFs modernos fingerprintam WebSocket handshakes
pub struct WebSocketFingerprinter {
    browser_profile: BrowserProfile,
}

impl WebSocketFingerprinter {
    pub fn new(browser_profile: BrowserProfile) -> Self {
        Self { browser_profile }
    }

    /// Gera Sec-WebSocket-Key com entropy adequada
    /// Formato: 16 bytes aleatórios encodados em base64
    pub fn generate_ws_key(&self) -> String {
        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        general_purpose::STANDARD.encode(key)
    }

    /// Gera Sec-WebSocket-Extensions com ordem browser-specific
    pub fn build_extensions(&self) -> String {
        match self.browser_profile.name.as_str() {
            "Chrome 131" | "chrome_131" | "Edge 120" | "edge_120" => {
                // Chrome/Edge suportam permessage-deflate com client_max_window_bits
                "permessage-deflate; client_max_window_bits".to_string()
            }
            "Firefox 133" | "firefox_133" => {
                // Firefox usa apenas permessage-deflate
                "permessage-deflate".to_string()
            }
            "Safari 18" | "safari_18" => {
                // Safari não usa deflate por padrão
                String::new()
            }
            _ => "permessage-deflate; client_max_window_bits".to_string(),
        }
    }

    /// Gera headers completos do WebSocket handshake
    pub fn build_handshake_headers(&self, host: &str, path: &str) -> Vec<(String, String)> {
        let ws_key = self.generate_ws_key();
        let extensions = self.build_extensions();

        let mut headers = vec![
            ("GET".to_string(), path.to_string()),
            ("Host".to_string(), host.to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("Sec-WebSocket-Key".to_string(), ws_key),
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
        ];

        // Adicionar User-Agent
        headers.push((
            "User-Agent".to_string(),
            self.browser_profile.user_agent.clone(),
        ));

        // Adicionar extensions se não vazio
        if !extensions.is_empty() {
            headers.push(("Sec-WebSocket-Extensions".to_string(), extensions));
        }

        // Chrome/Edge adicionam Origin
        if self.browser_profile.name.contains("Chrome") || self.browser_profile.name.contains("Edge") {
            headers.push(("Origin".to_string(), format!("https://{}", host)));
        }

        headers
    }

    /// Mascara payload de WebSocket frame
    /// RFC 6455: Client-to-server frames MUST be masked
    pub fn mask_frame(&self, payload: &[u8]) -> (Vec<u8>, [u8; 4]) {
        let mask_key: [u8; 4] = rand::random();
        
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ mask_key[i % 4])
            .collect();

        (masked, mask_key)
    }

    /// Gera WebSocket accept key (para validação)
    pub fn generate_accept_key(ws_key: &str) -> String {
        use sha1::{Sha1, Digest};
        
        const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let concatenated = format!("{}{}", ws_key, GUID);
        
        let mut hasher = Sha1::new();
        hasher.update(concatenated.as_bytes());
        let hash = hasher.finalize();
        
        general_purpose::STANDARD.encode(hash)
    }
}

/// WebSocket Frame Types (RFC 6455)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WsOpcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

/// Build WebSocket frame header
pub fn build_frame_header(opcode: WsOpcode, payload_len: usize, masked: bool) -> Vec<u8> {
    let mut header = vec![0x80 | (opcode as u8)]; // FIN bit + opcode

    // Payload length encoding
    let mask_bit = if masked { 0x80 } else { 0x00 };
    
    if payload_len < 126 {
        header.push(mask_bit | (payload_len as u8));
    } else if payload_len < 65536 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::BrowserProfiles;

    #[test]
    fn test_generate_ws_key() {
        let profile = BrowserProfiles::chrome_131();
        let fp = WebSocketFingerprinter::new(profile);
        
        let key = fp.generate_ws_key();
        
        // Deve ser base64 válido de 16 bytes (24 chars em base64)
        assert_eq!(key.len(), 24);
        assert!(general_purpose::STANDARD.decode(&key).is_ok());
    }

    #[test]
    fn test_chrome_extensions() {
        let profile = BrowserProfiles::chrome_131();
        let fp = WebSocketFingerprinter::new(profile);
        
        let ext = fp.build_extensions();
        assert!(ext.contains("permessage-deflate"));
        assert!(ext.contains("client_max_window_bits"));
    }

    #[test]
    fn test_firefox_extensions() {
        let profile = BrowserProfiles::firefox_133();
        let fp = WebSocketFingerprinter::new(profile);
        
        let ext = fp.build_extensions();
        assert_eq!(ext, "permessage-deflate");
    }

    #[test]
    fn test_mask_frame() {
        let profile = BrowserProfiles::chrome_131();
        let fp = WebSocketFingerprinter::new(profile);
        
        let payload = b"Hello WebSocket";
        let (masked, mask_key) = fp.mask_frame(payload);
        
        // Demascarar para verificar
        let unmasked: Vec<u8> = masked
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ mask_key[i % 4])
            .collect();
        
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn test_accept_key_generation() {
        let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = WebSocketFingerprinter::generate_accept_key(ws_key);
        
        // RFC 6455 example
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_frame_header() {
        let header = build_frame_header(WsOpcode::Text, 5, true);
        
        // 0x81 = FIN + TEXT opcode
        assert_eq!(header[0], 0x81);
        
        // 0x85 = MASK bit + length 5
        assert_eq!(header[1], 0x85);
    }
}
