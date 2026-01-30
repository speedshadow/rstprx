use indexmap::IndexMap;
use crate::stealth::BrowserProfile;

/// Header Order Preservation (CRITICAL FIX!)
/// HTTP/2 pseudo-headers e regular headers têm ordem específica por browser
/// HeaderMap padrão não preserva ordem - facilmente detectável!
pub struct OrderedHeaderBuilder {
    headers: IndexMap<String, String>,
    browser_profile: BrowserProfile,
}

impl OrderedHeaderBuilder {
    pub fn new(browser_profile: BrowserProfile) -> Self {
        Self {
            headers: IndexMap::new(),
            browser_profile,
        }
    }

    /// Insere header mantendo tracking para ordenação posterior
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }

    /// Retorna headers na ordem correta do browser
    pub fn build(&self) -> Vec<(String, String)> {
        let order = match self.browser_profile.name.as_str() {
            "Chrome 131" | "chrome_131" => Self::chrome_order(),
            "Firefox 133" | "firefox_133" => Self::firefox_order(),
            "Safari 18" | "safari_18" => Self::safari_order(),
            "Edge 120" | "edge_120" => Self::edge_order(),
            _ => Self::chrome_order(),
        };

        let mut ordered = Vec::new();
        
        // Ordenar de acordo com o browser
        for &header_name in &order {
            if let Some(value) = self.headers.get(header_name) {
                ordered.push((header_name.to_string(), value.clone()));
            }
        }

        // Adicionar headers não listados no final (custom headers)
        for (name, value) in &self.headers {
            if !order.contains(&name.as_str()) {
                ordered.push((name.clone(), value.clone()));
            }
        }

        ordered
    }

    /// Chrome 131 exact header order
    fn chrome_order() -> Vec<&'static str> {
        vec![
            // HTTP/2 pseudo-headers (sempre primeiro)
            ":method",
            ":authority",
            ":scheme",
            ":path",
            // Chrome-specific headers
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    }

    /// Firefox 133 exact header order (DIFERENTE do Chrome!)
    fn firefox_order() -> Vec<&'static str> {
        vec![
            // HTTP/2 pseudo-headers
            ":method",
            ":path",
            ":authority",
            ":scheme",
            // Firefox-specific order
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "dnt",
            "connection",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "te",
        ]
    }

    /// Safari 18 exact header order
    fn safari_order() -> Vec<&'static str> {
        vec![
            ":method",
            ":scheme",
            ":path",
            ":authority",
            "accept",
            "accept-encoding",
            "accept-language",
            "user-agent",
            "connection",
            "upgrade-insecure-requests",
        ]
    }

    /// Edge 120 order (same as Chrome, Chromium-based)
    fn edge_order() -> Vec<&'static str> {
        Self::chrome_order()
    }

    /// Detecta se header é pseudo-header HTTP/2
    pub fn is_pseudo_header(name: &str) -> bool {
        name.starts_with(':')
    }

    /// Valida ordem de pseudo-headers (devem vir antes de headers regulares)
    pub fn validate_pseudo_header_order(headers: &[(String, String)]) -> bool {
        let mut seen_regular = false;
        
        for (name, _) in headers {
            if Self::is_pseudo_header(name) {
                if seen_regular {
                    return false; // Pseudo-header depois de regular header = inválido!
                }
            } else {
                seen_regular = true;
            }
        }
        
        true
    }
}

/// Converte HeaderMap para ordered headers preservando browser fingerprint
pub fn headermap_to_ordered(
    headers: &http::HeaderMap,
    browser_profile: &BrowserProfile,
) -> Vec<(String, String)> {
    let mut builder = OrderedHeaderBuilder::new(browser_profile.clone());

    for (name, value) in headers {
        if let Ok(value_str) = value.to_str() {
            builder.insert(name.as_str(), value_str);
        }
    }

    builder.build()
}

/// Detecta header order fingerprint (para debugging)
pub fn detect_header_order_fingerprint(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .filter(|(name, _)| !OrderedHeaderBuilder::is_pseudo_header(name))
        .map(|(name, _)| {
            // Abreviar nome do header
            name.split('-')
                .map(|part| part.chars().next().unwrap_or('x'))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::BrowserProfiles;

    #[test]
    fn test_chrome_header_order() {
        let profile = BrowserProfiles::chrome_131();
        let mut builder = OrderedHeaderBuilder::new(profile);

        builder.insert(":path", "/");
        builder.insert("user-agent", "Chrome");
        builder.insert(":method", "GET");
        builder.insert("accept", "*/*");

        let ordered = builder.build();

        // Chrome order: :method, :authority, :scheme, :path, ...
        assert_eq!(ordered[0].0, ":method");
        assert_eq!(ordered[1].0, ":path");
    }

    #[test]
    fn test_firefox_different_order() {
        let profile = BrowserProfiles::firefox_133();
        let mut builder = OrderedHeaderBuilder::new(profile);

        builder.insert(":path", "/");
        builder.insert("user-agent", "Firefox");
        builder.insert(":method", "GET");
        builder.insert(":authority", "example.com");

        let ordered = builder.build();

        // Firefox order: :method, :path, :authority, :scheme
        assert_eq!(ordered[0].0, ":method");
        assert_eq!(ordered[1].0, ":path");
        assert_eq!(ordered[2].0, ":authority");
    }

    #[test]
    fn test_pseudo_header_validation() {
        let valid = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            ("user-agent".to_string(), "test".to_string()),
        ];
        assert!(OrderedHeaderBuilder::validate_pseudo_header_order(&valid));

        let invalid = vec![
            ("user-agent".to_string(), "test".to_string()),
            (":method".to_string(), "GET".to_string()), // Pseudo depois de regular!
        ];
        assert!(!OrderedHeaderBuilder::validate_pseudo_header_order(&invalid));
    }

    #[test]
    fn test_header_fingerprint_detection() {
        let headers = vec![
            ("user-agent".to_string(), "test".to_string()),
            ("accept-encoding".to_string(), "gzip".to_string()),
            ("accept-language".to_string(), "en".to_string()),
        ];

        let fp = detect_header_order_fingerprint(&headers);
        assert_eq!(fp, "ua:ae:al");
    }
}
