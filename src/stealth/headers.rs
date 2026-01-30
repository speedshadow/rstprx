use http::HeaderMap;

pub static CHROME_HEADER_ORDER: &[&str] = &[
    ":method",
    ":authority",
    ":scheme",
    ":path",
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
];

pub static FIREFOX_HEADER_ORDER: &[&str] = &[
    ":method",
    ":path",
    ":authority",
    ":scheme",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "origin",
    "dnt",
    "connection",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
];

#[derive(Clone)]
pub struct HeaderManipulator {
    remove_headers: Vec<String>,
    #[allow(dead_code)]
    preserve_order: bool,
}

impl HeaderManipulator {
    pub fn new(remove_headers: Vec<String>, preserve_order: bool) -> Self {
        Self {
            remove_headers,
            preserve_order,
        }
    }

    pub fn clean_headers(&self, headers: &mut HeaderMap) {
        for header_name in &self.remove_headers {
            if let Ok(name) = http::header::HeaderName::from_bytes(header_name.as_bytes()) {
                headers.remove(&name);
            }
        }

        headers.remove(http::header::CONNECTION);
        headers.remove(http::header::UPGRADE);
        headers.remove("proxy-connection");
        headers.remove("proxy-authorization");
    }

    pub fn add_stealth_headers(&self, headers: &mut HeaderMap, user_agent: &str) {
        if !headers.contains_key(http::header::USER_AGENT) {
            headers.insert(http::header::USER_AGENT, user_agent.parse().unwrap());
        }

        if !headers.contains_key(http::header::ACCEPT) {
            headers.insert(
                http::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".parse().unwrap(),
            );
        }

        if !headers.contains_key(http::header::ACCEPT_LANGUAGE) {
            headers.insert(
                http::header::ACCEPT_LANGUAGE,
                "en-US,en;q=0.9".parse().unwrap(),
            );
        }

        if !headers.contains_key(http::header::ACCEPT_ENCODING) {
            headers.insert(
                http::header::ACCEPT_ENCODING,
                "gzip, deflate, br, zstd".parse().unwrap(),
            );
        }

        headers.insert("sec-fetch-dest", "document".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("sec-fetch-site", "none".parse().unwrap());
        headers.insert("sec-fetch-user", "?1".parse().unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_cleaning() {
        let manipulator =
            HeaderManipulator::new(vec!["X-Forwarded-For".to_string(), "Via".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "127.0.0.1".parse().unwrap());
        headers.insert("Via", "proxy".parse().unwrap());
        headers.insert(http::header::HOST, "example.com".parse().unwrap());

        manipulator.clean_headers(&mut headers);

        assert!(!headers.contains_key("X-Forwarded-For"));
        assert!(!headers.contains_key("Via"));
        assert!(headers.contains_key(http::header::HOST));
    }
}
