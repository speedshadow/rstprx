use crate::stealth::fingerprint::BrowserProfile;
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

pub static RESPONSE_HEADERS_TO_STRIP: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-timer",
    "x-request-id",
    "x-correlation-id",
    "x-amz-request-id",
    "x-amz-id-2",
    "cf-ray",
    "cf-cache-status",
    "via",
    "x-cdn",
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
        headers.insert(http::header::USER_AGENT, user_agent.parse().unwrap());
        self.add_common_headers(headers, user_agent);
    }

    pub fn add_stealth_headers_for_profile(&self, headers: &mut HeaderMap, profile: &BrowserProfile) {
        let ua = &profile.user_agent;
        headers.insert(http::header::USER_AGENT, ua.parse().unwrap());
        self.add_common_headers(headers, ua);

        // Browser-specific Accept header correlation
        let name = profile.name.as_str();
        if name.contains("Firefox") {
            headers.insert(
                http::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".parse().unwrap(),
            );
            headers.insert("dnt", "1".parse().unwrap());
            headers.insert("te", "trailers".parse().unwrap());
        } else if name.contains("Safari") && !name.contains("Chrome") {
            headers.insert(
                http::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".parse().unwrap(),
            );
        }
        // Chrome/Edge use the default Accept set in add_common_headers
    }

    fn add_common_headers(&self, headers: &mut HeaderMap, user_agent: &str) {
        if !headers.contains_key(http::header::ACCEPT) {
            headers.insert(
                http::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap(),
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

        // sec-ch-ua Client Hints (CRITICAL for 2026 - missing = instant detection)
        if user_agent.contains("Chrome/131") && !user_agent.contains("Edg/") {
            headers.insert("sec-ch-ua", "\"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\", \"Not_A Brand\";v=\"24\"".parse().unwrap());
            headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
            if user_agent.contains("Macintosh") {
                headers.insert("sec-ch-ua-platform", "\"macOS\"".parse().unwrap());
            } else if user_agent.contains("Linux") {
                headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
            } else {
                headers.insert("sec-ch-ua-platform", "\"Windows\"".parse().unwrap());
            }
        } else if user_agent.contains("Edg/120") {
            headers.insert("sec-ch-ua", "\"Microsoft Edge\";v=\"120\", \"Chromium\";v=\"120\", \"Not_A Brand\";v=\"24\"".parse().unwrap());
            headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
            headers.insert("sec-ch-ua-platform", "\"Windows\"".parse().unwrap());
        }
        // Firefox and Safari do NOT send sec-ch-ua (correct real browser behavior)

        headers.insert("sec-fetch-dest", "document".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("sec-fetch-site", "none".parse().unwrap());
        headers.insert("sec-fetch-user", "?1".parse().unwrap());

        // Chrome/Edge send upgrade-insecure-requests, Firefox does too
        if user_agent.contains("Chrome") || user_agent.contains("Edg/") || user_agent.contains("Firefox") {
            headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
        }
    }

    pub fn sanitize_response_headers(&self, headers: &mut HeaderMap) {
        for header_name in RESPONSE_HEADERS_TO_STRIP {
            if let Ok(name) = http::header::HeaderName::from_bytes(header_name.as_bytes()) {
                headers.remove(&name);
            }
        }
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
