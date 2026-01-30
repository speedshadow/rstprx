use serde_json::Value;

pub struct IptvRewriter {
    proxy_scheme: String,
    proxy_host: String,
}

impl IptvRewriter {
    pub fn new() -> Self {
        Self {
            proxy_scheme: "https".to_string(),
            proxy_host: String::new(),
        }
    }

    pub fn set_proxy_origin(&mut self, scheme: &str, host: &str) {
        self.proxy_scheme = scheme.to_string();
        self.proxy_host = host.to_string();
    }

    pub fn should_rewrite(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        lower.ends_with(".m3u")
            || lower.ends_with(".m3u8")
            || lower.contains("player_api.php")
            || lower.contains("get.php")
            || lower.contains("/live/")
            || lower.contains("/movie/")
    }

    pub fn rewrite_content(
        &self,
        content: &[u8],
        target_url: &str,
        path: String,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if path.to_lowercase().ends_with(".json") || self.is_json_response(content) {
            self.rewrite_json(content, target_url)
        } else {
            Ok(self.rewrite_m3u(content, target_url))
        }
    }

    fn is_json_response(&self, content: &[u8]) -> bool {
        if content.is_empty() {
            return false;
        }

        let first_char = content[0];
        first_char == b'{' || first_char == b'['
    }

    fn rewrite_m3u(&self, content: &[u8], target_url: &str) -> Vec<u8> {
        let content_str = String::from_utf8_lossy(content);
        let mut result = String::new();

        for line in content_str.lines() {
            if line.starts_with("http://") || line.starts_with("https://") {
                if let Some(rewritten) = self.rewrite_url(line, target_url) {
                    result.push_str(&rewritten);
                    result.push('\n');
                    continue;
                }
            }
            result.push_str(line);
            result.push('\n');
        }

        result.into_bytes()
    }

    fn rewrite_json(
        &self,
        content: &[u8],
        target_url: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let json: Value = serde_json::from_slice(content)?;
        let rewritten = self.rewrite_json_value(&json, target_url);
        Ok(serde_json::to_vec(&rewritten)?)
    }

    fn rewrite_json_value(&self, value: &Value, target_url: &str) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    new_map.insert(key.clone(), self.rewrite_json_value(val, target_url));
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| self.rewrite_json_value(v, target_url))
                    .collect(),
            ),
            Value::String(s) => {
                if s.starts_with("http://") || s.starts_with("https://") {
                    if let Some(rewritten) = self.rewrite_url(s, target_url) {
                        return Value::String(rewritten);
                    }
                }
                Value::String(s.clone())
            }
            _ => value.clone(),
        }
    }

    fn rewrite_url(&self, original_url: &str, target_url: &str) -> Option<String> {
        let parsed_original = url::Url::parse(original_url).ok()?;
        let parsed_target = url::Url::parse(target_url).ok()?;

        if parsed_original.host_str() != parsed_target.host_str() {
            return None;
        }

        let new_url = format!(
            "{}://{}{}{}",
            self.proxy_scheme,
            self.proxy_host,
            parsed_original.path(),
            parsed_original
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default()
        );

        Some(new_url)
    }
}

impl Default for IptvRewriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_rewrite() {
        let rewriter = IptvRewriter::new();
        assert!(rewriter.should_rewrite("/playlist.m3u8"));
        assert!(rewriter.should_rewrite("/player_api.php"));
        assert!(!rewriter.should_rewrite("/index.html"));
    }

    #[test]
    fn test_m3u_rewriting() {
        let mut rewriter = IptvRewriter::new();
        rewriter.set_proxy_origin("https", "proxy.local");

        let content = b"#EXTM3U\nhttp://target.com/stream1\nhttp://target.com/stream2\n";
        let rewritten = rewriter.rewrite_m3u(content, "http://target.com");

        let result = String::from_utf8_lossy(&rewritten);
        assert!(result.contains("https://proxy.local"));
    }
}
