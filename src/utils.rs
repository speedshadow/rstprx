use std::time::{SystemTime, UNIX_EPOCH};

pub fn random_delay_ms(min: u64, max: u64) -> u64 {
    use rand::Rng;
    if min >= max {
        return min;
    }
    rand::thread_rng().gen_range(min..=max)
}

pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn sanitize_subdomain(subdomain: &str) -> String {
    subdomain
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
        .collect()
}

pub fn anonymize_ip(ip: &str) -> String {
    if let Some(last_dot) = ip.rfind('.') {
        format!("{}.xxx", &ip[..last_dot])
    } else if let Some(last_colon) = ip.rfind(':') {
        format!("{}:xxxx", &ip[..last_colon])
    } else {
        "xxx.xxx.xxx.xxx".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_delay() {
        let delay = random_delay_ms(50, 100);
        assert!(delay >= 50 && delay <= 100);
    }

    #[test]
    fn test_sanitize_subdomain() {
        assert_eq!(sanitize_subdomain("test-123.com"), "test-123.com");
        assert_eq!(sanitize_subdomain("test@#$123"), "test123");
    }

    #[test]
    fn test_anonymize_ip() {
        assert_eq!(anonymize_ip("192.168.1.1"), "192.168.1.xxx");
        assert_eq!(anonymize_ip("2001:db8::1"), "2001:db8::xxxx");
    }
}
