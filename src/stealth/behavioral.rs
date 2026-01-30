use crate::utils::random_delay_ms;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Clone)]
pub struct BehavioralMimicry {
    enabled: bool,
    human_pattern: bool,
    min_delay_ms: u64,
    max_delay_ms: u64,
    burst_threshold: u32,
    burst_delay_ms: u64,
    last_requests: Arc<DashMap<String, RequestHistory>>,
    referer_chains: Arc<DashMap<String, Vec<String>>>,
}

#[derive(Clone)]
struct RequestHistory {
    last_time: Instant,
    count: u32,
    window_start: Instant,
}

impl BehavioralMimicry {
    pub fn new(
        enabled: bool,
        human_pattern: bool,
        min_delay_ms: u64,
        max_delay_ms: u64,
        burst_threshold: u32,
        burst_delay_ms: u64,
    ) -> Self {
        Self {
            enabled,
            human_pattern,
            min_delay_ms,
            max_delay_ms,
            burst_threshold,
            burst_delay_ms,
            last_requests: Arc::new(DashMap::new()),
            referer_chains: Arc::new(DashMap::new()),
        }
    }

    pub async fn apply_delay(&self, target_host: &str) {
        if !self.enabled {
            return;
        }

        let delay = self.calculate_delay(target_host);
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }

        self.update_request_history(target_host);
    }

    fn calculate_delay(&self, target_host: &str) -> u64 {
        if let Some(history) = self.last_requests.get(target_host) {
            let elapsed = history.last_time.elapsed();

            if elapsed < Duration::from_millis(100) {
                return self.burst_delay_ms;
            }

            if self.human_pattern {
                let window_elapsed = history.window_start.elapsed();
                if window_elapsed < Duration::from_secs(1) && history.count >= self.burst_threshold {
                    return self.burst_delay_ms;
                }

                if elapsed < Duration::from_secs(1) {
                    return self.max_delay_ms;
                }
            }
        }

        random_delay_ms(self.min_delay_ms, self.max_delay_ms)
    }

    fn update_request_history(&self, target_host: &str) {
        let now = Instant::now();

        self.last_requests
            .entry(target_host.to_string())
            .and_modify(|history| {
                let window_elapsed = history.window_start.elapsed();
                if window_elapsed > Duration::from_secs(1) {
                    history.count = 1;
                    history.window_start = now;
                } else {
                    history.count += 1;
                }
                history.last_time = now;
            })
            .or_insert_with(|| RequestHistory {
                last_time: now,
                count: 1,
                window_start: now,
            });
    }

    pub fn get_referer(&self, target_host: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }

        self.referer_chains
            .get(target_host)
            .and_then(|chain| chain.last().cloned())
    }

    pub fn update_referer(&self, target_host: &str, current_url: String) {
        if !self.enabled {
            return;
        }

        self.referer_chains
            .entry(target_host.to_string())
            .and_modify(|chain| {
                chain.push(current_url.clone());
                if chain.len() > 10 {
                    chain.remove(0);
                }
            })
            .or_insert_with(|| vec![current_url]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_behavioral_mimicry() {
        let mimicry = BehavioralMimicry::new(true, true, 10, 50, 5, 500);

        let start = Instant::now();
        mimicry.apply_delay("example.com").await;
        let elapsed = start.elapsed();

        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn test_referer_tracking() {
        let mimicry = BehavioralMimicry::new(true, true, 10, 50, 5, 500);

        mimicry.update_referer("example.com", "https://example.com/page1".to_string());
        mimicry.update_referer("example.com", "https://example.com/page2".to_string());

        let referer = mimicry.get_referer("example.com");
        assert_eq!(referer, Some("https://example.com/page2".to_string()));
    }
}
