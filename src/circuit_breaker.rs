use crate::error::{Error, Result};
use crate::types::CircuitState;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CircuitBreakerState {
    state: CircuitState,
    failures: u32,
    successes: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failures: 0,
            successes: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
        }
    }
}

#[derive(Clone)]
pub struct CircuitBreaker {
    states: Arc<Mutex<HashMap<String, CircuitBreakerState>>>,
    max_failures: u32,
    timeout: Duration,
    half_open_max_requests: u32,
    #[allow(dead_code)]
    failure_threshold: f64,
    enabled: bool,
}

impl CircuitBreaker {
    pub fn new(
        max_failures: u32,
        timeout_secs: u64,
        failure_threshold: f64,
        enabled: bool,
    ) -> Self {
        Self {
            states: Arc::new(Mutex::new(HashMap::new())),
            max_failures,
            timeout: Duration::from_secs(timeout_secs),
            half_open_max_requests: 3,
            failure_threshold,
            enabled,
        }
    }

    pub async fn call<F, Fut, T>(&self, key: &str, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if !self.enabled {
            return f().await;
        }

        self.before_call(key)?;

        match f().await {
            Ok(result) => {
                self.on_success(key);
                Ok(result)
            }
            Err(e) => {
                self.on_failure(key);
                Err(e)
            }
        }
    }

    fn before_call(&self, key: &str) -> Result<()> {
        let mut states = self.states.lock();
        let state = states.entry(key.to_string()).or_insert_with(CircuitBreakerState::new);

        match state.state {
            CircuitState::Open => {
                if state.last_state_change.elapsed() > self.timeout {
                    state.state = CircuitState::HalfOpen;
                    state.successes = 0;
                    state.failures = 0;
                    state.last_state_change = Instant::now();
                    Ok(())
                } else {
                    Err(Error::Proxy(format!("Circuit breaker open for: {}", key)))
                }
            }
            CircuitState::HalfOpen => {
                if state.successes + state.failures >= self.half_open_max_requests {
                    Err(Error::Proxy(format!("Circuit breaker half-open limit reached for: {}", key)))
                } else {
                    Ok(())
                }
            }
            CircuitState::Closed => Ok(()),
        }
    }

    fn on_success(&self, key: &str) {
        let mut states = self.states.lock();
        let state = states.entry(key.to_string()).or_insert_with(CircuitBreakerState::new);

        match state.state {
            CircuitState::HalfOpen => {
                state.successes += 1;
                if state.successes >= self.half_open_max_requests {
                    state.state = CircuitState::Closed;
                    state.failures = 0;
                    state.successes = 0;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::Closed => {
                state.failures = 0;
            }
            CircuitState::Open => {}
        }
    }

    fn on_failure(&self, key: &str) {
        let mut states = self.states.lock();
        let state = states.entry(key.to_string()).or_insert_with(CircuitBreakerState::new);

        state.failures += 1;
        state.last_failure_time = Some(Instant::now());

        match state.state {
            CircuitState::Closed => {
                if state.failures >= self.max_failures {
                    state.state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                state.state = CircuitState::Open;
                state.last_state_change = Instant::now();
            }
            CircuitState::Open => {}
        }
    }

    pub fn get_state(&self, key: &str) -> CircuitState {
        let states = self.states.lock();
        states.get(key).map(|s| s.state).unwrap_or(CircuitState::Closed)
    }

    pub fn reset(&self, key: &str) {
        let mut states = self.states.lock();
        if let Some(state) = states.get_mut(key) {
            state.state = CircuitState::Closed;
            state.failures = 0;
            state.successes = 0;
            state.last_state_change = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let cb = CircuitBreaker::new(3, 60, 0.6, true);
        let key = "test-service";

        for _ in 0..3 {
            let _ = cb.call(key, || async { Err::<(), _>(Error::Proxy("test error".to_string())) }).await;
        }

        assert_eq!(cb.get_state(key), CircuitState::Open);

        let result = cb.call(key, || async { Ok(()) }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker_disabled() {
        let cb = CircuitBreaker::new(1, 60, 0.6, false);
        let key = "test-service";

        for _ in 0..10 {
            let result = cb.call(key, || async { Err::<(), _>(Error::Proxy("test error".to_string())) }).await;
            assert!(result.is_err());
        }

        assert_eq!(cb.get_state(key), CircuitState::Closed);
    }
}
