use crate::error::{Error, Result};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovRateLimiter,
};
use nonzero_ext::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Clone)]
pub struct RateLimiter {
    per_ip_limiter: Arc<RwLock<HashMap<IpAddr, Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>>,
    per_domain_limiter: Arc<RwLock<HashMap<String, Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>>,
    per_ip_quota: Quota,
    per_domain_quota: Quota,
    enabled: bool,
}

impl RateLimiter {
    pub fn new(per_ip: u32, per_domain: u32, burst: u32, enabled: bool) -> Self {
        let per_ip_quota = Quota::per_minute(NonZeroU32::new(per_ip).unwrap_or(nonzero!(100u32)))
            .allow_burst(NonZeroU32::new(burst).unwrap_or(nonzero!(20u32)));

        let per_domain_quota = Quota::per_minute(NonZeroU32::new(per_domain).unwrap_or(nonzero!(1000u32)))
            .allow_burst(NonZeroU32::new(burst * 10).unwrap_or(nonzero!(200u32)));

        Self {
            per_ip_limiter: Arc::new(RwLock::new(HashMap::new())),
            per_domain_limiter: Arc::new(RwLock::new(HashMap::new())),
            per_ip_quota,
            per_domain_quota,
            enabled,
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let limiter = {
            let mut limiters = self.per_ip_limiter.write();
            limiters
                .entry(ip)
                .or_insert_with(|| Arc::new(GovRateLimiter::direct(self.per_ip_quota)))
                .clone()
        };

        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::RateLimit(format!("Rate limit exceeded for IP: {}", ip))),
        }
    }

    pub fn check_domain(&self, domain: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let limiter = {
            let mut limiters = self.per_domain_limiter.write();
            limiters
                .entry(domain.to_string())
                .or_insert_with(|| Arc::new(GovRateLimiter::direct(self.per_domain_quota)))
                .clone()
        };

        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::RateLimit(format!("Rate limit exceeded for domain: {}", domain))),
        }
    }

    pub fn cleanup(&self) {
        let mut ip_limiters = self.per_ip_limiter.write();
        ip_limiters.retain(|_, limiter| Arc::strong_count(limiter) > 1);

        let mut domain_limiters = self.per_domain_limiter.write();
        domain_limiters.retain(|_, limiter| Arc::strong_count(limiter) > 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 10, 5, true);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..5 {
            assert!(limiter.check_ip(ip).is_ok());
        }

        assert!(limiter.check_ip(ip).is_err());
    }

    #[test]
    fn test_disabled_rate_limiter() {
        let limiter = RateLimiter::new(1, 1, 1, false);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..100 {
            assert!(limiter.check_ip(ip).is_ok());
        }
    }
}
