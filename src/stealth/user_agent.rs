use parking_lot::RwLock;
use rand::seq::SliceRandom;
use std::sync::Arc;

#[derive(Clone)]
pub struct UserAgentPool {
    agents: Arc<RwLock<Vec<String>>>,
}

impl UserAgentPool {
    pub fn new(agents: Vec<String>) -> Self {
        let agents = if agents.is_empty() {
            Self::default_agents()
        } else {
            agents
        };

        Self {
            agents: Arc::new(RwLock::new(agents)),
        }
    }

    pub fn random(&self) -> String {
        let agents = self.agents.read();
        agents
            .choose(&mut rand::thread_rng())
            .cloned()
            .unwrap_or_else(|| Self::default_agents()[0].clone())
    }

    pub fn add(&self, agent: String) {
        let mut agents = self.agents.write();
        agents.push(agent);
    }

    pub fn set(&self, agents: Vec<String>) {
        let mut current = self.agents.write();
        *current = agents;
    }

    pub fn default_agents() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_agent_pool() {
        let pool = UserAgentPool::new(vec![]);
        let ua = pool.random();
        assert!(!ua.is_empty());
    }

    #[test]
    fn test_custom_agents() {
        let custom = vec!["Custom UA 1".to_string(), "Custom UA 2".to_string()];
        let pool = UserAgentPool::new(custom.clone());
        let ua = pool.random();
        assert!(custom.contains(&ua));
    }
}
