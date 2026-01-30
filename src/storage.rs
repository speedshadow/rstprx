use crate::error::{Error, Result};
use crate::types::DomainMapping;
use crate::utils::current_timestamp;
use dashmap::DashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Storage {
    db: Arc<sled::Db>,
    cache: Arc<DashMap<String, DomainMapping>>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| Error::Storage(format!("Failed to open database: {}", e)))?;

        let storage = Self {
            db: Arc::new(db),
            cache: Arc::new(DashMap::new()),
        };

        storage.load_cache()?;

        Ok(storage)
    }

    fn load_cache(&self) -> Result<()> {
        let domains_tree = self.db.open_tree(b"domains")
            .map_err(|e| Error::Storage(format!("Failed to open domains tree: {}", e)))?;

        for item in domains_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::Storage(format!("Failed to iterate domains: {}", e)))?;

            let subdomain = String::from_utf8_lossy(&key).to_string();
            let mapping: DomainMapping = serde_json::from_slice(&value)
                .map_err(|e| Error::Storage(format!("Failed to deserialize domain: {}", e)))?;

            self.cache.insert(subdomain, mapping);
        }

        Ok(())
    }

    pub fn get_domain(&self, subdomain: &str) -> Option<DomainMapping> {
        self.cache.get(subdomain).map(|v| v.clone())
    }

    pub fn count_domains(&self) -> usize {
        self.cache.len()
    }

    pub fn list_domains(&self) -> Vec<DomainMapping> {
        self.cache.iter().map(|v| v.value().clone()).collect()
    }

    pub fn add_domain(&self, subdomain: String, target: String) -> Result<()> {
        let mapping = DomainMapping {
            subdomain: subdomain.clone(),
            target,
            enabled: true,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        };

        let domains_tree = self.db.open_tree(b"domains")
            .map_err(|e| Error::Storage(format!("Failed to open domains tree: {}", e)))?;

        let value = serde_json::to_vec(&mapping)
            .map_err(|e| Error::Storage(format!("Failed to serialize domain: {}", e)))?;

        domains_tree.insert(subdomain.as_bytes(), value)
            .map_err(|e| Error::Storage(format!("Failed to insert domain: {}", e)))?;

        self.cache.insert(subdomain, mapping);

        Ok(())
    }

    pub fn update_domain(&self, subdomain: &str, target: String) -> Result<()> {
        let mut mapping = self.get_domain(subdomain)
            .ok_or_else(|| Error::NotFound(format!("Domain not found: {}", subdomain)))?;

        mapping.target = target;
        mapping.updated_at = current_timestamp();

        let domains_tree = self.db.open_tree(b"domains")
            .map_err(|e| Error::Storage(format!("Failed to open domains tree: {}", e)))?;

        let value = serde_json::to_vec(&mapping)
            .map_err(|e| Error::Storage(format!("Failed to serialize domain: {}", e)))?;

        domains_tree.insert(subdomain.as_bytes(), value)
            .map_err(|e| Error::Storage(format!("Failed to update domain: {}", e)))?;

        self.cache.insert(subdomain.to_string(), mapping);

        Ok(())
    }

    pub fn delete_domain(&self, subdomain: &str) -> Result<()> {
        let domains_tree = self.db.open_tree(b"domains")
            .map_err(|e| Error::Storage(format!("Failed to open domains tree: {}", e)))?;

        domains_tree.remove(subdomain.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to delete domain: {}", e)))?;

        self.cache.remove(subdomain);

        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush()
            .map_err(|e| Error::Storage(format!("Failed to flush database: {}", e)))?;
        Ok(())
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        
        let storage = Storage::new(db_path).unwrap();

        storage.add_domain("test.local".to_string(), "https://example.com".to_string()).unwrap();

        let domain = storage.get_domain("test.local").unwrap();
        assert_eq!(domain.subdomain, "test.local");
        assert_eq!(domain.target, "https://example.com");

        storage.update_domain("test.local", "https://newexample.com".to_string()).unwrap();
        let updated = storage.get_domain("test.local").unwrap();
        assert_eq!(updated.target, "https://newexample.com");

        storage.delete_domain("test.local").unwrap();
        assert!(storage.get_domain("test.local").is_none());
    }
}
