use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAssignment {
    pub app_name: String,
    pub slot: String,
    pub port: u16,
    pub timestamp: String,
}

#[derive(Default)]
pub struct PortAllocator {
    used_ports: HashMap<u16, PortAssignment>,
    app_slots: HashMap<(String, String), u16>,
}

impl PortAllocator {
    pub fn new() -> Self {
        Self {
            used_ports: HashMap::new(),
            app_slots: HashMap::new(),
        }
    }

    pub fn allocate(&mut self, app_name: &str, slot: &str) -> Result<u16> {
        let key = (app_name.to_string(), slot.to_string());

        if let Some(&port) = self.app_slots.get(&key) {
            return Ok(port);
        }

        let port = self.find_available_port()?;
        self.used_ports.insert(
            port,
            PortAssignment {
                app_name: app_name.to_string(),
                slot: slot.to_string(),
                port,
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        );
        self.app_slots.insert(key, port);

        Ok(port)
    }

    fn find_available_port(&self) -> Result<u16> {
        if let Some(port) = portpicker::pick_unused_port() {
            return Ok(port);
        }
        anyhow::bail!("No available ports found")
    }

    pub fn release(&mut self, app_name: &str, slot: &str) {
        let key = (app_name.to_string(), slot.to_string());
        if let Some(port) = self.app_slots.remove(&key) {
            self.used_ports.remove(&port);
        }
    }

    pub fn get_port(&self, app_name: &str, slot: &str) -> Option<u16> {
        self.app_slots
            .get(&(app_name.to_string(), slot.to_string()))
            .copied()
    }
}

pub struct PortManager {
    allocator: Arc<Mutex<PortAllocator>>,
    lock_file: PathBuf,
}

impl PortManager {
    pub fn new(lock_dir: &str) -> Result<Self> {
        let lock_dir = PathBuf::from(lock_dir);
        fs::create_dir_all(&lock_dir)?;

        let lock_file = lock_dir.join("ports.lock");

        let allocator = Arc::new(Mutex::new(PortAllocator::new()));

        Ok(Self {
            allocator,
            lock_file,
        })
    }

    pub async fn allocate(&self, app_name: &str, slot: &str) -> Result<u16> {
        let port = {
            let mut allocator = self.allocator.lock().await;
            if let Some(port) = allocator.get_port(app_name, slot) {
                return Ok(port);
            }
            allocator.allocate(app_name, slot)?
        };
        self.persist().await?;
        Ok(port)
    }

    pub async fn release(&self, app_name: &str, slot: &str) {
        {
            let mut allocator = self.allocator.lock().await;
            allocator.release(app_name, slot);
        }
        let _ = self.persist().await;
    }

    async fn persist(&self) -> Result<()> {
        let allocator = self.allocator.lock().await;
        let content = serde_json::to_string_pretty(&allocator.used_ports)?;
        fs::write(&self.lock_file, content)?;
        Ok(())
    }

    pub async fn load(&self) -> Result<()> {
        if !self.lock_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.lock_file)?;
        let assignments: HashMap<u16, PortAssignment> = serde_json::from_str(&content)?;

        let mut allocator = self.allocator.lock().await;
        for (port, assignment) in assignments {
            allocator.used_ports.insert(port, assignment.clone());
            allocator
                .app_slots
                .insert((assignment.app_name, assignment.slot), port);
        }

        Ok(())
    }

    pub async fn get_port(&self, app_name: &str, slot: &str) -> Option<u16> {
        self.allocator.lock().await.get_port(app_name, slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_port_allocation() {
        let temp_dir = TempDir::new().unwrap();
        let pm = PortManager::new(temp_dir.path().to_str().unwrap()).unwrap();

        let port1 = pm.allocate("app1", "blue").await.unwrap();
        let port2 = pm.allocate("app1", "green").await.unwrap();
        let port3 = pm.allocate("app2", "blue").await.unwrap();

        assert_ne!(port1, port2);
        assert_ne!(port1, port3);
        assert_ne!(port2, port3);

        assert_eq!(pm.allocate("app1", "blue").await.unwrap(), port1);
    }

    #[tokio::test]
    async fn test_port_release() {
        let temp_dir = TempDir::new().unwrap();
        let pm = PortManager::new(temp_dir.path().to_str().unwrap()).unwrap();

        let port = pm.allocate("app1", "blue").await.unwrap();
        pm.release("app1", "blue").await;

        let new_port = pm.allocate("app1", "blue").await.unwrap();
        assert_ne!(port, new_port);
    }
}
