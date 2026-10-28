use crate::dns::DnsSnapshot;
use crate::id::DomainIdResult;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub domain_id: String,
    pub raw_id: String,
    pub canonical_domain: String,
    pub checksum: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: String,
    pub cached_dns: Option<DnsSnapshot>,
}

pub struct SdsRegistry {
    file_path: PathBuf,
    entries: HashMap<String, RegistryEntry>, // keyed by raw_id
    domain_to_id: HashMap<String, String>,   // domain -> raw_id
}

/// Cross-process file lock preventing lost updates during concurrent process writes
struct FileLock {
    lock_path: PathBuf,
}

impl FileLock {
    fn acquire(base_path: &Path, timeout: std::time::Duration) -> Result<Self> {
        let lock_path = base_path.with_extension("lock");
        let start = std::time::Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(Self { lock_path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if start.elapsed() >= timeout {
                        // Stale lock recovery: if lock file older than 10 seconds, clear it
                        if let Ok(meta) = fs::metadata(&lock_path) {
                            if let Ok(modified) = meta.modified() {
                                if modified.elapsed().unwrap_or_default()
                                    > std::time::Duration::from_secs(10)
                                {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                        anyhow::bail!(
                            "Timeout waiting for cross-process file lock on {:?}",
                            lock_path
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => anyhow::bail!("Failed to acquire cross-process file lock: {}", e),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

impl SdsRegistry {
    pub fn load_default() -> Result<Self> {
        let path = Path::new("sds_registry.json").to_path_buf();
        Self::load_from_path(path)
    }

    pub fn load_from_path(file_path: PathBuf) -> Result<Self> {
        let mut entries = HashMap::new();
        let mut domain_to_id = HashMap::new();

        if file_path.exists() {
            let data = fs::read_to_string(&file_path)?;
            if let Ok(loaded) = serde_json::from_str::<Vec<RegistryEntry>>(&data) {
                for entry in loaded {
                    domain_to_id.insert(entry.canonical_domain.clone(), entry.raw_id.clone());
                    entries.insert(entry.raw_id.clone(), entry);
                }
            }
        }

        Ok(Self {
            file_path,
            entries,
            domain_to_id,
        })
    }

    pub fn save(&self) -> Result<()> {
        let list: Vec<&RegistryEntry> = self.entries.values().collect();
        let json = serde_json::to_string_pretty(&list)?;
        // Atomic save: write to temporary file first, then atomic rename
        let tmp_path = self.file_path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &self.file_path)?;
        Ok(())
    }

    pub fn reload(&mut self) -> Result<()> {
        if self.file_path.exists() {
            let data = fs::read_to_string(&self.file_path)?;
            if let Ok(loaded) = serde_json::from_str::<Vec<RegistryEntry>>(&data) {
                self.entries.clear();
                self.domain_to_id.clear();
                for entry in loaded {
                    self.domain_to_id
                        .insert(entry.canonical_domain.clone(), entry.raw_id.clone());
                    self.entries.insert(entry.raw_id.clone(), entry);
                }
            }
        }
        Ok(())
    }

    pub fn register_domain(
        &mut self,
        input_domain: &str,
        dns: Option<DnsSnapshot>,
    ) -> Result<RegistryEntry> {
        // 1. Acquire cross-process file lock to prevent lost updates across concurrent CLI processes
        let _lock = FileLock::acquire(&self.file_path, std::time::Duration::from_secs(5))?;
        let canonical = crate::canonical::normalize_domain(input_domain)?;
        let _ = self.reload(); // Refresh from disk inside lock to synchronize concurrent processes

        // 1. If already registered, return existing entry (ID NEVER changes!)
        if let Some(existing) = self.find_by_domain(&canonical) {
            let mut updated = existing.clone();
            if let Some(new_dns) = dns {
                updated.cached_dns = Some(new_dns);
                updated.updated_at = Utc::now();
                self.entries.insert(updated.raw_id.clone(), updated.clone());
                self.save()?;
            }
            return Ok(updated);
        }

        // 2. Expandable tiered search:
        // Tier 1: 8 payload chars = 10 chars total (1.1 Trillion capacity)
        // Tier 2: 10 payload chars = 12 chars total (1.12 Quadrillion capacity)
        // Tier 3: 12 payload chars = 14 chars total (1.15 Quintillion capacity)
        // Tier 4: 16 payload chars = 18 chars total (Enterprise scale)
        for payload_len in [8, 10, 12, 16] {
            for salt in 0..64 {
                let candidate =
                    crate::id::generate_domain_id_tiered(&canonical, salt, payload_len)?;
                if !self.entries.contains_key(&candidate.raw_id) {
                    return self.register(&candidate, dns);
                }
            }
        }

        anyhow::bail!("Exceeded maximum search tiers for unique domain ID");
    }

    pub fn register(
        &mut self,
        res: &DomainIdResult,
        dns: Option<DnsSnapshot>,
    ) -> Result<RegistryEntry> {
        let now = Utc::now();
        let entry = RegistryEntry {
            domain_id: res.formatted_id.clone(),
            raw_id: res.raw_id.clone(),
            canonical_domain: res.canonical_domain.clone(),
            checksum: res.checksum.clone(),
            created_at: now,
            updated_at: now,
            status: "active".to_string(),
            cached_dns: dns,
        };

        self.domain_to_id
            .insert(res.canonical_domain.clone(), res.raw_id.clone());
        self.entries.insert(res.raw_id.clone(), entry.clone());
        self.save()?;

        Ok(entry)
    }

    pub fn find_by_code(&self, code: &str) -> Option<&RegistryEntry> {
        let clean: String = code
            .chars()
            .filter(|c| !matches!(*c, '-' | '_' | '%' | '$' | '#' | '@' | ' '))
            .collect();
        let upper = clean.to_ascii_uppercase();
        self.entries.get(&upper)
    }

    pub fn find_by_domain(&self, domain: &str) -> Option<&RegistryEntry> {
        let lower = domain.trim().to_lowercase();
        if let Some(raw_id) = self.domain_to_id.get(&lower) {
            self.entries.get(raw_id)
        } else {
            None
        }
    }

    pub fn list_all(&self) -> Vec<&RegistryEntry> {
        let mut list: Vec<&RegistryEntry> = self.entries.values().collect();
        list.sort_by_key(|b| std::cmp::Reverse(&b.created_at));
        list
    }
}
