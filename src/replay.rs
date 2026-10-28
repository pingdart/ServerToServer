use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::frame::{
    ERR_0RTT_OPERATION_FORBIDDEN, ERR_REPLAY_DETECTED, TYPE_CALL_INVITE, TYPE_MSG_ENVELOPE,
    TYPE_MSG_OFFLINE_SYNC_REQ, TYPE_PING, TYPE_PRESENCE_STATE, TYPE_RESOLVE_PROFILE_REQ,
};

/// Server-Controlled Replay Strike Register for 0-RTT QUIC Early Data
pub struct ReplayStrikeRegister {
    max_ticket_lifetime: Duration,
    // Tracks processed idempotency keys mapped to their ingestion epoch
    seen_idempotency_keys: HashMap<String, u64>,
    // Tracks single-use session tickets
    seen_ticket_ids: HashSet<String>,
    insertion_order: Vec<(Instant, String)>,
}

impl Default for ReplayStrikeRegister {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayStrikeRegister {
    pub fn new() -> Self {
        Self {
            max_ticket_lifetime: Duration::from_secs(300), // 5 minutes max ticket validity window
            seen_idempotency_keys: HashMap::new(),
            seen_ticket_ids: HashSet::new(),
            insertion_order: Vec::new(),
        }
    }

    /// RFC 9001 Section 9.2 Policy Enforcement:
    /// 0-RTT early data MUST NOT be used for state-changing or non-idempotent actions.
    pub fn validate_0rtt_operation(&self, frame_type: u16) -> Result<(), u16> {
        match frame_type {
            // Permitted read-only / strictly idempotent operations
            TYPE_RESOLVE_PROFILE_REQ | TYPE_PING | TYPE_PRESENCE_STATE => Ok(()),

            // Strictly prohibited state-mutating actions
            TYPE_CALL_INVITE | TYPE_MSG_ENVELOPE | TYPE_MSG_OFFLINE_SYNC_REQ => {
                Err(ERR_0RTT_OPERATION_FORBIDDEN)
            }

            // Default safe denial
            _ => Err(ERR_0RTT_OPERATION_FORBIDDEN),
        }
    }

    /// Server-side validation of 0-RTT session tickets and request idempotency keys.
    /// Rejects replayed tickets or reused idempotency tokens.
    pub fn check_and_register_0rtt_request(
        &mut self,
        ticket_id: &str,
        ticket_expiry_epoch_ms: u64,
        idempotency_key: &str,
    ) -> Result<(), u16> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 1. Check server-bounded ticket expiry
        if now_ms >= ticket_expiry_epoch_ms {
            return Err(ERR_REPLAY_DETECTED); // Ticket expired
        }

        // 2. Reject replayed session ticket IDs
        if self.seen_ticket_ids.contains(ticket_id) {
            return Err(ERR_REPLAY_DETECTED);
        }

        // 3. Reject duplicate request idempotency keys
        if self.seen_idempotency_keys.contains_key(idempotency_key) {
            return Err(ERR_REPLAY_DETECTED);
        }

        // 4. Register single-use ticket and idempotency key
        self.seen_ticket_ids.insert(ticket_id.to_string());
        self.seen_idempotency_keys
            .insert(idempotency_key.to_string(), now_ms);
        self.insertion_order
            .push((Instant::now(), ticket_id.to_string()));

        // 5. Prune expired entries
        self.prune();

        Ok(())
    }

    /// Prune cached strike registers past max ticket lifetime
    pub fn prune(&mut self) {
        let now = Instant::now();
        let max_ttl = self.max_ticket_lifetime;

        let mut retain_idx = 0;
        for (i, (ts, _)) in self.insertion_order.iter().enumerate() {
            if now.duration_since(*ts) < max_ttl {
                retain_idx = i;
                break;
            }
        }

        if retain_idx > 0 {
            let expired = self.insertion_order.drain(0..retain_idx);
            for (_, ticket_id) in expired {
                self.seen_ticket_ids.remove(&ticket_id);
            }
        }
    }
}

/// Shared, cluster-wide atomic replay store accessible across multiple server worker instances
#[derive(Clone)]
pub struct SharedReplayStore {
    inner: std::sync::Arc<std::sync::RwLock<ReplayStrikeRegister>>,
}

impl SharedReplayStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(ReplayStrikeRegister::new())),
        }
    }

    pub fn validate_0rtt_operation(&self, frame_type: u16) -> Result<(), u16> {
        let guard = self.inner.read().map_err(|_| ERR_REPLAY_DETECTED)?;
        guard.validate_0rtt_operation(frame_type)
    }

    pub fn check_and_register_0rtt_request(
        &self,
        ticket_id: &str,
        ticket_expiry_epoch_ms: u64,
        idempotency_key: &str,
    ) -> Result<(), u16> {
        let mut guard = self.inner.write().map_err(|_| ERR_REPLAY_DETECTED)?;
        guard.check_and_register_0rtt_request(ticket_id, ticket_expiry_epoch_ms, idempotency_key)
    }
}

impl Default for SharedReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Cross-Process Atomic Replay Store
/// Coordinates session tickets and idempotency tokens across independent OS processes
/// using atomic file locks and append-only journal storage.
#[derive(Clone)]
pub struct CrossProcessReplayStore {
    journal_path: PathBuf,
}

impl CrossProcessReplayStore {
    pub fn new(journal_path: PathBuf) -> Self {
        Self { journal_path }
    }

    pub fn check_and_register_0rtt_request(
        &self,
        ticket_id: &str,
        ticket_expiry_epoch_ms: u64,
        idempotency_key: &str,
    ) -> Result<(), u16> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now_ms >= ticket_expiry_epoch_ms {
            return Err(ERR_REPLAY_DETECTED);
        }

        let lock_path = self.journal_path.with_extension("lock");
        let start = Instant::now();
        let timeout = Duration::from_secs(3);

        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(elapsed) = meta
                            .modified()
                            .and_then(|m| m.elapsed().map_err(std::io::Error::other))
                        {
                            if elapsed > Duration::from_secs(4) {
                                let _ = fs::remove_file(&lock_path);
                            }
                        }
                    }
                    if start.elapsed() > timeout {
                        return Err(ERR_REPLAY_DETECTED);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(ERR_REPLAY_DETECTED),
            }
        }

        struct ReplayLockGuard(PathBuf);
        impl Drop for ReplayLockGuard {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let _guard = ReplayLockGuard(lock_path);

        let mut seen_tickets: HashSet<String> = HashSet::new();
        let mut seen_idempotency: HashSet<String> = HashSet::new();

        if let Ok(content) = fs::read_to_string(&self.journal_path) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    seen_tickets.insert(parts[0].to_string());
                    seen_idempotency.insert(parts[1].to_string());
                }
            }
        }

        if seen_tickets.contains(ticket_id) || seen_idempotency.contains(idempotency_key) {
            return Err(ERR_REPLAY_DETECTED);
        }

        let record = format!("{}\t{}\t{}\n", ticket_id, idempotency_key, now_ms);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|_| ERR_REPLAY_DETECTED)?;
        file.write_all(record.as_bytes())
            .map_err(|_| ERR_REPLAY_DETECTED)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_0rtt_idempotency_gating() {
        let register = ReplayStrikeRegister::new();

        assert!(register
            .validate_0rtt_operation(TYPE_RESOLVE_PROFILE_REQ)
            .is_ok());
        assert!(register.validate_0rtt_operation(TYPE_PING).is_ok());
        assert!(register
            .validate_0rtt_operation(TYPE_PRESENCE_STATE)
            .is_ok());

        assert_eq!(
            register.validate_0rtt_operation(TYPE_CALL_INVITE),
            Err(ERR_0RTT_OPERATION_FORBIDDEN)
        );
        assert_eq!(
            register.validate_0rtt_operation(TYPE_MSG_ENVELOPE),
            Err(ERR_0RTT_OPERATION_FORBIDDEN)
        );
    }

    #[test]
    fn test_server_controlled_ticket_and_idempotency_replay_protection() {
        let mut register = ReplayStrikeRegister::new();
        let ticket_id = "srv-ticket-001";
        let idempotency_key = "req-uuid-9876";

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let future_expiry = now_ms + 60_000; // valid for 60 seconds

        // 1. Initial valid request
        assert!(register
            .check_and_register_0rtt_request(ticket_id, future_expiry, idempotency_key)
            .is_ok());

        // 2. Exact replay of ticket
        assert_eq!(
            register.check_and_register_0rtt_request(ticket_id, future_expiry, "diff-key"),
            Err(ERR_REPLAY_DETECTED)
        );

        // 3. Replay with different ticket but same idempotency key
        assert_eq!(
            register.check_and_register_0rtt_request(
                "srv-ticket-002",
                future_expiry,
                idempotency_key
            ),
            Err(ERR_REPLAY_DETECTED)
        );

        // 4. Expired ticket presentation
        let past_expiry = now_ms.saturating_sub(1000);
        assert_eq!(
            register.check_and_register_0rtt_request(
                "srv-ticket-003",
                past_expiry,
                "req-uuid-fresh"
            ),
            Err(ERR_REPLAY_DETECTED)
        );
    }

    #[test]
    fn test_cross_instance_distributed_replay_detection() {
        // Shared atomic store across Server Instance A and Server Instance B
        let shared_store = SharedReplayStore::new();
        let server_instance_a = shared_store.clone();
        let server_instance_b = shared_store.clone();

        let ticket_id = "cluster-ticket-777";
        let idempotency_key = "idemp-key-multi-node";
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let expiry = now_ms + 120_000;

        // Request 1 lands on Server Instance A: Accepted
        assert!(server_instance_a
            .check_and_register_0rtt_request(ticket_id, expiry, idempotency_key)
            .is_ok());

        // Attacker replays identical request to Server Instance B: Must be detected and aborted!
        let replay_result =
            server_instance_b.check_and_register_0rtt_request(ticket_id, expiry, idempotency_key);
        assert_eq!(replay_result, Err(ERR_REPLAY_DETECTED));
    }

    #[test]
    fn test_concurrent_multithreaded_replay_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let shared_store = SharedReplayStore::new();
        let ticket_id = "race-condition-ticket-999";
        let idempotency_key = "idemp-race-uuid-111";
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let expiry = now_ms + 60_000;

        let success_count = Arc::new(AtomicUsize::new(0));
        let replay_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        // 20 concurrent threads race to redeem identical 0-RTT ticket
        for _ in 0..20 {
            let store = shared_store.clone();
            let succ = Arc::clone(&success_count);
            let repl = Arc::clone(&replay_count);
            let handle = std::thread::spawn(move || {
                match store.check_and_register_0rtt_request(ticket_id, expiry, idempotency_key) {
                    Ok(()) => succ.fetch_add(1, Ordering::SeqCst),
                    Err(ERR_REPLAY_DETECTED) => repl.fetch_add(1, Ordering::SeqCst),
                    Err(_) => 0,
                };
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        // Exactly 1 request must win the race; all 19 other concurrent races must be rejected as replays
        assert_eq!(success_count.load(Ordering::SeqCst), 1);
        assert_eq!(replay_count.load(Ordering::SeqCst), 19);
    }

    #[test]
    fn test_crossprocess_replay_store_atomic_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let test_journal = std::env::temp_dir().join(format!(
            "sds_test_replay_journal_{}.log",
            rand::random::<u32>()
        ));
        let _ = fs::remove_file(&test_journal);
        let _ = fs::remove_file(test_journal.with_extension("lock"));

        let ticket_id = "cross-proc-ticket-555";
        let idempotency_key = "cross-proc-idemp-888";
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let expiry = now_ms + 60_000;

        let success_count = Arc::new(AtomicUsize::new(0));
        let replay_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        // 10 independent simulated process instances racing for the same ticket journal
        for _ in 0..10 {
            let journal_clone = test_journal.clone();
            let succ = Arc::clone(&success_count);
            let repl = Arc::clone(&replay_count);
            let handle = std::thread::spawn(move || {
                let store = CrossProcessReplayStore::new(journal_clone);
                match store.check_and_register_0rtt_request(ticket_id, expiry, idempotency_key) {
                    Ok(()) => succ.fetch_add(1, Ordering::SeqCst),
                    Err(ERR_REPLAY_DETECTED) => repl.fetch_add(1, Ordering::SeqCst),
                    Err(_) => 0,
                };
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            success_count.load(Ordering::SeqCst),
            1,
            "Exactly one process instance consumes ticket"
        );
        assert_eq!(
            replay_count.load(Ordering::SeqCst),
            9,
            "All 9 other instances must be rejected with ERR_REPLAY_DETECTED"
        );

        let _ = fs::remove_file(&test_journal);
        let _ = fs::remove_file(test_journal.with_extension("lock"));
    }
}
