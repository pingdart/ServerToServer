use sds_core::checksum::verify_checksum;
use sds_core::dns::DnsSnapshot;
use sds_core::id::{generate_domain_id, generate_domain_id_tiered, validate_domain_id};
use sds_core::storage::SdsRegistry;
use std::sync::{Arc, Mutex};
use std::thread;

/// VERIFICATION 1: All ID generation and tiered expansion tests pass
#[test]
fn test_id_generation_and_tiered_expansion() {
    let res10 = generate_domain_id("pingdart.com").unwrap();
    assert_eq!(res10.raw_id.len(), 10);
    assert_eq!(res10.raw_id, "5QJCXPH2HN");
    assert!(validate_domain_id(&res10.raw_id).unwrap());

    // Expandable tier: 12 characters (10 payload + 2 checksum)
    let res12 = generate_domain_id_tiered("pingdart.com", 0, 10).unwrap();
    assert_eq!(res12.raw_id.len(), 12);
    assert!(verify_checksum(&res12.raw_id).unwrap());

    // Expandable tier: 14 characters (12 payload + 2 checksum)
    let res14 = generate_domain_id_tiered("pingdart.com", 0, 12).unwrap();
    assert_eq!(res14.raw_id.len(), 14);
    assert!(verify_checksum(&res14.raw_id).unwrap());
}

/// VERIFICATION 1B: Exact parity against frozen cross-language test_vectors.json
#[test]
fn test_frozen_cross_language_test_vectors() {
    let vector_data =
        std::fs::read_to_string("test_vectors.json").expect("test_vectors.json must be present");
    let vectors: serde_json::Value = serde_json::from_str(&vector_data).unwrap();

    for v in vectors.as_array().unwrap() {
        let input_domain = v["input_domain"].as_str().unwrap();
        let salt = v["salt"].as_u64().unwrap() as u32;
        let payload_len = v["payload_length"].as_u64().unwrap() as usize;
        let exp_raw = v["raw_id"].as_str().unwrap();
        let exp_payload = v["payload"].as_str().unwrap();
        let exp_checksum = v["checksum"].as_str().unwrap();

        let res = generate_domain_id_tiered(input_domain, salt, payload_len).unwrap();
        assert_eq!(
            res.payload, exp_payload,
            "Payload mismatch for {}",
            input_domain
        );
        assert_eq!(
            res.checksum, exp_checksum,
            "Checksum mismatch for {}",
            input_domain
        );
        assert_eq!(res.raw_id, exp_raw, "Raw ID mismatch for {}", input_domain);
        assert!(
            verify_checksum(&res.raw_id).unwrap(),
            "Checksum failed for {}",
            exp_raw
        );
    }
}

/// VERIFICATION 2: Concurrent registrations cannot assign the same ID to different domains
#[test]
fn test_concurrent_registration_safety() {
    let tmp_dir = std::env::temp_dir();
    let test_db_path = tmp_dir.join(format!(
        "sds_concurrent_test_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    // Clean start
    let _ = std::fs::remove_file(&test_db_path);

    let registry = Arc::new(Mutex::new(
        SdsRegistry::load_from_path(test_db_path.clone()).unwrap(),
    ));

    let mut handles = Vec::new();
    let domain_count = 50;

    for i in 0..domain_count {
        let reg_clone = Arc::clone(&registry);
        let handle = thread::spawn(move || {
            let domain = format!("test-server-{}.ucall.io", i);
            let mut reg = reg_clone.lock().unwrap();
            reg.register_domain(&domain, None).unwrap()
        });
        handles.push(handle);
    }

    let mut issued_ids = std::collections::HashSet::new();
    let mut issued_domains = std::collections::HashSet::new();

    for handle in handles {
        let entry = handle.join().unwrap();
        // Uniqueness check: No two different domains can ever share an ID
        assert!(
            issued_ids.insert(entry.raw_id.clone()),
            "DUPLICATE ID DETECTED: {}",
            entry.raw_id
        );
        assert!(issued_domains.insert(entry.canonical_domain.clone()));
    }

    assert_eq!(issued_ids.len(), domain_count);

    // Clean up
    let _ = std::fs::remove_file(&test_db_path);
}

/// VERIFICATION 3: Offline decoding works from locally available mapping without network
#[test]
fn test_offline_decoding_without_network() {
    let tmp_dir = std::env::temp_dir();
    let test_db_path = tmp_dir.join(format!(
        "sds_offline_test_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let mut reg = SdsRegistry::load_from_path(test_db_path.clone()).unwrap();

    // Register domain offline (None for DNS snapshot)
    let entry = reg
        .register_domain("offline-node.example.org", None)
        .unwrap();
    let assigned_id = entry.raw_id.clone();

    // Simulate complete application restart & reload from disk
    drop(reg);
    let reloaded_reg = SdsRegistry::load_from_path(test_db_path.clone()).unwrap();

    // Decode completely offline:
    // 1. Checksum validation (0ms, 0 network)
    assert!(validate_domain_id(&assigned_id).unwrap());

    // 2. Local database resolution
    let resolved = reloaded_reg
        .find_by_code(&assigned_id)
        .expect("Should find domain offline");
    assert_eq!(resolved.canonical_domain, "offline-node.example.org");
    assert_eq!(resolved.raw_id, assigned_id);

    // Clean up
    let _ = std::fs::remove_file(&test_db_path);
}

/// VERIFICATION 4: IDs remain 100% stable across restarts and server IP changes
#[test]
fn test_id_stability_across_restarts_and_ip_changes() {
    let tmp_dir = std::env::temp_dir();
    let test_db_path = tmp_dir.join(format!(
        "sds_stability_test_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let mut reg = SdsRegistry::load_from_path(test_db_path.clone()).unwrap();

    // Initial registration with IP 1.2.3.4
    let mut initial_dns = DnsSnapshot::default();
    initial_dns.a_records.push("1.2.3.4".to_string());
    let initial_entry = reg
        .register_domain("stable-service.pingdart.net", Some(initial_dns))
        .unwrap();
    let original_id = initial_entry.raw_id.clone();

    // Application restart: drop and reload from disk
    drop(reg);
    let mut reloaded_reg = SdsRegistry::load_from_path(test_db_path.clone()).unwrap();

    // Domain IP changes to 5.6.7.8
    let mut changed_dns = DnsSnapshot::default();
    changed_dns.a_records.push("5.6.7.8".to_string());
    let re_registered = reloaded_reg
        .register_domain("stable-service.pingdart.net", Some(changed_dns))
        .unwrap();

    // THE CORE INVARIANT:
    // 1. ID must be identical before and after
    assert_eq!(re_registered.raw_id, original_id);
    // 2. DNS snapshot is updated
    assert_eq!(re_registered.cached_dns.unwrap().a_records[0], "5.6.7.8");
    // 3. Resolving old ID still yields the exact domain
    let resolved = reloaded_reg.find_by_code(&original_id).unwrap();
    assert_eq!(resolved.canonical_domain, "stable-service.pingdart.net");

    // Clean up
    let _ = std::fs::remove_file(&test_db_path);
}

/// VERIFICATION 5: Cross-Process File Lock Concurrency (simulates independent OS processes)
#[test]
fn test_crossprocess_file_lock_concurrent_registrations() {
    let tmp_dir = std::env::temp_dir();
    let test_db_path = tmp_dir.join(format!(
        "sds_crossprocess_test_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let _ = std::fs::remove_file(&test_db_path);
    let _ = std::fs::remove_file(test_db_path.with_extension("lock"));

    // 15 simulated independent processes (each with distinct SdsRegistry instances pointing to same file)
    let process_count = 15;
    let mut handles = Vec::new();

    for i in 0..process_count {
        let path_clone = test_db_path.clone();
        let handle = thread::spawn(move || {
            let mut reg = SdsRegistry::load_from_path(path_clone).unwrap();
            let domain = format!("isolated-process-{}.pingdart.com", i);
            reg.register_domain(&domain, None).unwrap()
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    // Load final registry from disk: all 15 independent process writes must be present with ZERO lost updates
    let final_reg = SdsRegistry::load_from_path(test_db_path.clone()).unwrap();
    let all_entries = final_reg.list_all();
    assert_eq!(all_entries.len(), process_count);

    for i in 0..process_count {
        let domain = format!("isolated-process-{}.pingdart.com", i);
        assert!(final_reg.find_by_domain(&domain).is_some());
    }

    // Clean up
    let _ = std::fs::remove_file(&test_db_path);
    let _ = std::fs::remove_file(test_db_path.with_extension("lock"));
}
