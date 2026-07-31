//! Unit tests for GlobalFpStore and cross-scan merge functionality

use crate::common::create_test_finding;
use baco::findings::FindingsMerger;
use baco::root_cause_dedup::GlobalFpStore;

#[test]
fn test_global_fp_store_load_missing_file() {
    use crate::common::create_temp_scan_dir;
    let temp_dir = create_temp_scan_dir();
    let missing_path = temp_dir.path().join("nonexistent.json");

    let store = GlobalFpStore::load(&missing_path);

    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn test_global_fp_store_mark_and_check() {
    use crate::common::create_temp_scan_dir;
    let temp_dir = create_temp_scan_dir();
    let fp_path = temp_dir.path().join("fp_store.json");

    let mut store = GlobalFpStore::with_path(&fp_path);
    let test_id = "test-root-cause-id-123";

    store.mark_false_positive(test_id);

    assert!(store.is_false_positive(test_id));
    assert_eq!(store.len(), 1);
}

#[test]
fn test_global_fp_store_remove() {
    use crate::common::create_temp_scan_dir;
    let temp_dir = create_temp_scan_dir();
    let fp_path = temp_dir.path().join("fp_store.json");

    let mut store = GlobalFpStore::with_path(&fp_path);
    let test_id = "test-root-cause-id-456";

    store.mark_false_positive(test_id);
    assert!(store.is_false_positive(test_id));

    store.remove(test_id);
    assert!(!store.is_false_positive(test_id));
    assert_eq!(store.len(), 0);
}

#[test]
fn test_global_fp_store_save_and_reload() {
    use crate::common::create_temp_scan_dir;
    let temp_dir = create_temp_scan_dir();
    let fp_path = temp_dir.path().join("fp_store.json");

    // Create and populate store
    {
        let mut store = GlobalFpStore::with_path(&fp_path);
        store.mark_false_positive("id-1");
        store.mark_false_positive("id-2");
        store.mark_false_positive("id-3");

        // Explicit save
        store.save().unwrap();
    }

    // Reload from disk
    let reloaded = GlobalFpStore::load(&fp_path);

    assert_eq!(reloaded.len(), 3);
    assert!(reloaded.is_false_positive("id-1"));
    assert!(reloaded.is_false_positive("id-2"));
    assert!(reloaded.is_false_positive("id-3"));
    assert!(!reloaded.is_false_positive("nonexistent"));
}

#[test]
fn test_merge_scans_deduplicates() {
    let scan1 = vec![
        create_test_finding("f1", "SQL Injection", "src/db.rs", 42),
        create_test_finding("f2", "XSS", "src/api.rs", 100),
    ];

    let scan2 = vec![
        create_test_finding("f1", "SQL Injection", "src/db.rs", 42), // Duplicate
        create_test_finding("f3", "CSRF", "src/auth.rs", 200),
    ];

    let scan3 = vec![
        create_test_finding("f2", "XSS", "src/api.rs", 100), // Duplicate
        create_test_finding("f4", "Path Traversal", "src/fs.rs", 50),
    ];

    let merged = FindingsMerger::merge_scans(vec![scan1, scan2, scan3]);

    // Should have 4 unique findings (f1, f2, f3, f4)
    assert_eq!(merged.len(), 4);

    // Verify all unique IDs are present
    let ids: Vec<String> = merged.iter().map(|f| f.id.clone()).collect();
    assert!(ids.contains(&"f1".to_string()));
    assert!(ids.contains(&"f2".to_string()));
    assert!(ids.contains(&"f3".to_string()));
    assert!(ids.contains(&"f4".to_string()));
}

#[test]
fn test_merge_scans_empty_scans() {
    let merged = FindingsMerger::merge_scans(vec![
        vec![],
        vec![create_test_finding("f1", "Test", "src/test.rs", 1)],
        vec![],
    ]);

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].id, "f1");
}

#[test]
fn test_merge_scans_all_duplicates() {
    let scan1 = vec![
        create_test_finding("f1", "SQL Injection", "src/db.rs", 42),
        create_test_finding("f2", "XSS", "src/api.rs", 100),
    ];

    let scan2 = vec![
        create_test_finding("f1", "SQL Injection", "src/db.rs", 42),
        create_test_finding("f2", "XSS", "src/api.rs", 100),
    ];

    let merged = FindingsMerger::merge_scans(vec![scan1, scan2]);

    assert_eq!(merged.len(), 2);
}
