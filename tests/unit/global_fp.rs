//! Unit tests for GlobalFpStore and cross-scan merge functionality

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
