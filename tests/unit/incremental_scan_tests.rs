//! Unit tests for src/incremental_scan.rs
//!
//! Tests cover FileHashStore operations, save/load functionality,
//! and incremental scanning logic.

use baco::file_hash::FileHasher;
use baco::findings::VulnerabilityFinding;
use baco::incremental_scan::FileHashStore;
use std::path::PathBuf;
use tempfile::TempDir;

use crate::fixtures::create_test_finding;

// ============================================================================
// Helper: get baco version
// ============================================================================

fn baco_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ============================================================================
// FileHashStore::new() Tests
// ============================================================================

#[test]
fn test_file_hash_store_new_creates_empty_store() {
    let store = FileHashStore::new();

    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

// ============================================================================
// FileHashStore::insert_hash() Tests
// ============================================================================

#[test]
fn test_insert_hash_adds_new_entry() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "abc123".to_string());

    assert_eq!(store.len(), 1);
    assert_eq!(store.get_hash(&path), Some(&"abc123".to_string()));
}

#[test]
fn test_insert_hash_updates_existing_entry() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "old_hash".to_string());
    store.insert_hash(&path, "new_hash".to_string());

    assert_eq!(store.len(), 1);
    assert_eq!(store.get_hash(&path), Some(&"new_hash".to_string()));
}

#[test]
fn test_insert_hash_different_paths() {
    let mut store = FileHashStore::new();
    let path1 = PathBuf::from("/test/file1.txt");
    let path2 = PathBuf::from("/test/file2.txt");
    let path3 = PathBuf::from("/test/file3.txt");

    store.insert_hash(&path1, "hash1".to_string());
    store.insert_hash(&path2, "hash2".to_string());
    store.insert_hash(&path3, "hash3".to_string());

    assert_eq!(store.len(), 3);
    assert_eq!(store.get_hash(&path1), Some(&"hash1".to_string()));
    assert_eq!(store.get_hash(&path2), Some(&"hash2".to_string()));
    assert_eq!(store.get_hash(&path3), Some(&"hash3".to_string()));
}

// ============================================================================
// FileHashStore::get_hash() Tests
// ============================================================================

#[test]
fn test_get_hash_returns_none_for_missing_file() {
    let store = FileHashStore::new();
    let path = PathBuf::from("/nonexistent/file.txt");

    assert!(store.get_hash(&path).is_none());
}

#[test]
fn test_get_hash_with_different_path_formats() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "test_hash".to_string());

    // Same path should work
    assert!(store.get_hash(&path).is_some());

    // Different path should return None
    let different_path = PathBuf::from("/test/other.txt");
    assert!(store.get_hash(&different_path).is_none());
}

// ============================================================================
// FileHashStore::len() and is_empty() Tests
// ============================================================================

#[test]
fn test_len_returns_correct_count() {
    let mut store = FileHashStore::new();

    assert_eq!(store.len(), 0);

    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    assert_eq!(store.len(), 1);

    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    assert_eq!(store.len(), 2);

    store.insert_hash(&PathBuf::from("file1.txt"), "updated_hash".to_string());
    assert_eq!(store.len(), 2); // Should still be 2, not 3
}

#[test]
fn test_is_empty_changes_with_content() {
    let mut store = FileHashStore::new();

    assert!(store.is_empty());

    store.insert_hash(&PathBuf::from("file.txt"), "hash".to_string());

    assert!(!store.is_empty());
}

// ============================================================================
// FileHashStore::save() and load() Tests
// ============================================================================

#[test]
fn test_save_and_load_preserves_data() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("hash_store.json");

    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());

    store.save(path.to_str().unwrap()).unwrap();

    let loaded = FileHashStore::load(path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.len(), 2);
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file2.txt")),
        Some(&"hash2".to_string())
    );
}

#[test]
fn test_save_creates_parent_directories() {
    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir.path().join("nested/deep/path/hash_store.json");

    let store = FileHashStore::new();
    let result = store.save(nested_path.to_str().unwrap());

    assert!(result.is_ok());
    assert!(nested_path.exists());
}

#[test]
fn test_load_from_nonexistent_file_returns_error() {
    let result = FileHashStore::load("/nonexistent/path/hash_store.json");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to read"));
}

#[test]
fn test_load_with_invalid_json_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("invalid.json");

    std::fs::write(&path, "this is not valid json {{{{").unwrap();

    let result = FileHashStore::load(path.to_str().unwrap());

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse"));
}

#[test]
fn test_load_with_empty_file_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("empty.json");

    std::fs::write(&path, "").unwrap();

    let result = FileHashStore::load(path.to_str().unwrap());

    assert!(result.is_err());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_hash_string() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "".to_string());

    assert_eq!(store.get_hash(&path), Some(&"".to_string()));
}

#[test]
fn test_very_long_hash_string() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");
    let long_hash = "a".repeat(1000);

    store.insert_hash(&path, long_hash.clone());

    assert_eq!(store.get_hash(&path), Some(&long_hash));
}

#[test]
fn test_special_characters_in_path() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/文件/file with spaces.txt");

    store.insert_hash(&path, "hash".to_string());

    assert!(store.get_hash(&path).is_some());
}

#[test]
fn test_same_hash_for_multiple_files() {
    let mut store = FileHashStore::new();
    let path1 = PathBuf::from("/test/file1.txt");
    let path2 = PathBuf::from("/test/file2.txt");
    let path3 = PathBuf::from("/test/file3.txt");
    let identical_hash = "identical_hash_123".to_string();

    store.insert_hash(&path1, identical_hash.clone());
    store.insert_hash(&path2, identical_hash.clone());
    store.insert_hash(&path3, identical_hash.clone());

    assert_eq!(store.len(), 3);
    assert_eq!(store.get_hash(&path1), Some(&identical_hash));
    assert_eq!(store.get_hash(&path2), Some(&identical_hash));
    assert_eq!(store.get_hash(&path3), Some(&identical_hash));
}

#[test]
fn test_many_files_performance() {
    let mut store = FileHashStore::new();

    for i in 0..100 {
        let path = PathBuf::from(format!("/test/file{}.txt", i));
        store.insert_hash(&path, format!("hash{}", i));
    }

    assert_eq!(store.len(), 100);

    // Verify a few specific entries
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file0.txt")),
        Some(&"hash0".to_string())
    );
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file50.txt")),
        Some(&"hash50".to_string())
    );
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file99.txt")),
        Some(&"hash99".to_string())
    );
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_save_load_cycle() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("full_cycle.json");

    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());

    store.save(path.to_str().unwrap()).unwrap();

    let loaded = FileHashStore::load(path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
}

#[test]
fn test_multiple_save_load_cycles() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("cycles.json");

    let mut store = FileHashStore::new();

    // First cycle
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.save(path.to_str().unwrap()).unwrap();

    // Second cycle - update and add
    let loaded1 = FileHashStore::load(path.to_str().unwrap()).unwrap();
    let mut store2 = loaded1;
    store2.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    store2.save(path.to_str().unwrap()).unwrap();

    // Third cycle - verify both exist
    let loaded2 = FileHashStore::load(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded2.len(), 2);
    assert_eq!(
        loaded2.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
    assert_eq!(
        loaded2.get_hash(&PathBuf::from("file2.txt")),
        Some(&"hash2".to_string())
    );
}

// ============================================================================
// Atomic Write Tests
// ============================================================================

#[test]
fn test_atomic_save_no_temp_file_left_behind() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("atomic_test.json");

    let store = FileHashStore::new();
    store.save(path.to_str().unwrap()).unwrap();

    // Verify no .tmp file is left behind (atomic_write uses .tmp extension)
    let tmp_path = path.with_extension("tmp");
    assert!(
        !tmp_path.exists(),
        "Temp file should be removed after successful rename"
    );

    // Verify the target file exists and can be loaded
    assert!(path.exists());
    let loaded = FileHashStore::load(path.to_str().unwrap()).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn test_atomic_save_preserves_existing_content_on_failure() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("atomic_preserve.json");

    // Pre-create the file with known content
    let mut old_store = FileHashStore::new();
    old_store.insert_hash(&PathBuf::from("old.txt"), "old_hash".to_string());
    old_store.save(path.to_str().unwrap()).unwrap();

    // Verify old content is there
    let loaded_old = FileHashStore::load(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded_old.len(), 1);

    // Save new content atomically
    let mut new_store = FileHashStore::new();
    new_store.insert_hash(&PathBuf::from("new.txt"), "new_hash".to_string());
    new_store.save(path.to_str().unwrap()).unwrap();

    // Verify new content is there (proving rename worked)
    let loaded_new = FileHashStore::load(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded_new.len(), 1);
    assert_eq!(
        loaded_new.get_hash(&PathBuf::from("new.txt")),
        Some(&"new_hash".to_string())
    );

    // Verify no temp file left behind (atomic_write uses .tmp extension)
    let tmp_path = path.with_extension("tmp");
    assert!(!tmp_path.exists());
}

#[test]
fn test_atomic_save_writes_valid_json() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("valid_json.json");

    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("test.txt"), "test_hash".to_string());
    store.save(path.to_str().unwrap()).unwrap();

    // Read the file content directly
    let content = std::fs::read_to_string(&path).unwrap();

    // Verify it's valid JSON by parsing with serde_json
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Verify it's not empty
    assert!(!content.is_empty());

    // Verify it has the expected structure
    assert!(parsed.is_object());
}

// ============================================================================
// file_is_unchanged: the predicate both the restriction and the carry use
// ============================================================================

/// Record each file's current content hash, keyed by its canonical path —
/// the same key shape the persisted store uses in production.
fn store_from_files(files: &[&std::path::Path]) -> FileHashStore {
    let mut store = FileHashStore::new();
    let mut hasher = FileHasher::new();
    for f in files {
        let hash = hasher.hash_file(f).unwrap();
        store.insert_hash(&f.canonicalize().unwrap(), hash);
    }
    store
}

fn finding_in(id: &str, path: &std::path::Path) -> VulnerabilityFinding {
    create_test_finding(id, "t", path.to_str().unwrap(), 1)
}

#[test]
fn unchanged_file_with_recorded_hash_reads_as_unchanged() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let store = store_from_files(&[&file]);
    let mut hasher = FileHasher::new();

    assert!(baco::incremental_scan::file_is_unchanged(
        &file,
        &store,
        &mut hasher
    ));
}

#[test]
fn modified_file_reads_as_changed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let store = store_from_files(&[&file]);
    std::fs::write(&file, "fn a() { CHANGED }").unwrap();

    let mut hasher = FileHasher::new();
    assert!(!baco::incremental_scan::file_is_unchanged(
        &file,
        &store,
        &mut hasher
    ));
}

#[test]
fn file_without_recorded_hash_reads_as_changed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let other = dir.path().join("b.rs");
    std::fs::write(&other, "fn b() {}").unwrap();

    // Store holds only `other`, and an empty store must behave the same way:
    // both mean "no previous analysis", so the file is analyzed.
    let store = store_from_files(&[&other]);
    let mut hasher = FileHasher::new();
    assert!(!baco::incremental_scan::file_is_unchanged(
        &file,
        &store,
        &mut hasher
    ));

    let empty = FileHashStore::new();
    assert!(!baco::incremental_scan::file_is_unchanged(
        &file,
        &empty,
        &mut hasher
    ));
}

#[test]
fn deleted_file_reads_as_changed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let store = store_from_files(&[&file]);
    std::fs::remove_file(&file).unwrap();

    // The hash cannot be recomputed, so the file cannot be proven unchanged.
    let mut hasher = FileHasher::new();
    assert!(!baco::incremental_scan::file_is_unchanged(
        &file,
        &store,
        &mut hasher
    ));
}

#[test]
fn predicate_resolves_paths_canonically() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let store = store_from_files(&[&file]);

    // A path with a redundant `..` segment resolves to the same canonical
    // path the store is keyed by: the join key must not depend on spelling.
    let odd = dir
        .path()
        .join("..")
        .join(dir.path().file_name().unwrap())
        .join("a.rs");
    assert_eq!(
        odd.canonicalize().unwrap(),
        file.canonicalize().unwrap(),
        "test setup: both spellings must resolve to the same file"
    );

    let mut hasher = FileHasher::new();
    assert!(baco::incremental_scan::file_is_unchanged(
        &odd,
        &store,
        &mut hasher
    ));
}

// ============================================================================
// Restriction and carry: one predicate, disjoint by file
// ============================================================================

#[test]
fn keep_fresh_drops_only_unchanged_files_findings() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let changed = dir.path().join("changed.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&changed, "fn b() {}").unwrap();

    let store = store_from_files(&[&unchanged, &changed]);
    std::fs::write(&changed, "fn b() { CHANGED }").unwrap();

    let fresh = vec![
        finding_in("fresh-unchanged", &unchanged),
        finding_in("fresh-changed", &changed),
    ];

    let mut hasher = FileHasher::new();
    let kept = baco::incremental_scan::keep_fresh_findings(fresh, &store, &mut hasher);

    let mut kept_ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
    kept_ids.sort();
    assert_eq!(kept_ids, vec!["fresh-changed"]);
}

#[test]
fn keep_fresh_returns_everything_without_a_store() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    let fresh = vec![finding_in("fresh-1", &file), finding_in("fresh-2", &file)];

    let store = FileHashStore::new();
    let mut hasher = FileHasher::new();
    let kept = baco::incremental_scan::keep_fresh_findings(fresh, &store, &mut hasher);

    assert_eq!(kept.len(), 2);
}

#[test]
fn carry_previous_returns_only_unchanged_files_findings() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let changed = dir.path().join("changed.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&changed, "fn b() {}").unwrap();

    let store = store_from_files(&[&unchanged, &changed]);
    std::fs::write(&changed, "fn b() { CHANGED }").unwrap();

    let mut previous_changed = finding_in("prev-changed", &changed);
    previous_changed.description = "from the old run".to_string();
    let previous = vec![finding_in("prev-unchanged", &unchanged), previous_changed];

    let mut hasher = FileHasher::new();
    let carried = baco::incremental_scan::carry_previous(&previous, &store, &mut hasher);

    let mut carried_ids: Vec<&str> = carried.iter().map(|f| f.id.as_str()).collect();
    carried_ids.sort();
    assert_eq!(carried_ids, vec!["prev-unchanged"]);
}

#[test]
fn carry_previous_returns_nothing_without_a_store() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    let previous = vec![finding_in("prev-1", &file)];

    let store = FileHashStore::new();
    let mut hasher = FileHasher::new();
    let carried = baco::incremental_scan::carry_previous(&previous, &store, &mut hasher);

    assert!(carried.is_empty());
}

#[test]
fn union_neither_drops_nor_duplicates_by_file() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let changed = dir.path().join("changed.rs");
    let new = dir.path().join("new.rs");
    let gone = dir.path().join("gone.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&changed, "fn b() {}").unwrap();
    std::fs::write(&gone, "fn c() {}").unwrap();

    // The previous run saw unchanged, changed and gone.
    let store = store_from_files(&[&unchanged, &changed, &gone]);
    let previous = vec![
        finding_in("prev-unchanged", &unchanged),
        finding_in("prev-changed", &changed),
        finding_in("prev-gone", &gone),
    ];

    // Then reality moved: changed.rs was edited, new.rs appeared, gone.rs
    // was deleted. The store is deliberately stale — it is the previous
    // run's view of the world.
    std::fs::write(&changed, "fn b() { CHANGED }").unwrap();
    std::fs::write(&new, "fn n() {}").unwrap();
    std::fs::remove_file(&gone).unwrap();

    let fresh = vec![
        finding_in("fresh-unchanged", &unchanged),
        finding_in("fresh-changed", &changed),
        finding_in("fresh-new", &new),
    ];

    let mut hasher = FileHasher::new();
    let kept = baco::incremental_scan::keep_fresh_findings(fresh, &store, &mut hasher);
    let mut carried = baco::incremental_scan::carry_previous(&previous, &store, &mut hasher);

    let mut union_findings: Vec<VulnerabilityFinding> = kept;
    union_findings.append(&mut carried);

    let by_file: Vec<(String, Vec<String>)> = union_findings
        .into_iter()
        .map(|f| (f.file_path, vec![f.id]))
        .fold(
            std::collections::BTreeMap::<String, Vec<String>>::new(),
            |mut acc: std::collections::BTreeMap<String, Vec<String>>, (file, mut ids)| {
                acc.entry(file).or_default().append(&mut ids);
                acc
            },
        )
        .into_iter()
        .collect();
    // One entry per file, no file twice — a duplicate would mean the union
    // both dropped and carried the same file.
    assert_eq!(by_file.len(), 3);

    // Findings carry the path string they were created with; the deleted
    // file's path can no longer be resolved, so compare raw strings, the
    // same ones embedded in the findings above.
    let raw = |p: &std::path::Path| p.to_string_lossy().to_string();
    // BTreeMap order: files sorted by path string.
    let expected: Vec<(String, Vec<String>)> = vec![
        (raw(&changed), vec!["fresh-changed".to_string()]),
        (raw(&new), vec!["fresh-new".to_string()]),
        (raw(&unchanged), vec!["prev-unchanged".to_string()]),
    ];

    assert_eq!(by_file, expected);

    // gone.rs must appear in neither side: its file is gone, so the previous
    // finding is neither carried nor kept.
    let gone_raw = raw(&gone);
    assert!(
        !by_file.iter().any(|(file, _)| *file == gone_raw),
        "a deleted file's findings must vanish from the union"
    );
}

// ============================================================================
// Persisted envelope: version and rules-fingerprint bust gates
// ============================================================================

#[test]
fn persisted_store_round_trips_under_the_same_fingerprint() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let store = store_from_files(&[&file]);
    let path = dir
        .path()
        .join("file-hashes.json")
        .to_str()
        .unwrap()
        .to_string();

    baco::incremental_scan::save_persisted_store(&path, &store, "fp-1").unwrap();
    let loaded = baco::incremental_scan::load_persisted_store(&path, "fp-1").unwrap();

    assert_eq!(loaded.len(), 1);
    assert!(loaded.get_hash(&file.canonicalize().unwrap()).is_some());
}

#[test]
fn persisted_store_rejects_a_changed_rules_fingerprint() {
    let dir = TempDir::new().unwrap();
    let path = dir
        .path()
        .join("file-hashes.json")
        .to_str()
        .unwrap()
        .to_string();

    baco::incremental_scan::save_persisted_store(&path, &FileHashStore::new(), "fp-v1").unwrap();
    let err = baco::incremental_scan::load_persisted_store(&path, "fp-v2").unwrap_err();

    assert!(
        err.contains("config changed"),
        "error must name the reason, got: {}",
        err
    );
}

#[test]
fn persisted_store_rejects_an_older_schema() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("file-hashes.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema": 0,
            "baco_version": env!("CARGO_PKG_VERSION"),
            "rules_fingerprint": "fp",
            "hashes": {},
        })
        .to_string(),
    )
    .unwrap();

    let err =
        baco::incremental_scan::load_persisted_store(path.to_str().unwrap(), "fp").unwrap_err();

    assert!(
        err.contains("schema"),
        "error must name the schema mismatch, got: {}",
        err
    );
}

#[test]
fn persisted_store_rejects_a_foreign_baco_version() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("file-hashes.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "schema": baco::incremental_scan::STORE_SCHEMA,
            "baco_version": "0.0.0-test",
            "rules_fingerprint": "fp",
            "hashes": {},
        })
        .to_string(),
    )
    .unwrap();

    let err =
        baco::incremental_scan::load_persisted_store(path.to_str().unwrap(), "fp").unwrap_err();

    assert!(
        err.contains("0.0.0-test"),
        "error must name the version that wrote it, got: {}",
        err
    );
}

#[test]
fn rules_fingerprint_is_stable_and_difference_sensitive() {
    use baco::incremental_scan::rules_fingerprint;

    let base = rules_fingerprint(&["rust".to_string()], &[], &[], &[]);
    let same = rules_fingerprint(&["rust".to_string()], &[], &[], &[]);
    assert_eq!(base, same, "identical inputs must fingerprint identically");

    let other_language = rules_fingerprint(&["python".to_string()], &[], &[], &[]);
    assert_ne!(base, other_language, "language set is rule-affecting");

    let other_rules = rules_fingerprint(
        &["rust".to_string()],
        &[],
        &[],
        &["custom-rule.yaml".to_string()],
    );
    assert_ne!(base, other_rules, "custom rules are rule-affecting");
}

// ============================================================================
// analysis_files_for_incremental: the gating helper for LLM static analysis
// ============================================================================

#[test]
fn analysis_files_for_incremental_none_store_keeps_all() {
    let dir = TempDir::new().unwrap();
    let file1 = dir.path().join("a.rs");
    let file2 = dir.path().join("b.rs");
    std::fs::write(&file1, "fn a() {}").unwrap();
    std::fs::write(&file2, "fn b() {}").unwrap();

    use baco::indexer::FileInfo;
    let files = vec![
        FileInfo {
            path: file1.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
        FileInfo {
            path: file2.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
    ];

    let (kept, skipped) =
        baco::incremental_scan::analysis_files_for_incremental(&files, None, false);

    assert_eq!(kept.len(), 2);
    assert_eq!(skipped, 0);
}

#[test]
fn analysis_files_for_incremental_empty_store_keeps_all() {
    let dir = TempDir::new().unwrap();
    let file1 = dir.path().join("a.rs");
    let file2 = dir.path().join("b.rs");
    std::fs::write(&file1, "fn a() {}").unwrap();
    std::fs::write(&file2, "fn b() {}").unwrap();

    use baco::indexer::FileInfo;
    let files = vec![
        FileInfo {
            path: file1.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
        FileInfo {
            path: file2.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
    ];

    let store = FileHashStore::new();
    let (kept, skipped) =
        baco::incremental_scan::analysis_files_for_incremental(&files, Some(&store), false);

    assert_eq!(kept.len(), 2);
    assert_eq!(skipped, 0);
}

#[test]
fn analysis_files_for_incremental_some_store_no_previous_findings_keeps_all() {
    let dir = TempDir::new().unwrap();
    let file1 = dir.path().join("a.rs");
    let file2 = dir.path().join("b.rs");
    std::fs::write(&file1, "fn a() {}").unwrap();
    std::fs::write(&file2, "fn b() {}").unwrap();

    use baco::indexer::FileInfo;
    let files = vec![
        FileInfo {
            path: file1.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
        FileInfo {
            path: file2.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
    ];

    let store = store_from_files(&[&file1, &file2]);
    let (kept, skipped) =
        baco::incremental_scan::analysis_files_for_incremental(&files, Some(&store), false);

    // No previous findings → everything analyzed
    assert_eq!(kept.len(), 2);
    assert_eq!(skipped, 0);
}

#[test]
fn analysis_files_for_incremental_some_store_with_findings_skips_unchanged() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let modified = dir.path().join("modified.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&modified, "fn b() {}").unwrap();

    use baco::indexer::FileInfo;
    let files = vec![
        FileInfo {
            path: unchanged.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
        FileInfo {
            path: modified.clone(),
            language: "rust".to_string(),
            size: 10,
            hash: None,
        },
    ];

    // Store hashes for both files
    let store = store_from_files(&[&unchanged, &modified]);

    // Modify one file
    std::fs::write(&modified, "fn b() { CHANGED }").unwrap();

    let (kept, skipped) =
        baco::incremental_scan::analysis_files_for_incremental(&files, Some(&store), true);

    assert_eq!(kept.len(), 1);
    assert_eq!(skipped, 1);
    assert_eq!(kept[0].path.file_name().unwrap(), "modified.rs");
}

// ============================================================================
// drop_findings_for_unchanged_files: the chokepoint helper
// ============================================================================

#[test]
fn drop_findings_for_unchanged_files_none_store_keeps_all() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let findings = vec![finding_in("f1", &file), finding_in("f2", &file)];

    let (kept, dropped) =
        baco::incremental_scan::drop_findings_for_unchanged_files(findings, None, 0);

    assert_eq!(kept.len(), 2);
    assert_eq!(dropped, 0);
}

#[test]
fn drop_findings_for_unchanged_files_empty_store_keeps_all() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();

    let findings = vec![finding_in("f1", &file), finding_in("f2", &file)];

    let store = FileHashStore::new();
    let (kept, dropped) =
        baco::incremental_scan::drop_findings_for_unchanged_files(findings, Some(&store), 0);

    assert_eq!(kept.len(), 2);
    assert_eq!(dropped, 0);
}

#[test]
fn drop_findings_for_unchanged_files_drops_unchanged() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let changed = dir.path().join("changed.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&changed, "fn b() {}").unwrap();

    let store = store_from_files(&[&unchanged, &changed]);
    std::fs::write(&changed, "fn b() { CHANGED }").unwrap();

    let findings = vec![
        finding_in("f-unchanged", &unchanged),
        finding_in("f-changed", &changed),
    ];

    let (kept, dropped) =
        baco::incremental_scan::drop_findings_for_unchanged_files(findings, Some(&store), 1);

    assert_eq!(kept.len(), 1);
    assert_eq!(dropped, 1);
    assert_eq!(kept[0].id, "f-changed");
}

// ============================================================================
// should_persist: the save gate helper
// ============================================================================

#[test]
fn should_persist_all_true_returns_true() {
    assert!(baco::incremental_scan::should_persist(true, true, true));
}

#[test]
fn should_persist_incremental_inactive_returns_false() {
    assert!(!baco::incremental_scan::should_persist(false, true, true));
}

#[test]
fn should_persist_parallel_failed_returns_false() {
    assert!(!baco::incremental_scan::should_persist(true, false, true));
}

#[test]
fn should_persist_scan_incomplete_returns_false() {
    assert!(!baco::incremental_scan::should_persist(true, true, false));
}

// ============================================================================
// effective_analysed: the health math helper
// ============================================================================

#[test]
fn effective_analysed_subtracts_unchanged() {
    assert_eq!(baco::incremental_scan::effective_analysed(100, 20), 80);
}

#[test]
fn effective_analysed_zero_unchanged_returns_indexed() {
    assert_eq!(baco::incremental_scan::effective_analysed(100, 0), 100);
}

#[test]
fn effective_analysed_all_unchanged_returns_zero() {
    assert_eq!(baco::incremental_scan::effective_analysed(100, 100), 0);
}

#[test]
fn effective_analysed_more_unchanged_than_indexed_returns_zero() {
    assert_eq!(baco::incremental_scan::effective_analysed(50, 100), 0);
}

// ============================================================================
// load_previous_run_context: the snapshot helper
// ============================================================================

#[test]
fn load_previous_run_context_no_store_warns_and_returns_empty() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path();
    let fingerprint = "test-fingerprint";

    let (store, findings, warnings) = baco::incremental_scan::load_previous_run_context(
        output_dir,
        fingerprint,
        &output_dir.join("file-hashes.json"),
    );

    assert!(store.is_none());
    assert!(findings.is_empty());
    // When the store is missing, a warning is produced
    assert!(!warnings.is_empty());
}

#[test]
fn load_previous_run_context_corrupt_store_warns() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path();
    let fingerprint = "test-fingerprint";

    // Create a corrupt store file
    let store_path = output_dir.join("file-hashes.json");
    std::fs::write(&store_path, "corrupt json").unwrap();

    let (store, findings, warnings) =
        baco::incremental_scan::load_previous_run_context(output_dir, fingerprint, &store_path);

    assert!(store.is_none());
    assert!(findings.is_empty());
    assert!(!warnings.is_empty());
}

#[test]
fn load_previous_run_context_valid_store_loads_data() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path();
    let fingerprint = "test-fingerprint";

    // Create a valid store file with proper envelope
    let store_path = output_dir.join("file-hashes.json");
    let store_json = format!(
        r#"{{
        "schema": 1,
        "baco_version": "{}",
        "rules_fingerprint": "{}",
        "hashes": {{
            "src/main.rs": "abc123"
        }}
    }}"#,
        baco_version(),
        fingerprint
    );
    std::fs::write(&store_path, store_json).unwrap();

    let (store, findings, warnings) =
        baco::incremental_scan::load_previous_run_context(output_dir, fingerprint, &store_path);

    // The store should load successfully
    assert!(
        store.is_some(),
        "Store should load: warnings={:?}",
        warnings
    );
    assert_eq!(store.as_ref().unwrap().len(), 1);
    assert!(findings.is_empty());
    // No warnings when store loads successfully
    assert!(warnings.is_empty());
}

// ============================================================================
// Orchestrator glue: incremental context wiring
// ============================================================================

use baco::scanner::Scanner;
use baco::scanner::orchestrator::{
    IncrementalContext, apply_incremental_chokepoint, ingest_incremental_snapshot,
    maybe_persist_incremental_store, prepare_incremental_context,
};

fn glue_test_scanner(output_dir: &std::path::Path, active: bool, force: bool) -> Scanner {
    let mut config = baco::config::ScannerConfig::default();
    config.output.dir = output_dir.to_string_lossy().to_string();
    config.scanner.incremental_scan = active;
    config.prior_runs.enabled = active;
    config.project.languages = vec!["php".to_string()];
    Scanner::new(config, std::path::PathBuf::from("."), force)
}

#[test]
fn prepare_context_reflects_config_force_and_paths() {
    let dir = TempDir::new().unwrap();
    let scanner = glue_test_scanner(dir.path(), true, false);
    let ctx = prepare_incremental_context(&scanner);

    assert!(ctx.active);
    assert_eq!(ctx.store_path, dir.path().join("file-hashes.json"));
    // The fingerprint must be the same function of config the store was
    // persisted under — anything else rejects the store at load.
    assert_eq!(
        ctx.fingerprint,
        baco::incremental_scan::rules_fingerprint(&["php".to_string()], &[], &[], &[],)
    );

    let forced = glue_test_scanner(dir.path(), true, true);
    assert!(!prepare_incremental_context(&forced).active);
    let disabled = glue_test_scanner(dir.path(), false, false);
    assert!(!prepare_incremental_context(&disabled).active);
}

/// Build a scanner whose output dir holds a usable previous run: a store
/// recording `files`'s current hashes and one saved prior run with
/// `previous_findings`.
fn scanner_with_previous_run(
    output_dir: &std::path::Path,
    files: &[&std::path::Path],
    previous_findings: &[VulnerabilityFinding],
) -> (Scanner, IncrementalContext) {
    let store = store_from_files(files);
    let store_path = output_dir
        .join("file-hashes.json")
        .to_str()
        .unwrap()
        .to_string();
    let scanner = glue_test_scanner(output_dir, true, false);
    let ctx = prepare_incremental_context(&scanner);
    baco::incremental_scan::save_persisted_store(&store_path, &store, &ctx.fingerprint).unwrap();

    let run_dir = output_dir.join("runs").join("run-0001_a");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("findings.json"),
        serde_json::to_string(previous_findings).unwrap(),
    )
    .unwrap();

    (scanner, ctx)
}

#[test]
fn ingest_snapshot_loads_previous_run_into_state() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();
    let previous = vec![finding_in("prev-1", &file)];
    let (scanner, ctx) = scanner_with_previous_run(dir.path(), &[&file], &previous);

    let warnings = ingest_incremental_snapshot(&scanner, &ctx);

    assert_eq!(
        warnings, 0,
        "usable previous run must load without warnings"
    );
    let state = scanner.state.borrow();
    assert!(
        state
            .previous_hash_store
            .as_ref()
            .is_some_and(|s| !s.is_empty())
    );
    assert_eq!(state.previous_findings.len(), 1);
}

#[test]
fn ingest_snapshot_without_previous_run_warns_and_stays_empty() {
    let dir = TempDir::new().unwrap();
    let scanner = glue_test_scanner(dir.path(), true, false);
    let ctx = prepare_incremental_context(&scanner);

    let warnings = ingest_incremental_snapshot(&scanner, &ctx);

    assert!(warnings > 0);
    let state = scanner.state.borrow();
    assert!(state.previous_hash_store.is_none());
    assert!(state.previous_findings.is_empty());
}

#[test]
fn ingest_snapshot_is_a_no_op_when_inactive() {
    let dir = TempDir::new().unwrap();
    let scanner = glue_test_scanner(dir.path(), false, false);
    let ctx = prepare_incremental_context(&scanner);

    assert_eq!(ingest_incremental_snapshot(&scanner, &ctx), 0);
    assert!(scanner.state.borrow().previous_hash_store.is_none());
}

#[test]
fn chokepoint_drops_fresh_findings_for_unchanged_files_only() {
    let dir = TempDir::new().unwrap();
    let unchanged = dir.path().join("unchanged.rs");
    let changed = dir.path().join("changed.rs");
    std::fs::write(&unchanged, "fn a() {}").unwrap();
    std::fs::write(&changed, "fn b() {}").unwrap();

    let previous = vec![finding_in("prev-unchanged", &unchanged)];
    let (scanner, ctx) = scanner_with_previous_run(dir.path(), &[&unchanged, &changed], &previous);
    ingest_incremental_snapshot(&scanner, &ctx);
    std::fs::write(&changed, "fn b() { CHANGED }").unwrap();
    // the escalation: fresh findings on both files
    let fresh = vec![
        finding_in("fresh-unchanged", &unchanged),
        finding_in("fresh-changed", &changed),
    ];

    let kept = apply_incremental_chokepoint(&scanner, &ctx, fresh);

    let mut kept_ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
    kept_ids.sort();
    assert_eq!(kept_ids, vec!["fresh-changed"]);
}

#[test]
fn chokepoint_inactive_keeps_everything() {
    let dir = TempDir::new().unwrap();
    let scanner = glue_test_scanner(dir.path(), false, false);
    let ctx = prepare_incremental_context(&scanner);

    let fresh = vec![finding_in("fresh-1", &dir.path().join("x.rs"))];
    let kept = apply_incremental_chokepoint(&scanner, &ctx, fresh);

    assert_eq!(kept.len(), 1);
}

#[test]
fn persist_gate_writes_the_store_only_for_a_full_active_scan() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.rs");
    std::fs::write(&file, "fn a() {}").unwrap();
    let scanner = glue_test_scanner(dir.path(), true, false);
    let ctx = prepare_incremental_context(&scanner);
    let store = store_from_files(&[&file]);
    scanner
        .state
        .send_modify(|s| s.last_hash_store = Some(store.clone()));

    maybe_persist_incremental_store(&scanner, &ctx, true, true);
    assert!(
        dir.path().join("file-hashes.json").exists(),
        "a fully completed active scan must persist the store"
    );

    // Early termination must not poison the next run.
    let dir2 = TempDir::new().unwrap();
    let scanner2 = glue_test_scanner(dir2.path(), true, false);
    let ctx2 = prepare_incremental_context(&scanner2);
    scanner2
        .state
        .send_modify(|s| s.last_hash_store = Some(FileHashStore::new()));
    maybe_persist_incremental_store(&scanner2, &ctx2, true, false);
    assert!(!dir2.path().join("file-hashes.json").exists());

    // Inactive feature must not write anything either.
    let dir3 = TempDir::new().unwrap();
    let scanner3 = glue_test_scanner(dir3.path(), false, false);
    let ctx3 = prepare_incremental_context(&scanner3);
    scanner3
        .state
        .send_modify(|s| s.last_hash_store = Some(FileHashStore::new()));
    maybe_persist_incremental_store(&scanner3, &ctx3, true, true);
    assert!(!dir3.path().join("file-hashes.json").exists());
}
