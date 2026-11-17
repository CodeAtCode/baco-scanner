//! Tests for atomic write functionality.
//!
//! These tests verify that atomic writes:
//! 1. Round-trip correctly (save → load produces same data)
//! 2. Leave no .tmp residue in the directory
//! 3. Create parent directories as needed

use std::fs;
use tempfile::TempDir;

/// Get a unique test directory for this test
fn test_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

#[test]
fn test_atomic_write_round_trip() {
    let tmp_dir = test_dir();
    let path = tmp_dir.path().join("test.json");

    let data = br#"{"key": "value", "number": 42}"#;

    // Write atomically
    baco::hook_registry::atomic_write(&path, data).expect("Failed to write");

    // Read back
    let read = fs::read(&path).expect("Failed to read");

    // Verify content matches
    assert_eq!(data, &read[..]);
}

#[test]
fn test_atomic_write_no_tmp_residue() {
    let tmp_dir = test_dir();
    let path = tmp_dir.path().join("test.json");

    let data = b"test content";

    // Write atomically
    baco::hook_registry::atomic_write(&path, data).expect("Failed to write");

    // Check no .tmp file remains
    let tmp_path = tmp_dir.path().join("test.tmp");
    assert!(
        !tmp_path.exists(),
        "Temporary file should not remain after successful write"
    );

    // Also check the directory has only our file
    let entries: Vec<_> = fs::read_dir(tmp_dir.path())
        .expect("Failed to read dir")
        .map(|e| e.expect("Failed to read entry").file_name())
        .collect();

    assert_eq!(
        entries.len(),
        1,
        "Directory should contain only the target file"
    );
    assert_eq!(entries[0], "test.json");
}

#[test]
fn test_atomic_write_creates_parent() {
    let tmp_dir = test_dir();
    let path = tmp_dir.path().join("nested").join("deep").join("test.json");

    let data = b"nested content";

    // Write atomically - should create parent directories
    baco::hook_registry::atomic_write(&path, data).expect("Failed to write");

    // Verify file exists
    assert!(path.exists(), "Target file should exist");

    // Verify content
    let read = fs::read(&path).expect("Failed to read");
    assert_eq!(data, &read[..]);

    // Verify no .tmp residue
    let tmp_path = tmp_dir.path().join("nested").join("deep").join("test.tmp");
    assert!(!tmp_path.exists(), "Temporary file should not remain");
}

#[test]
fn test_atomic_write_overwrites_existing() {
    let tmp_dir = test_dir();
    let path = tmp_dir.path().join("test.json");

    // Write initial content
    let initial = b"initial content";
    baco::hook_registry::atomic_write(&path, initial).expect("Failed to write");

    // Overwrite with new content
    let updated = b"updated content";
    baco::hook_registry::atomic_write(&path, updated).expect("Failed to write");

    // Verify new content
    let read = fs::read(&path).expect("Failed to read");
    assert_eq!(updated, &read[..]);

    // Verify no .tmp residue
    let tmp_path = tmp_dir.path().join("test.tmp");
    assert!(!tmp_path.exists(), "Temporary file should not remain");
}

#[test]
fn test_atomic_write_json_pretty() {
    let tmp_dir = test_dir();
    let path = tmp_dir.path().join("baseline.json");

    // Simulate JSON pretty-printed content
    let json = r#"{
  "total_findings": 100,
  "true_positives": 85,
  "false_positives": 15,
  "mean_confidence": 0.75,
  "sum_sq_dev": 12.5
}"#;

    // Write atomically
    baco::hook_registry::atomic_write(&path, json.as_bytes()).expect("Failed to write");

    // Read back and verify
    let read = fs::read_to_string(&path).expect("Failed to read");
    assert_eq!(json, read);

    // Verify no .tmp residue
    let tmp_path = tmp_dir.path().join("baseline.tmp");
    assert!(!tmp_path.exists(), "Temporary file should not remain");
}
