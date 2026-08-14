//! Unit tests for `baco::file_hash` module
//!
//! Covers: calculate_file_hash, calculate_content_hash, FileHasher

use baco::file_hash::{calculate_content_hash, calculate_file_hash, FileHasher};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// calculate_content_hash Tests
// ============================================================================

#[test]
fn test_calculate_content_hash_hello_world() {
    let content = b"Hello, World!";
    let hash = calculate_content_hash(content);

    // SHA256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    assert_eq!(
        hash,
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    );
}

#[test]
fn test_calculate_content_hash_empty() {
    let content = b"";
    let hash = calculate_content_hash(content);

    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_calculate_content_hash_single_byte() {
    let content = b"a";
    let hash = calculate_content_hash(content);

    // SHA256("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
    assert_eq!(
        hash,
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
}

#[test]
fn test_calculate_content_hash_deterministic() {
    let content = b"test content for determinism";

    let hash1 = calculate_content_hash(content);
    let hash2 = calculate_content_hash(content);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_calculate_content_hash_different_inputs_different_hashes() {
    let hash1 = calculate_content_hash(b"input1");
    let hash2 = calculate_content_hash(b"input2");

    assert_ne!(hash1, hash2);
}

#[test]
fn test_calculate_content_hash_unicode() {
    let content = "Hello, 世界！🌍".as_bytes();
    let hash = calculate_content_hash(content);

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_calculate_content_hash_long_content() {
    let content = vec![b'a'; 10000];
    let hash = calculate_content_hash(&content);

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ============================================================================
// calculate_file_hash Tests
// ============================================================================

#[test]
fn test_calculate_file_hash_basic() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_calculate_file_hash_known_value() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Hello, World!").unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    // Should match SHA256("Hello, World!")
    assert_eq!(
        hash,
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    );
}

#[test]
fn test_calculate_file_hash_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("empty.txt");

    File::create(&file_path).unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    // SHA256 of empty content
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_calculate_file_hash_nonexistent_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("nonexistent.txt");

    let result = calculate_file_hash(&file_path);

    assert!(result.is_err());
}

#[test]
fn test_calculate_file_hash_directory_instead_of_file() {
    let temp_dir = TempDir::new().unwrap();

    let result = calculate_file_hash(temp_dir.path());

    assert!(result.is_err());
}

#[test]
fn test_calculate_file_hash_deterministic() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"deterministic test").unwrap();

    let hash1 = calculate_file_hash(&file_path).unwrap();
    let hash2 = calculate_file_hash(&file_path).unwrap();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_calculate_file_hash_binary_content() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("binary.bin");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(&[0x00, 0xFF, 0xAB, 0xCD, 0xEF]).unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ============================================================================
// FileHasher Tests
// ============================================================================

#[test]
fn test_file_hasher_new() {
    let _hasher = FileHasher::new();
}

#[test]
fn test_file_hasher_default() {
    let _hasher = FileHasher::default();
}

#[test]
fn test_file_hasher_hash_file_basic() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Basic hash test").unwrap();

    let mut hasher = FileHasher::new();
    let hash = hasher.hash_file(&file_path).unwrap();

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_file_hasher_cache_hit() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Cached test").unwrap();

    let mut hasher = FileHasher::new();

    let hash1 = hasher.hash_file(&file_path).unwrap();
    let hash2 = hasher.hash_file(&file_path).unwrap();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_file_hasher_nonexistent_file() {
    let mut hasher = FileHasher::new();

    let result = hasher.hash_file(Path::new("/nonexistent/file.txt"));

    assert!(result.is_err());
}

#[test]
fn test_file_hasher_multiple_files() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("test1.txt");
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"Content 1").unwrap();

    let file2 = temp_dir.path().join("test2.txt");
    let mut f2 = File::create(&file2).unwrap();
    f2.write_all(b"Content 2").unwrap();

    let mut hasher = FileHasher::new();

    let hash1 = hasher.hash_file(&file1).unwrap();
    let hash2 = hasher.hash_file(&file2).unwrap();

    assert_ne!(hash1, hash2);
}

#[test]
fn test_file_hasher_hash_consistency_across_files() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("test1.txt");
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"Same content").unwrap();

    let file2 = temp_dir.path().join("test2.txt");
    let mut f2 = File::create(&file2).unwrap();
    f2.write_all(b"Same content").unwrap();

    let mut hasher = FileHasher::new();

    let hash1 = hasher.hash_file(&file1).unwrap();
    let hash2 = hasher.hash_file(&file2).unwrap();

    // Same content should produce same hash
    assert_eq!(hash1, hash2);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_file_hash_single_byte_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("single.bin");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(&[0x42]).unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_calculate_content_hash_newline() {
    let content = b"\n";
    let hash = calculate_content_hash(content);

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_calculate_content_hash_all_ascii() {
    let content: Vec<u8> = (0..128).collect();
    let hash = calculate_content_hash(&content);

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_file_hash_special_characters_in_path() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test with spaces.txt");

    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"test").unwrap();

    let hash = calculate_file_hash(&file_path).unwrap();

    assert_eq!(hash.len(), 64);
}
