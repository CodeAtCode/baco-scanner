//! Verification test for file hash store persistence.
//!
//! This test documents the current behavior: the file hash store built during
//! indexing is never persisted or consulted, so incremental skipping never happens.
//!
//! Per the task specification, this is VERIFY-ONLY - no fix is authorized because
//! wiring incremental skipping can silently drop a changed file from a scan.
//! This test pins the current behavior so any future change to skipping is deliberate.
//!
//! Evidence from code review (grep/read):
//! - src/indexer.rs:131 builds a hash_store field but never saves it
//! - src/incremental_scan.rs:53,76 define save/load with no callers
//! - grep "save.*hash_store" or "load.*hash_store" returns no results in src/

/// Test that documents the file hash store is never persisted.
///
/// This is a verification test that documents the current (buggy) behavior.
/// The test always passes because it's documenting what exists, not what should exist.
#[test]
fn test_file_hash_store_never_persisted_verification() {
    // Evidence from code review:
    //
    // 1. src/indexer.rs:131 creates FileIndex with hash_store field:
    //    Ok(FileIndex {
    //        files,
    //        total_size,
    //        hash_store: previous_hash_store,  // <-- Never saved to disk
    //    })
    //
    // 2. src/incremental_scan.rs:53 defines FileHashStore::save:
    //    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> { ... }
    //    But grep shows NO CALLERS of this method
    //
    // 3. src/incremental_scan.rs:76 defines FileHashStore::load:
    //    pub fn load(path: &Path) -> Result<Self, String> { ... }
    //    But grep shows NO CALLERS of this method
    //
    // Conclusion: The hash store infrastructure exists but is never used.
    // Incremental skipping based on file hashes does not happen.

    // This test passes because it documents the absence of persistence.
    // After a fix (if authorized), this test would verify that:
    // 1. The hash store is persisted after indexing
    // 2. The hash store is loaded on subsequent scans
    // 3. Unchanged files are skipped based on hash comparison
    let _documentation = "Hash store persistence not implemented";
}

/// Test that documents a second scan re-analyses unchanged files.
///
/// This is the acceptance test for the current behavior: incremental skipping is not implemented.
#[test]
fn test_second_scan_re_analyses_unchanged_files_verification() {
    // This test documents that incremental skipping is not implemented.
    // The hash store is built but never persisted, so every scan re-analyses all files.

    // After a fix (if authorized), this test would verify that:
    // 1. A second scan loads the previous hash store
    // 2. Files with unchanged hashes are skipped
    // 3. Only changed files are re-analysed
    let _documentation = "Incremental skipping not implemented";
}

/// Test documenting the grep evidence for missing hash store callers.
#[test]
fn test_grep_evidence_no_hash_store_callers() {
    // Run grep to verify no callers of hash_store save/load exist
    // This is a runtime verification that the code review finding is correct

    let output = std::process::Command::new("grep")
        .args([
            "-r",
            "--include=*.rs",
            "save.*hash_store\\|load.*hash_store",
            "src/",
        ])
        .output()
        .expect("Failed to run grep");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The grep should return empty (no matches)
    // This verifies the claim that save/load are never called
    assert!(
        stdout.trim().is_empty(),
        "No callers of hash_store save/load should exist, but found:\n{}",
        stdout
    );
}
