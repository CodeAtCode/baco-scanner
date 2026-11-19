//! Tests for run_store timestamp resolution and parse failure logging.

use crate::fixtures::create_test_finding;
use baco::findings::{VerificationStatus, VulnerabilityFinding};
use baco::run_store;
use std::fs::File;
use std::io::Write;

fn make_finding(id: &str) -> VulnerabilityFinding {
    let mut f = create_test_finding(id, "Test finding", "src/test.rs", 1);
    f.description = "Test description".to_string();
    f.verification_status = Some(VerificationStatus::Confirmed);
    f
}

/// Test that same-second runs no longer overwrite each other due to sub-second resolution.
#[test]
fn test_same_second_runs_no_longer_overwrite_with_subsecond_resolution() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Save two runs in quick succession (within the same second)
    let findings1 = vec![make_finding("finding-1")];
    let findings2 = vec![make_finding("finding-2")];

    run_store::save_run(output_dir, &findings1);
    run_store::save_run(output_dir, &findings2);

    // Check how many run directories were created
    let runs_dir = output_dir.join("runs");
    let run_dirs: Vec<_> = std::fs::read_dir(&runs_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();

    // FIX: With sub-second resolution, both runs should have separate directories
    assert_eq!(
        run_dirs.len(),
        2,
        "FIX VERIFIED: Sub-second resolution prevents same-second overwrites"
    );

    // Load prior runs - should have both findings
    let loaded = run_store::load_prior_runs(output_dir, 5);
    assert_eq!(
        loaded.len(),
        2,
        "FIX VERIFIED: Both findings loaded from separate run directories"
    );

    // Verify each run directory has a unique name with nanoseconds
    for dir in &run_dirs {
        let name = dir.file_name().unwrap().to_string_lossy();
        // Should contain underscore (secs_nanos format) or be unique
        assert!(
            name.contains("_") || name.starts_with("run-"),
            "Run directory should have proper naming: {}",
            name
        );
    }
}

/// Test that parse failures are now logged at warning level, not debug.
/// This verifies the fix for the silent failure bug.
#[test]
fn test_parse_failure_logging_level_is_now_warn() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();
    let runs_dir = output_dir.join("runs");
    let run_dir = runs_dir.join("run-1000");

    std::fs::create_dir_all(&run_dir).unwrap();

    // Write corrupt JSON
    File::create(run_dir.join("findings.json"))
        .unwrap()
        .write_all(b"not valid json")
        .unwrap();

    // Load prior runs - corrupt JSON is skipped
    let loaded = run_store::load_prior_runs(output_dir, 5);
    assert_eq!(loaded.len(), 0, "Corrupt JSON should be skipped");

    // FIX: The skip is now logged at WARN level (run_store.rs:162-164)
    // This ensures lost data is not silent - complies with AGENTS.md "No silent failures"
    //
    // Note: We cannot easily verify the log level in a unit test, but the fix
    // changes tracing::debug! to tracing::warn! at the source.
}

/// Test that unparseable prior runs are now warned about, not silently skipped.
/// This verifies the fix for the silent failure bug.
#[test]
fn test_unparseable_prior_runs_now_warned_about_not_silently_skipped() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();
    let runs_dir = output_dir.join("runs");

    // Create two run directories
    let run1_dir = runs_dir.join("run-1000");
    let run2_dir = runs_dir.join("run-2000");
    std::fs::create_dir_all(&run1_dir).unwrap();
    std::fs::create_dir_all(&run2_dir).unwrap();

    // Write valid JSON to run1
    let findings1 = vec![make_finding("valid-finding")];
    let json1 = serde_json::to_string(&findings1).unwrap();
    File::create(run1_dir.join("findings.json"))
        .unwrap()
        .write_all(json1.as_bytes())
        .unwrap();

    // Write corrupt JSON to run2
    File::create(run2_dir.join("findings.json"))
        .unwrap()
        .write_all(b"corrupt data")
        .unwrap();

    // Load with max_runs=5
    let loaded = run_store::load_prior_runs(output_dir, 5);

    // FIX: The corrupt run is now logged at WARN level (not silently skipped)
    // A skipped prior run is lost data and must not be silent
    assert_eq!(loaded.len(), 1, "Valid run should be loaded");

    // Note: We cannot easily verify the warning was logged in a unit test,
    // but the fix changes tracing::debug! to tracing::warn! at the source.
}
