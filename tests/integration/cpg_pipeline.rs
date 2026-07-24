//! Integration tests for CPG-guided slicing (T3.1)
//!
//! These tests require Joern to be installed.
//! Run with: cargo test --test cpg_pipeline -- --include-ignored

use baco::cpg::{CpgEngine, JoernEngine};
use std::path::Path;

/// This test is ignored because it requires Joern to be installed.
/// To run: cargo test --test cpg_pipeline -- --include-ignored
#[test]
fn full_cpg_pipeline_produces_slice() {
    // Create Joern engine
    let engine = JoernEngine::new(None);

    // Skip if Joern not available (test passes without assertion)
    if !engine.is_available() {
        eprintln!("Joern not available — test passes without assertion");
        return;
    }

    // Create a temporary test project
    let temp_dir = std::env::temp_dir().join("baco-cpg-test");
    let _ = std::fs::remove_dir_all(&temp_dir); // Clean up previous runs
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    // Create a simple vulnerable C file
    let vulnerable_code = r#"
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Buffer overflow vulnerability
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
"#;

    let test_file = temp_dir.join("vulnerable.c");
    std::fs::write(&test_file, vulnerable_code).expect("Failed to write test file");

    // Build CPG
    let cpg = engine.build(&temp_dir).expect("Failed to build CPG");
    assert!(cpg.cpg_path.exists(), "CPG file should exist");

    // Run a query for buffer overflow patterns
    let query = "cpg.call(\".*strcpy.*\").argument.l";
    let result = engine.run_query(&cpg, query).expect("Failed to run query");

    // Verify we got results
    assert!(
        !result.nodes.is_empty(),
        "Query should return nodes for strcpy call"
    );

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Test that JoernEngine correctly reports availability
#[test]
fn joern_engine_availability_check() {
    let engine_with_path = JoernEngine::new(None);
    let engine_with_explicit_path = JoernEngine::new(Some(Path::new("joern").to_path_buf()));

    // If Joern not available, skip gracefully
    if !engine_with_path.is_available() {
        eprintln!("Joern not available — test passes without assertion");
        return;
    }

    // Both should report the same availability status
    assert_eq!(
        engine_with_path.is_available(),
        engine_with_explicit_path.is_available()
    );
}

/// Test that build fails gracefully when Joern is not installed
#[test]
fn build_fails_gracefully_without_joern() {
    let engine = JoernEngine::new(None);

    if !engine.is_available() {
        let temp_dir = std::env::temp_dir().join("baco-test-no-joern");
        let result = engine.build(&temp_dir);

        assert!(
            matches!(result, Err(baco::cpg::CpgError::JoernNotInstalled)),
            "Should return JoernNotInstalled error when Joern is not available"
        );
    }
    // If Joern IS available, this test doesn't apply (but that's fine - Joern should be rare in CI)
}
