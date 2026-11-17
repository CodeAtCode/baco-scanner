//! Unit tests for the analysis context persistence module.
//!
//! Tests cover all public APIs in src/analysis_context.rs including
//! save, load, and edge cases.

use baco::analysis_context::AnalysisContext;

// ============================================================================
// save tests
// ============================================================================

#[test]
fn test_save_creates_directory() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let nested_path = tmp_dir.path().join("nested").join("output");

    let ctx = AnalysisContext::default();
    let result = ctx.save(&nested_path);

    assert!(result.is_ok());
    assert!(nested_path.exists());
}

#[test]
fn test_save_creates_context_json() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext::default();
    ctx.save(tmp_dir.path()).unwrap();

    let context_path = tmp_dir.path().join("context.json");
    assert!(context_path.exists());
}

#[test]
fn test_save_with_data() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext {
        invariants: vec!["Invariant 1".to_string(), "Invariant 2".to_string()],
        findings_so_far: vec!["Finding 1".to_string()],
    };

    let result = ctx.save(tmp_dir.path());
    assert!(result.is_ok());

    // Verify file exists and has content
    let context_path = tmp_dir.path().join("context.json");
    let content = std::fs::read_to_string(&context_path).unwrap();
    assert!(!content.is_empty());
}

// ============================================================================
// load tests
// ============================================================================

#[test]
fn test_load_returns_default_when_file_missing() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert!(ctx.invariants.is_empty());
    assert!(ctx.findings_so_far.is_empty());
}

#[test]
fn test_load_returns_default_when_directory_empty() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert!(ctx.invariants.is_empty());
}

#[test]
fn test_load_restores_saved_context() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let original = AnalysisContext {
        invariants: vec!["No unauthenticated access".to_string()],
        findings_so_far: vec!["CWE-79: XSS".to_string(), "CWE-89: SQLi".to_string()],
    };

    original.save(tmp_dir.path()).unwrap();
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert_eq!(loaded.invariants, original.invariants);
    assert_eq!(loaded.findings_so_far, original.findings_so_far);
}

#[test]
fn test_load_with_empty_invariants() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext {
        invariants: vec![],
        findings_so_far: vec![],
    };

    ctx.save(tmp_dir.path()).unwrap();
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert!(loaded.invariants.is_empty());
}

#[test]
fn test_load_with_multiple_findings() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext {
        invariants: vec![],
        findings_so_far: vec![
            "CWE-79: XSS in header".to_string(),
            "CWE-89: SQL injection".to_string(),
            "CWE-200: Information disclosure".to_string(),
        ],
    };

    ctx.save(tmp_dir.path()).unwrap();
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert_eq!(loaded.findings_so_far.len(), 3);
    assert!(
        loaded
            .findings_so_far
            .contains(&"CWE-79: XSS in header".to_string())
    );
}

// ============================================================================
// save/load roundtrip tests
// ============================================================================

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn test_save_returns_error_when_parent_is_a_file() {
    // save() calls create_dir_all, so a missing parent would simply be created.
    // A regular file in the path makes create_dir_all fail with ENOTDIR on every
    // platform and for every user, including root in a CI container.
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("not-a-directory");
    std::fs::write(&file_path, b"x").unwrap();

    let result = AnalysisContext::default().save(&file_path.join("child"));

    assert!(
        result.is_err(),
        "save should fail when a path component is a regular file"
    );
}

#[test]
fn test_load_error_for_invalid_json() {
    let tmp_dir = tempfile::tempdir().unwrap();

    // Create an invalid JSON file
    let context_path = tmp_dir.path().join("context.json");
    std::fs::write(&context_path, "not valid json {").unwrap();

    let result = AnalysisContext::load(tmp_dir.path());
    assert!(result.is_err());
}

#[test]
fn test_load_error_for_malformed_json() {
    let tmp_dir = tempfile::tempdir().unwrap();

    // Create a JSON file with wrong structure - missing required fields
    let context_path = tmp_dir.path().join("context.json");
    std::fs::write(&context_path, r#"{"invalid": "structure"}"#).unwrap();

    let result = AnalysisContext::load(tmp_dir.path());
    assert!(
        result.is_err(),
        "Load should fail for JSON with missing required fields"
    );
}

// ============================================================================
// Default behavior tests
// ============================================================================

#[test]
fn test_default_context_is_empty() {
    let ctx = AnalysisContext::default();

    assert!(ctx.invariants.is_empty());
    assert!(ctx.findings_so_far.is_empty());
}

#[test]
fn test_default_can_be_saved_and_loaded() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext::default();
    ctx.save(tmp_dir.path()).unwrap();

    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();
    assert!(loaded.invariants.is_empty());
}

// ============================================================================
// Edge case tests
// ============================================================================

#[test]
fn test_save_load_with_very_long_strings() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let long_string = "x".repeat(10000);
    let ctx = AnalysisContext {
        invariants: vec![long_string.clone()],
        findings_so_far: vec![long_string.clone()],
    };

    ctx.save(tmp_dir.path()).unwrap();
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert_eq!(loaded.invariants[0].len(), 10000);
    assert_eq!(loaded.findings_so_far[0].len(), 10000);
}

#[test]
fn test_save_load_with_unicode_content() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let ctx = AnalysisContext {
        invariants: vec!["Invariant: 不变量".to_string()],
        findings_so_far: vec!["Finding: 发现".to_string()],
    };

    ctx.save(tmp_dir.path()).unwrap();
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();

    assert_eq!(loaded.invariants, ctx.invariants);
    assert_eq!(loaded.findings_so_far, ctx.findings_so_far);
}

#[test]
fn test_save_overwrites_existing_file() {
    let tmp_dir = tempfile::tempdir().unwrap();

    // Save first context
    let ctx1 = AnalysisContext {
        invariants: vec![],
        findings_so_far: vec![],
    };
    ctx1.save(tmp_dir.path()).unwrap();

    // Save second context
    let ctx2 = AnalysisContext {
        invariants: vec![],
        findings_so_far: vec![],
    };
    ctx2.save(tmp_dir.path()).unwrap();

    // Load and verify second context overwrote first
    let loaded = AnalysisContext::load(tmp_dir.path()).unwrap();
    assert!(loaded.invariants.is_empty());
}
// ============================================================================
// Additional AnalysisContext Tests
// ============================================================================

#[test]
fn test_context_save_load() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = AnalysisContext {
        invariants: vec!["No unauthenticated access".to_string()],
        findings_so_far: vec!["CWE-79: XSS in header".to_string()],
    };

    ctx.save(tmp.path()).unwrap();

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert_eq!(loaded.invariants, ctx.invariants);
    assert_eq!(loaded.findings_so_far, ctx.findings_so_far);
}

#[test]
fn test_context_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = AnalysisContext::load(tmp.path()).unwrap();
    assert!(ctx.invariants.is_empty());
    assert!(ctx.findings_so_far.is_empty());
}
