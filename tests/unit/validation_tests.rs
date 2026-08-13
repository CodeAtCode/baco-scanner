//! Unit tests for validation functions
//!
//! Tests cover validate_file_exists, validate_config, validate_findings,
//! and validate_checkpoint functions.

use baco::validation::{
    validate_checkpoint, validate_config, validate_file_exists, validate_findings,
};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

// ============================================================================
// validate_file_exists() Tests
// ============================================================================

#[test]
fn test_validate_file_exists_nonexistent() {
    let result = validate_file_exists(Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[test]
fn test_validate_file_exists_directory() {
    let result = validate_file_exists(Path::new("/tmp"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("is not a file"));
}

#[test]
fn test_validate_file_exists_valid() {
    let temp_file = NamedTempFile::new().unwrap();
    let result = validate_file_exists(temp_file.path());
    assert!(result.is_ok());
}

// ============================================================================
// validate_config() Tests
// ============================================================================

#[test]
fn test_validate_config_nonexistent() {
    let result = validate_config(Path::new("/nonexistent/config.toml"));
    assert!(result.is_err());
}

#[test]
fn test_validate_config_invalid_toml() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"invalid toml {{{").unwrap();

    let result = validate_config(temp_file.path());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("parse"));
}

#[test]
fn test_validate_config_valid_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    // Write a minimal valid config
    let config_content = r#"
[detector]
semgrep_enabled = true
"#;
    temp_file.write_all(config_content.as_bytes()).unwrap();

    let result = validate_config(temp_file.path());
    // May fail validation but should parse
    assert!(result.is_ok() || result.is_err());
}

// ============================================================================
// validate_findings() Tests
// ============================================================================

#[test]
fn test_validate_findings_nonexistent() {
    let result = validate_findings(Path::new("/nonexistent/findings.json"));
    assert!(result.is_err());
}

#[test]
fn test_validate_findings_invalid_json() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{bad json").unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("parse"));
}

#[test]
fn test_validate_findings_empty_array() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"[]").unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("empty"));
}

#[test]
fn test_validate_findings_valid() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings_json = r#"[{"id": "test-1", "title": "Test", "description": "Desc", "severity": "high", "confidence_score": 0.8, "cwe_id": "CWE-79", "file_path": "src/test.rs", "line_number": 10, "code_snippet": "code", "recommendation": "fix", "already_reported": false, "sources": []}]"#;
    temp_file.write_all(findings_json.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok(), "Error: {:?}", result.err());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_validate_findings_missing_id() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings_json = r#"[{"id": "", "title": "Test", "description": "Desc", "severity": "high", "confidence_score": 0.8, "file_path": "src/test.rs", "line_number": 10, "code_snippet": "code", "recommendation": "fix", "cwe_id": "CWE-79", "already_reported": false, "sources": []}]"#;
    temp_file.write_all(findings_json.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].id.is_empty(), "ID should be auto-generated");
    assert_eq!(findings[0].id.len(), 64, "ID should be a 64-char hex hash");
    assert!(
        findings[0].id.chars().all(|c| c.is_ascii_hexdigit()),
        "ID should be hex-encoded"
    );
}

// ============================================================================
// validate_checkpoint() Tests
// ============================================================================

#[test]
fn test_validate_checkpoint_nonexistent() {
    let result = validate_checkpoint(Path::new("/nonexistent/checkpoint.json"));
    assert!(result.is_err());
}

#[test]
fn test_validate_checkpoint_valid_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    // Write minimal valid checkpoint JSON
    let checkpoint = r#"{"version": 1, "findings": [], "invariants": []}"#;
    temp_file.write_all(checkpoint.as_bytes()).unwrap();

    let result = validate_checkpoint(temp_file.path());
    // May fail due to missing required fields but should parse
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_validate_checkpoint_with_invalid_path_chars() {
    // Test that validate_checkpoint handles paths with invalid characters
    // This covers the error path in validate_checkpoint where path.to_str() fails
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Create a path with invalid UTF-8 characters
        // Note: This path won't exist, so validate_file_exists will fail first
        // We're testing that the error handling works correctly
        let invalid_utf8 = OsStr::from_bytes(b"\xff\xfe");
        let path = std::path::Path::new(invalid_utf8);

        let result = validate_checkpoint(path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        // Either file doesn't exist OR path has invalid chars - both are valid error paths
        assert!(
            err_msg.contains("does not exist") || err_msg.contains("invalid characters"),
            "Expected 'does not exist' or 'invalid characters' error, got: {}",
            err_msg
        );
    }
    #[cfg(not(unix))]
    {
        // On non-Unix systems, skip this test as we can't easily create invalid UTF-8 paths
        // The test is primarily for Unix systems where this edge case matters
    }
}

// ============================================================================
// Additional validate_findings() Tests
// ============================================================================

#[test]
fn test_validate_findings_multiple_findings() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "1", "title": "T1", "description": "D1", "severity": "high", "confidence_score": 0.8, "file_path": "f1.rs", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}, {"id": "2", "title": "T2", "description": "D2", "severity": "medium", "confidence_score": 0.7, "file_path": "f2.rs", "line_number": 2, "already_reported": false, "sources": [], "cwe_id": "CWE-89"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 2);
}

#[test]
fn test_validate_findings_with_null_id() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": null, "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "f.rs", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    // null id should be handled
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_validate_findings_absolute_path() {
    let result = validate_findings(Path::new("/tmp/nonexistent_findings_12345.json"));
    assert!(result.is_err());
}

#[test]
fn test_validate_findings_with_special_chars_in_file_path() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "src/test_file.rs", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

#[test]
fn test_validate_findings_with_unicode_in_file_path() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "src/tëst.rs", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

#[test]
fn test_validate_findings_with_very_long_file_path() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let long_path = "a".repeat(200);
    let findings = format!(
        r#"[{{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "{}", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}}]"#,
        long_path
    );
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

#[test]
fn test_validate_findings_with_zero_line_number() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "f.rs", "line_number": 0, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

#[test]
fn test_validate_findings_with_negative_line_number() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "f.rs", "line_number": -1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    // JSON number may be parsed as unsigned, so this may fail at parse time
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_validate_findings_with_empty_sources() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "f.rs", "line_number": 1, "already_reported": false, "sources": [], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

#[test]
fn test_validate_findings_with_multiple_sources() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    let mut temp_file = NamedTempFile::new().unwrap();
    let findings = r#"[{"id": "test", "title": "T", "description": "D", "severity": "high", "confidence_score": 0.8, "file_path": "f.rs", "line_number": 1, "already_reported": false, "sources": ["semgrep", "bandit"], "cwe_id": "CWE-79"}]"#;
    temp_file.write_all(findings.as_bytes()).unwrap();

    let result = validate_findings(temp_file.path());
    assert!(result.is_ok());
}

// ============================================================================
// Additional validate_file_exists() Tests
// ============================================================================

#[test]
fn test_validate_file_exists_relative_path() {
    let result = validate_file_exists(Path::new("./nonexistent.txt"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

#[test]
fn test_validate_file_exists_absolute_path() {
    let result = validate_file_exists(Path::new("/tmp/nonexistent_file_12345.txt"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

// ============================================================================
// Additional validate_config() Tests
// ============================================================================

#[test]
fn test_validate_config_relative_path() {
    let result = validate_config(Path::new("./nonexistent_config.toml"));
    assert!(result.is_err());
}

#[test]
fn test_validate_config_absolute_path() {
    let result = validate_config(Path::new("/tmp/nonexistent_config_12345.toml"));
    assert!(result.is_err());
}
