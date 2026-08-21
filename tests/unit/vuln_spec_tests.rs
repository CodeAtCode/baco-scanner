//! VulInSpec unit tests.
//!
//! Tests for specification extraction, RAG retrieval, and prompt augmentation.

use baco::vuln_spec::extractor;
use baco::vuln_spec::schema::{DomainCategory, SecuritySpecification, VulnSpecConfig};

// ============================================================================
// Schema Tests
// ============================================================================

#[test]
fn test_security_specification_creation() {
    let spec = SecuritySpecification {
        id: "test-spec-001".to_string(),
        vuln_type: "CWE-79".to_string(),
        description: "Cross-site scripting vulnerability in user input handling".to_string(),
        safe_behavior_pattern: "Sanitize all user input before rendering to HTML".to_string(),
        project_domain: "web-server".to_string(),
        source_patch_hash: "abc123def456".to_string(),
        category: DomainCategory::General,
    };

    assert_eq!(spec.id, "test-spec-001");
    assert_eq!(spec.vuln_type, "CWE-79");
    assert!(matches!(spec.category, DomainCategory::General));
    assert!(spec
        .safe_behavior_pattern
        .to_lowercase()
        .contains("sanitize"));
}

#[test]
fn test_vuln_spec_config_defaults() {
    let config = VulnSpecConfig::default();

    assert!(!config.enabled, "Should be disabled by default");
    assert_eq!(config.db_path, "baco-output/vuln_spec_db.json");
    assert!(!config.auto_extract_from_patches);
}

#[test]
fn test_specification_serialization() {
    let spec = SecuritySpecification {
        id: "serialize-test".to_string(),
        vuln_type: "CWE-125".to_string(),
        description: "Out-of-bounds read".to_string(),
        safe_behavior_pattern: "Validate array bounds before access".to_string(),
        project_domain: "general".to_string(),
        source_patch_hash: "xyz789".to_string(),
        category: DomainCategory::General,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&spec).unwrap();
    assert!(json.contains("serialize-test"));
    assert!(json.contains("CWE-125"));

    // Deserialize from JSON
    let deserialized: SecuritySpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, spec.id);
    assert_eq!(deserialized.vuln_type, spec.vuln_type);
}

// ============================================================================
// Extractor Tests
// ============================================================================

#[test]
fn test_extract_sql_injection_specification() {
    let patch = r#"
--- a/src/database.rs
+++ b/src/database.rs
@@ -15,5 +15,6 @@
-    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
-    db.execute(&query);
+    let query = "SELECT * FROM users WHERE id = ?";
+    let stmt = db.prepare(query).unwrap();
+    stmt.execute(&[user_id]).unwrap();
"#;

    let specs = extractor::extract_from_patch(patch);

    assert!(
        !specs.is_empty(),
        "Should extract at least one specification"
    );

    let spec = &specs[0];
    assert_eq!(spec.vuln_type, "CWE-89", "Should identify SQL injection");
    assert!(
        spec.safe_behavior_pattern.contains("parameterized")
            || spec.safe_behavior_pattern.contains("prepare"),
        "Safe pattern should mention parameterized queries"
    );
    assert_eq!(spec.project_domain, "database");
}

#[test]
fn test_extract_xss_specification() {
    let patch = r#"
--- a/src/web/handler.js
+++ b/src/web/handler.js
@@ -22,3 +22,4 @@
-    element.innerHTML = userInput;
+    // Sanitize input before rendering
+    element.textContent = escapeHtml(userInput);
"#;

    let specs = extractor::extract_from_patch(patch);

    assert!(!specs.is_empty(), "Should extract XSS specification");

    let spec = &specs[0];
    assert_eq!(spec.vuln_type, "CWE-79", "Should identify XSS");
    assert_eq!(spec.project_domain, "web-server");
    assert!(
        spec.safe_behavior_pattern
            .to_lowercase()
            .contains("sanitiz")
            || spec.safe_behavior_pattern.to_lowercase().contains("escap")
    );
}

#[test]
fn test_extract_buffer_overflow_specification() {
    let patch = r#"
--- a/src/memory.c
+++ b/src/memory.c
@@ -10,3 +10,4 @@
-    strcpy(dest, src);
+    // Validate buffer size before copy
+    strncpy(dest, src, sizeof(dest) - 1);
+    dest[sizeof(dest) - 1] = '\0';
"#;

    let specs = extractor::extract_from_patch(patch);

    assert!(
        !specs.is_empty(),
        "Should extract buffer overflow specification"
    );

    let spec = &specs[0];
    assert_eq!(
        spec.vuln_type, "CWE-120",
        "Should identify buffer copy issue"
    );
    // Check that a pattern was generated
    assert!(
        !spec.safe_behavior_pattern.is_empty(),
        "Safe pattern should not be empty"
    );
}

#[test]
fn test_mock_llm_response_parsing() {
    // Test that we can parse LLM responses with specification context
    let mock_response = r#"{
        "description": "This code has a cross-site scripting vulnerability because user input is directly rendered",
        "fix_code": "element.textContent = escapeHtml(userInput);"
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(mock_response).unwrap();

    assert_eq!(
        parsed.get("description").unwrap().as_str().unwrap(),
        "This code has a cross-site scripting vulnerability because user input is directly rendered"
    );
    assert_eq!(
        parsed.get("fix_code").unwrap().as_str().unwrap(),
        "element.textContent = escapeHtml(userInput);"
    );
}
