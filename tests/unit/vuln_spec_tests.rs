//! VulInSpec unit tests.
//!
//! Tests for specification extraction, RAG retrieval, and prompt augmentation.

use baco::vuln_spec::extractor;
use baco::vuln_spec::retriever;
use baco::vuln_spec::schema::{DomainCategory, SecuritySpecification, VulnSpecConfig};
use std::io::Write;

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

// ============================================================================
// Retriever Tests
// ===========================================================================

#[cfg(test)]
mod retriever_tests {
    use super::*;
    use std::sync::Mutex;

    static INDEX_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_retrieve_relevant_specs_after_build() {
        let _guard = INDEX_LOCK.lock().unwrap();

        // Clear index first
        retriever::clear_index();

        let spec = SecuritySpecification {
            id: "test-retrieve-001".to_string(),
            vuln_type: "CWE-89".to_string(),
            description: "SQL injection vulnerability in database queries".to_string(),
            safe_behavior_pattern: "Use parameterized queries to prevent SQL injection".to_string(),
            project_domain: "database".to_string(),
            source_patch_hash: "test123".to_string(),
            category: DomainCategory::DomainSpecific("database".to_string()),
        };

        // Build index with one spec
        retriever::build_embedding_index(std::slice::from_ref(&spec)).unwrap();

        // Retrieve with matching query
        let results =
            retriever::retrieve_relevant_specs("SELECT * FROM users WHERE id = ?", "CWE-89", 5);

        // Should return non-empty results containing our spec
        assert!(!results.is_empty(), "Should retrieve relevant specs");
        assert!(
            results.iter().any(|s| s.id == spec.id),
            "Should contain the spec we added"
        );
    }

    #[test]
    fn test_initialize_spec_index_with_temp_file() {
        let _guard = INDEX_LOCK.lock().unwrap();

        // Clear index first
        retriever::clear_index();

        // Create temp file with specs
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_vuln_spec_db.json");

        let specs = vec![
            SecuritySpecification {
                id: "init-test-1".to_string(),
                vuln_type: "CWE-79".to_string(),
                description: "XSS vulnerability".to_string(),
                safe_behavior_pattern: "Sanitize input".to_string(),
                project_domain: "web".to_string(),
                source_patch_hash: "hash1".to_string(),
                category: DomainCategory::General,
            },
            SecuritySpecification {
                id: "init-test-2".to_string(),
                vuln_type: "CWE-89".to_string(),
                description: "SQL injection".to_string(),
                safe_behavior_pattern: "Use parameterized queries".to_string(),
                project_domain: "database".to_string(),
                source_patch_hash: "hash2".to_string(),
                category: DomainCategory::DomainSpecific("database".to_string()),
            },
        ];

        // Write specs to temp file
        let json = serde_json::to_string(&specs).unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        file.write_all(json.as_bytes()).unwrap();

        // Initialize index
        let config = VulnSpecConfig {
            enabled: true,
            db_path: db_path.to_string_lossy().to_string(),
            auto_extract_from_patches: false,
        };

        let count = baco::vuln_spec::initialize_spec_index(&config);

        assert_eq!(count, 2, "Should load 2 specs from file");

        // Verify retrieval works
        let stats = retriever::get_index_stats();
        assert_eq!(stats.num_documents, 2);
    }

    #[test]
    fn test_extract_and_add_specs_to_index() {
        let _guard = INDEX_LOCK.lock().unwrap();

        // Clear index first
        retriever::clear_index();

        let patch = r#"--- a/src/crypto.rs
+++ b/src/crypto.rs
@@ -10,5 +10,6 @@
-    let query = format!("SELECT * FROM secrets WHERE key = {}", user_input);
-    db.execute(&query);
+    let query = "SELECT * FROM secrets WHERE key = ?";
+    let stmt = db.prepare(query).unwrap();
+    stmt.execute(&[user_input]).unwrap();
"#;

        // Extract specs from patch
        let specs = extractor::extract_from_patch(patch);
        assert!(!specs.is_empty(), "Should extract at least one spec");

        // Add to index
        let count = retriever::add_specs_to_index(&specs).unwrap();
        assert!(count > 0, "Should add specs to index");

        // Verify retrieval works
        let stats = retriever::get_index_stats();
        assert!(stats.num_documents > 0, "Index should have documents");

        // Try to retrieve
        let results =
            retriever::retrieve_relevant_specs("SELECT * FROM secrets WHERE key", "CWE-89", 5);
        assert!(!results.is_empty(), "Should retrieve the added spec");
    }
}
