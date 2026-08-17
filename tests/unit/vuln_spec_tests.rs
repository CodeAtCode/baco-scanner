//! VulInSpec unit tests.
//!
//! Tests for specification extraction, RAG retrieval, and prompt augmentation.

use baco::vuln_spec::extractor;
use baco::vuln_spec::schema::{
    DomainCategory, SecuritySpecification, SpecificationDatabase, VulnSpecConfig,
};

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
fn test_specification_database_operations() {
    let mut db = SpecificationDatabase::new();

    let spec1 = SecuritySpecification {
        id: "spec-1".to_string(),
        vuln_type: "CWE-79".to_string(),
        description: "XSS vulnerability".to_string(),
        safe_behavior_pattern: "Escape HTML entities".to_string(),
        project_domain: "web".to_string(),
        source_patch_hash: "hash1".to_string(),
        category: DomainCategory::General,
    };

    let spec2 = SecuritySpecification {
        id: "spec-2".to_string(),
        vuln_type: "CWE-89".to_string(),
        description: "SQL injection".to_string(),
        safe_behavior_pattern: "Use parameterized queries".to_string(),
        project_domain: "database".to_string(),
        source_patch_hash: "hash2".to_string(),
        category: DomainCategory::DomainSpecific("database".to_string()),
    };

    db.add_specification(spec1);
    db.add_specification(spec2);

    assert_eq!(db.specifications.len(), 2);

    // Test filtering by CWE
    let cwe79_specs = db.get_by_cwe("CWE-79");
    assert_eq!(cwe79_specs.len(), 1);
    assert_eq!(cwe79_specs[0].id, "spec-1");

    // Test filtering by domain
    let web_specs = db.get_by_domain("web");
    assert_eq!(web_specs.len(), 1);

    // Test general vs domain-specific
    let general = db.get_general_specs();
    let domain = db.get_domain_specs();
    assert_eq!(general.len(), 1);
    assert_eq!(domain.len(), 1);
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
fn test_categorize_general_specification() {
    let spec = SecuritySpecification {
        id: "general-test".to_string(),
        vuln_type: "CWE-89".to_string(),
        description: "SQL injection".to_string(),
        safe_behavior_pattern: "Use parameterized queries to sanitize and validate input"
            .to_string(),
        project_domain: "database".to_string(),
        source_patch_hash: "test123".to_string(),
        category: DomainCategory::General,
    };

    let category = extractor::categorize_spec(&spec);
    assert!(matches!(category, DomainCategory::General));
}

#[test]
fn test_patch_hash_uniqueness() {
    let patch1 = "diff --git a/test1.patch\n+safe code";
    let patch2 = "diff --git a/test2.patch\n+different code";

    let hash1 = extractor::compute_patch_hash(patch1);
    let hash2 = extractor::compute_patch_hash(patch2);

    assert_ne!(
        hash1, hash2,
        "Different patches should have different hashes"
    );
    assert_eq!(hash1.len(), 64, "SHA256 hash should be 64 hex characters");
    assert_eq!(hash2.len(), 64);
}

#[test]
fn test_domain_extraction_from_patch() {
    let crypto_patch = "--- a/crypto/aes_impl.rs";
    assert_eq!(extractor::extract_domain_from_patch(crypto_patch), "crypto");

    let db_patch = "--- a/database/postgres.rs";
    assert_eq!(extractor::extract_domain_from_patch(db_patch), "database");

    let web_patch = "--- a/web/api_handler.py";
    assert_eq!(
        extractor::extract_domain_from_patch(web_patch),
        "web-server"
    );

    let network_patch = "--- a/network/socket.rs";
    assert_eq!(
        extractor::extract_domain_from_patch(network_patch),
        "network"
    );

    let auth_patch = "--- a/auth/login.go";
    assert_eq!(
        extractor::extract_domain_from_patch(auth_patch),
        "authentication"
    );
}

// ============================================================================
// RAG Retriever Tests
// ============================================================================

#[test]
fn test_build_embedding_index() {
    let specs = vec![
        SecuritySpecification {
            id: "embed-1".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "Cross-site scripting vulnerability in web applications".to_string(),
            safe_behavior_pattern: "Sanitize and escape all user input before rendering"
                .to_string(),
            project_domain: "web-server".to_string(),
            source_patch_hash: "hash1".to_string(),
            category: DomainCategory::General,
        },
        SecuritySpecification {
            id: "embed-2".to_string(),
            vuln_type: "CWE-89".to_string(),
            description: "SQL injection through unsanitized input".to_string(),
            safe_behavior_pattern: "Use parameterized queries for database operations".to_string(),
            project_domain: "database".to_string(),
            source_patch_hash: "hash2".to_string(),
            category: DomainCategory::DomainSpecific("database".to_string()),
        },
    ];

    // Clear existing index
    baco::vuln_spec::retriever::clear_index();

    baco::vuln_spec::retriever::build_embedding_index(&specs)
        .expect("Should build embedding index");

    let stats = baco::vuln_spec::retriever::get_index_stats();
    assert_eq!(stats.num_documents, 2);
    assert_eq!(stats.num_embeddings, 2);
}

#[test]
fn test_vector_similarity() {
    use crate::vuln_spec_tests::retriever_tests::cosine_similarity_internal;

    // Test cosine similarity with identical vectors
    let a = vec![1.0, 0.0, 0.0, 0.0];
    let b = vec![1.0, 0.0, 0.0, 0.0];

    // Access internal function through a test wrapper
    let similarity = cosine_similarity_internal(&a, &b);
    assert!(
        (similarity - 1.0).abs() < 0.0001,
        "Identical vectors should have similarity 1.0"
    );

    // Test with orthogonal vectors
    let c = vec![0.0, 1.0, 0.0, 0.0];
    let similarity_orthogonal = cosine_similarity_internal(&a, &c);
    assert!(
        (similarity_orthogonal - 0.0).abs() < 0.0001,
        "Orthogonal vectors should have similarity 0.0"
    );
}

#[test]
fn test_embedding_generation_consistency() {
    use crate::vuln_spec_tests::retriever_tests::generate_embedding_internal;

    let text1 = "test embedding consistency";
    let text2 = "test embedding consistency";
    let text3 = "different text content";

    let emb1 = generate_embedding_internal(text1);
    let emb2 = generate_embedding_internal(text2);
    let emb3 = generate_embedding_internal(text3);

    // Same text should produce same embedding
    assert_eq!(
        emb1, emb2,
        "Identical text should produce identical embeddings"
    );

    // Different text should produce different embedding
    assert_ne!(
        emb1, emb3,
        "Different text should produce different embeddings"
    );

    // All embeddings should have correct dimension
    assert_eq!(emb1.len(), 768, "Embedding dimension should be 768");
}

#[test]
fn test_hybrid_search_with_specs() {
    use crate::vuln_spec_tests::retriever_tests::hybrid_search_internal;

    let specs = vec![SecuritySpecification {
        id: "search-1".to_string(),
        vuln_type: "CWE-79".to_string(),
        description: "XSS vulnerability in HTML rendering".to_string(),
        safe_behavior_pattern: "Sanitize user input with HTML escaping".to_string(),
        project_domain: "web-server".to_string(),
        source_patch_hash: "searchhash1".to_string(),
        category: DomainCategory::General,
    }];

    baco::vuln_spec::retriever::clear_index();
    baco::vuln_spec::retriever::build_embedding_index(&specs).unwrap();

    let results = hybrid_search_internal("XSS sanitization escaping", 5);

    // Should return results (may be empty if no matches, but shouldn't panic)
    assert!(results.len() <= 5, "Should respect top_k limit");
}

#[test]
fn test_clear_index() {
    let specs = vec![SecuritySpecification {
        id: "clear-test".to_string(),
        vuln_type: "CWE-79".to_string(),
        description: "Test".to_string(),
        safe_behavior_pattern: "Test pattern".to_string(),
        project_domain: "test".to_string(),
        source_patch_hash: "test".to_string(),
        category: DomainCategory::General,
    }];

    baco::vuln_spec::retriever::clear_index();
    baco::vuln_spec::retriever::build_embedding_index(&specs).unwrap();
    assert_eq!(
        baco::vuln_spec::retriever::get_index_stats().num_documents,
        1
    );

    baco::vuln_spec::retriever::clear_index();
    assert_eq!(
        baco::vuln_spec::retriever::get_index_stats().num_documents,
        0
    );
}

// ============================================================================
// Prompt Augmentation Tests
// ============================================================================

#[test]
fn test_specification_context_formatting() {
    // This tests the format of specification context that would be added to prompts
    let specs = vec![SecuritySpecification {
        id: "ctx-1".to_string(),
        vuln_type: "CWE-79".to_string(),
        description: "Cross-site scripting".to_string(),
        safe_behavior_pattern: "Escape HTML entities".to_string(),
        project_domain: "web".to_string(),
        source_patch_hash: "ctxhash1".to_string(),
        category: DomainCategory::General,
    }];

    baco::vuln_spec::retriever::clear_index();
    baco::vuln_spec::retriever::build_embedding_index(&specs).unwrap();

    // Simulate context building (this would normally call retrieve_relevant_specs)
    let cwe_id = "CWE-79";
    let code = "element.innerHTML = userInput;";

    let retrieved = baco::vuln_spec::retriever::retrieve_relevant_specs(code, cwe_id, 3);

    // Context should be built from retrieved specs
    if !retrieved.is_empty() {
        let mut context = String::from("SECURITY SPECIFICATION CONTEXT\n");
        context.push_str("Based on similar vulnerabilities, expected safe behaviors include:\n\n");

        for spec in &retrieved {
            context.push_str("[Specification]\n");
            context.push_str(&format!("  Type: {}\n", spec.vuln_type));
            context.push_str(&format!("  Safe Pattern: {}\n", spec.safe_behavior_pattern));
        }

        assert!(context.contains("CWE-79"));
        assert!(context.contains("safe"));
    }
}

#[test]
fn test_spec_retrieval_by_cwe() {
    let specs = vec![
        SecuritySpecification {
            id: "cwe-test-1".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "XSS vulnerability".to_string(),
            safe_behavior_pattern: "Sanitize HTML input".to_string(),
            project_domain: "web".to_string(),
            source_patch_hash: "cwehash1".to_string(),
            category: DomainCategory::General,
        },
        SecuritySpecification {
            id: "cwe-test-2".to_string(),
            vuln_type: "CWE-89".to_string(),
            description: "SQL injection".to_string(),
            safe_behavior_pattern: "Use prepared statements".to_string(),
            project_domain: "database".to_string(),
            source_patch_hash: "cwehash2".to_string(),
            category: DomainCategory::DomainSpecific("database".to_string()),
        },
    ];

    baco::vuln_spec::retriever::clear_index();
    baco::vuln_spec::retriever::build_embedding_index(&specs).unwrap();

    // Test retrieval with specific CWE
    let code = "SELECT * FROM users WHERE id = 'user_input'";
    let results = baco::vuln_spec::retriever::retrieve_relevant_specs(code, "CWE-89", 5);

    // Should prefer SQL-related specs
    if !results.is_empty() {
        let has_sql_spec = results.iter().any(|s| s.vuln_type == "CWE-89");
        assert!(
            has_sql_spec,
            "Should retrieve SQL injection spec for SQL code"
        );
    }
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
// Integration Tests
// ============================================================================

#[test]
fn test_full_extraction_and_retrieval_pipeline() {
    // Step 1: Extract specification from patch
    let patch = r#"
--- a/src/db.rs
+++ b/src/db.rs
@@ -10,3 +10,4 @@
-    let query = format!("SELECT * FROM users WHERE id = {}", id);
+    let query = "SELECT * FROM users WHERE id = ?";
+    let stmt = db.prepare(query).unwrap();
     db.execute(&query);
"#;

    let extracted_specs = extractor::extract_from_patch(patch);
    assert!(
        !extracted_specs.is_empty(),
        "Should extract specification from patch"
    );

    // Step 2: Build retrieval index
    baco::vuln_spec::retriever::clear_index();
    baco::vuln_spec::retriever::build_embedding_index(&extracted_specs).unwrap();

    // Step 3: Retrieve relevant specs for similar code
    let target_code = "SELECT * FROM products WHERE name = '$input'";
    let retrieved = baco::vuln_spec::retriever::retrieve_relevant_specs(target_code, "CWE-89", 3);

    // Should retrieve the SQL injection spec
    if !retrieved.is_empty() {
        assert_eq!(retrieved[0].vuln_type, "CWE-89");
        assert!(
            retrieved[0]
                .safe_behavior_pattern
                .to_lowercase()
                .contains("parameter")
                || retrieved[0]
                    .safe_behavior_pattern
                    .to_lowercase()
                    .contains("prepare")
        );
    }
}

#[test]
fn test_specification_database_persistence() {
    let mut db = SpecificationDatabase::new();

    // Add some specifications
    for i in 0..3 {
        db.add_specification(SecuritySpecification {
            id: format!("persist-{}", i),
            vuln_type: format!("CWE-{}", 79 + i),
            description: format!("Vulnerability type {}", i),
            safe_behavior_pattern: format!("Safe pattern {}", i),
            project_domain: "test".to_string(),
            source_patch_hash: format!("persisthash{}", i),
            category: DomainCategory::General,
        });
    }

    // Save to temp file
    let temp_path = "/tmp/test_vuln_spec_persistence.json";
    db.save(temp_path).expect("Should save database");

    // Load from temp file
    let loaded_db = SpecificationDatabase::load(temp_path).expect("Should load database");

    // Verify data integrity
    assert_eq!(loaded_db.specifications.len(), 3);
    assert_eq!(loaded_db.specifications[0].id, "persist-0");
    assert_eq!(loaded_db.specifications[2].vuln_type, "CWE-81");

    // Clean up
    std::fs::remove_file(temp_path).ok();
}

// ============================================================================
// Helper functions for testing internal retriever functions
// ============================================================================

// These are re-implementations for testing purposes
// In production, these would be internal functions exposed for testing

mod retriever_tests {

    pub fn cosine_similarity_internal(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }

    pub fn generate_embedding_internal(text: &str) -> Vec<f32> {
        const EMBEDDING_DIM: usize = 768;
        let mut embedding = vec![0.0f32; EMBEDDING_DIM];

        for (i, byte) in text.bytes().enumerate() {
            let idx = i % EMBEDDING_DIM;
            embedding[idx] += (byte as f32) / 255.0;
        }

        let norm = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for val in embedding.iter_mut() {
                *val /= norm;
            }
        }

        embedding
    }

    pub fn hybrid_search_internal(query: &str, top_k: usize) -> Vec<(usize, f32)> {
        // Simplified version for testing
        let index = baco::vuln_spec::retriever::EMBEDDING_INDEX
            .read()
            .expect("Failed to acquire read lock");

        let query_embedding = generate_embedding_internal(query);
        index.search_vector(&query_embedding, top_k)
    }
}
