//! Integration tests for the CWE RAG (Retrieval-Augmented Generation) pipeline.
//!
//! These tests verify the full flow of loading the CWE knowledge base and
//! performing retrieval queries for vulnerability analysis.

use baco::retrieval::CweKnowledgeBase;

#[test]
fn test_full_pipeline_load_and_search() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    assert!(!kb.is_empty(), "Knowledge base should not be empty");

    let results = kb.search("SQL injection vulnerability", 5);
    assert!(!results.is_empty(), "Should find results for SQL injection");

    let first_result = &results[0];
    assert!(
        first_result.cwe_id == "CWE-89" || first_result.name.contains("SQL"),
        "Top result should be related to SQL injection"
    );
}

#[test]
fn test_query_untrusted_input_sql() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "untrusted input concatenated to SQL query";
    let results = kb.search(query, 3);

    assert!(
        !results.is_empty(),
        "Should find relevant CWE for SQL injection query"
    );

    let has_cwe89 = results.iter().any(|d| d.cwe_id == "CWE-89");
    assert!(
        has_cwe89,
        "CWE-89 (SQL Injection) should be in top results for untrusted input SQL query"
    );
}

#[test]
fn test_query_xss_vulnerability() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "cross site scripting user input reflected";
    let results = kb.search(query, 3);

    assert!(
        !results.is_empty(),
        "Should find relevant CWE for XSS query"
    );

    let has_cwe79 = results.iter().any(|d| d.cwe_id == "CWE-79");
    assert!(
        has_cwe79,
        "CWE-79 (XSS) should be found for cross-site scripting query"
    );
}

#[test]
fn test_query_buffer_overflow_memory() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "buffer overflow memory corruption unsafe write";
    let results = kb.search(query, 5);

    assert!(
        !results.is_empty(),
        "Should find relevant CWE for buffer overflow"
    );

    let has_cwe119 = results.iter().any(|d| d.cwe_id == "CWE-119");
    assert!(
        has_cwe119,
        "CWE-119 (Buffer Overflow) should be found for memory corruption query"
    );
}

#[test]
fn test_query_authentication_bypass() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "missing authentication critical function";
    let results = kb.search(query, 5);

    assert!(
        !results.is_empty(),
        "Should find relevant CWE for authentication"
    );

    let has_auth_cwe = results
        .iter()
        .any(|d| d.cwe_id == "CWE-287" || d.cwe_id == "CWE-862" || d.cwe_id == "CWE-306");
    assert!(
        has_auth_cwe,
        "Should find authentication-related CWE (287/862/306)"
    );
}

#[test]
fn test_query_cryptographic_weakness() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "broken cryptographic algorithm weak encryption";
    let results = kb.search(query, 5);

    assert!(!results.is_empty(), "Should find relevant CWE for crypto");

    let has_cwe327 = results.iter().any(|d| d.cwe_id == "CWE-327");
    assert!(
        has_cwe327,
        "CWE-327 (Broken Crypto) should be found for cryptographic query"
    );
}

#[test]
fn test_retrieval_preserves_document_integrity() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let results = kb.search("SQL injection", 1);
    assert_eq!(results.len(), 1, "Should return exactly 1 result");

    let doc = &results[0];
    assert!(!doc.name.is_empty(), "Document should have a name");
    assert!(
        !doc.description.is_empty(),
        "Document should have a description"
    );
    assert!(!doc.examples.is_empty(), "Document should have examples");
    assert!(
        !doc.mitigation.is_empty(),
        "Document should have mitigation"
    );
}

#[test]
fn test_multiple_queries_consistency() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let queries = vec![
        "SQL injection",
        "cross site scripting",
        "path traversal",
        "command injection",
        "buffer overflow",
    ];

    for query in queries {
        let results = kb.search(query, 3);
        assert!(
            !results.is_empty(),
            "Query '{}' should return results",
            query
        );
    }
}

#[test]
fn test_knowledge_base_cwe_coverage() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let expected_cwes = vec![
        "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-119", "CWE-20", "CWE-125", "CWE-787",
        "CWE-352", "CWE-434", "CWE-502", "CWE-287", "CWE-862", "CWE-863", "CWE-732", "CWE-306",
        "CWE-200", "CWE-201", "CWE-798", "CWE-327",
    ];

    let ids = kb.get_cwe_ids();
    for expected in expected_cwes {
        assert!(
            ids.contains(&expected),
            "Knowledge base should contain {}",
            expected
        );
    }
}

#[test]
fn test_search_with_various_k_values() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load CWE knowledge base");

    let query = "injection vulnerability";

    let results_k1 = kb.search(query, 1);
    assert_eq!(results_k1.len(), 1, "k=1 should return 1 result");

    let results_k5 = kb.search(query, 5);
    assert!(results_k5.len() <= 5, "k=5 should return at most 5 results");

    let results_k10 = kb.search(query, 10);
    assert!(
        results_k10.len() <= 10,
        "k=10 should return at most 10 results"
    );
}
