//! Unit tests for retrieval module - CweKnowledgeBase and BM25 edge cases.

use baco::retrieval::{
    Bm25Index, CweDocument, CweKnowledgeBase, IndexedCweDocument, RetrievalError,
};

// ============================================================================
// CweKnowledgeBase: len() and is_empty() tests
// ============================================================================

#[test]
fn test_kb_len_returns_correct_count() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let count = kb.len();
    assert!(count >= 20, "Should have at least 20 documents");
}

#[test]
fn test_kb_is_empty_false_when_loaded() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    assert!(!kb.is_empty(), "Loaded KB should not be empty");
}

#[test]
fn test_kb_is_empty_true_for_empty_json() {
    let result = CweKnowledgeBase::load_from_json(r#"{"cwe_specifications": []}"#);
    assert!(result.is_err());
    let kb_err = result.unwrap_err();

    // load_from_json returns Empty error for empty cwe_specifications
    assert!(matches!(kb_err, RetrievalError::Empty));
}

// ============================================================================
// CweKnowledgeBase: get_cwe_ids() tests
// ============================================================================

#[test]
fn test_get_cwe_ids_returns_all_ids() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let ids = kb.get_cwe_ids();

    assert!(!ids.is_empty());
    assert!(ids.len() >= 20);
}

#[test]
fn test_get_cwe_ids_contains_expected_cwes() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let ids = kb.get_cwe_ids();

    assert!(ids.contains(&"CWE-79"));
    assert!(ids.contains(&"CWE-89"));
    assert!(ids.contains(&"CWE-22"));
    assert!(ids.contains(&"CWE-119"));
    assert!(ids.contains(&"CWE-78"));
    assert!(ids.contains(&"CWE-798"));
}

#[test]
fn test_get_cwe_ids_all_unique() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let ids = kb.get_cwe_ids();
    let unique_count = ids.iter().collect::<std::collections::HashSet<_>>().len();

    assert_eq!(unique_count, ids.len(), "All CWE IDs should be unique");
}

// ============================================================================
// CweKnowledgeBase: load_from_json() with valid JSON
// ============================================================================

#[test]
fn test_load_from_json_valid_single_doc() {
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-TEST-1",
                "name": "Test Vulnerability",
                "description": "A test vulnerability for testing",
                "examples": ["Example 1", "Example 2"],
                "mitigation": "Use proper validation"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).expect("Should load valid JSON");
    assert!(!kb.is_empty());
    assert_eq!(kb.len(), 1);

    let ids = kb.get_cwe_ids();
    assert!(ids.contains(&"CWE-TEST-1"));
}

#[test]
fn test_load_from_json_multiple_documents() {
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-A",
                "name": "First",
                "description": "First vulnerability",
                "examples": [],
                "mitigation": "Fix it"
            },
            {
                "cwe_id": "CWE-B",
                "name": "Second",
                "description": "Second vulnerability",
                "examples": [],
                "mitigation": "Fix it too"
            },
            {
                "cwe_id": "CWE-C",
                "name": "Third",
                "description": "Third vulnerability",
                "examples": [],
                "mitigation": "Also fix"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).unwrap();
    assert_eq!(kb.len(), 3);

    let ids = kb.get_cwe_ids();
    assert!(ids.contains(&"CWE-A"));
    assert!(ids.contains(&"CWE-B"));
    assert!(ids.contains(&"CWE-C"));
}

#[test]
fn test_load_from_json_empty_examples_array() {
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-EMPTY",
                "name": "No Examples",
                "description": "Description without examples",
                "examples": [],
                "mitigation": "Mitigation"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).unwrap();
    assert_eq!(kb.len(), 1);
}

// ============================================================================
// CweKnowledgeBase: search() edge cases
// ============================================================================

#[test]
fn test_search_k_zero_returns_empty() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("sql injection", 0);
    assert!(results.is_empty(), "k=0 should return no results");
}

#[test]
fn test_search_k_larger_than_available() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("vulnerability", 1000);

    assert!(!results.is_empty());
    assert!(results.len() <= kb.len());
}

#[test]
fn test_search_whitespace_only_query() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("   \t\n   ", 10);
    assert!(
        results.is_empty(),
        "Whitespace-only query should return no results"
    );
}

#[test]
fn test_search_partial_term_match() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("injection", 5);

    assert!(!results.is_empty());
}

#[test]
fn test_search_multiple_terms() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("sql injection prevention", 3);

    assert!(!results.is_empty());
    let has_cwe89 = results.iter().any(|d| d.cwe_id == "CWE-89");
    assert!(has_cwe89);
}

#[test]
fn test_search_case_insensitive() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();

    let results_upper = kb.search("SQL INJECTION", 1);
    let results_lower = kb.search("sql injection", 1);
    let results_mixed = kb.search("Sql InJeCtIoN", 1);

    assert_eq!(results_upper.len(), results_lower.len());
    assert_eq!(results_lower.len(), results_mixed.len());
}

// ============================================================================
// Bm25Index: parameter variations
// ============================================================================

#[test]
fn test_bm25_high_k1_boostes_term_frequency() {
    let docs = vec![
        "sql sql sql injection injection",
        "sql injection",
        "injection sql",
    ];

    // High k1 means term frequency matters more
    let index = Bm25Index::new(docs, 2.0, 0.75);
    let results = index.search("sql", 3);

    assert!(!results.is_empty());
    // First doc has most "sql" occurrences
    assert_eq!(results[0], 0);
}

#[test]
fn test_bm25_low_b_less_length_normalization() {
    let docs = vec![
        "sql injection vulnerability in database application code",
        "sql injection",
    ];

    // Low b means length normalization has less effect
    let index = Bm25Index::new(docs, 1.2, 0.1);
    let results = index.search("sql injection", 2);

    assert_eq!(results.len(), 2);
}

#[test]
fn test_bm25_high_b_stronger_length_normalization() {
    let docs = vec![
        "sql injection",
        "sql injection vulnerability in database application code with many words",
    ];

    // High b means length normalization has more effect
    let index = Bm25Index::new(docs, 1.2, 0.9);
    let results = index.search("sql injection", 2);

    assert_eq!(results.len(), 2);
}

#[test]
fn test_bm25_zero_k1_no_term_frequency_boost() {
    let docs = vec!["sql sql sql sql injection", "sql injection"];

    // k1=0 means no term frequency boost
    let index = Bm25Index::new(docs, 0.0, 0.75);
    let results = index.search("sql", 2);

    assert_eq!(results.len(), 2);
}

// ============================================================================
// Bm25Index: edge cases with special characters and unicode
// ============================================================================

#[test]
fn test_bm25_unicode_characters() {
    let docs = vec![
        "vulnerabilité dans le système",
        "seguridad en la aplicación",
        "security vulnerability",
    ];

    let index = Bm25Index::new(docs, 1.2, 0.75);

    // Should handle unicode without panicking
    let results = index.search("vulnerability", 3);
    assert!(!results.is_empty());
}

#[test]
fn test_bm25_special_characters_in_text() {
    let docs = vec![
        "SQLi: SQL Injection (common vulnerability)",
        "XSS <script>alert('xss')</script>",
        "Path Traversal: ../../../etc/passwd",
    ];

    let index = Bm25Index::new(docs, 1.2, 0.75);

    let results_sqli = index.search("sqli", 3);
    assert!(!results_sqli.is_empty());
    assert_eq!(results_sqli[0], 0);
}

#[test]
fn test_bm25_very_long_document() {
    let long_text = "security vulnerability ".repeat(100);
    let docs = vec!["short", &long_text, "medium length document with security"];

    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("security vulnerability", 3);

    assert_eq!(results.len(), 2); // Only 2 docs match
    assert_eq!(results[0], 1); // Long doc should rank higher
}

#[test]
fn test_bm25_many_documents() {
    let docs: Vec<&str> = (0..100)
        .map(|i| {
            if i == 50 {
                "sql injection vulnerability here"
            } else {
                "random unrelated content number"
            }
        })
        .collect();

    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("sql injection", 10);

    assert!(!results.is_empty());
    assert_eq!(results[0], 50); // The matching doc should be first
}

// ============================================================================
// Bm25Index: search behavior verification
// ============================================================================

#[test]
fn test_bm25_search_excludes_non_matching_docs() {
    let docs = vec![
        "hello world test document",
        "completely unrelated content xyz",
    ];
    let index = Bm25Index::new(docs, 1.2, 0.75);

    // Only first doc should match
    let results = index.search("hello world", 2);
    assert_eq!(results, vec![0]);
}

#[test]
fn test_bm25_search_term_frequency_affects_ranking() {
    let docs = vec!["test document", "test test document test"];
    let index = Bm25Index::new(docs, 1.2, 0.75);

    // Second doc has more "test" occurrences, should rank higher
    let results = index.search("test", 2);
    assert_eq!(results[0], 1);
}

// ============================================================================
// Struct tests: CweDocument and IndexedCweDocument
// ============================================================================

#[test]
fn test_cwe_document_creation() {
    let doc = CweDocument {
        cwe_id: "CWE-TEST".to_string(),
        name: "Test CWE".to_string(),
        description: "A test description".to_string(),
        examples: vec!["Example 1".to_string(), "Example 2".to_string()],
        mitigation: "Use proper input validation".to_string(),
    };

    assert_eq!(doc.cwe_id, "CWE-TEST");
    assert_eq!(doc.examples.len(), 2);
}

#[test]
fn test_indexed_cwe_document_creation() {
    let doc = CweDocument {
        cwe_id: "CWE-INDEXED".to_string(),
        name: "Indexed Test".to_string(),
        description: "Test for indexing".to_string(),
        examples: vec![],
        mitigation: "Fix it".to_string(),
    };

    let indexed = IndexedCweDocument {
        document: doc.clone(),
        search_text: "CWE-INDEXED Indexed Test Test for indexing Fix it".to_string(),
    };

    assert_eq!(indexed.document.cwe_id, "CWE-INDEXED");
    assert!(!indexed.search_text.is_empty());
}

// ============================================================================
// RetrievalError tests
// ============================================================================

#[test]
fn test_retrieval_error_display_json_error() {
    let err = RetrievalError::JsonError("parse failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("JSON error"));
    assert!(display.contains("parse failed"));
}

#[test]
fn test_retrieval_error_display_empty() {
    let err = RetrievalError::Empty;
    let display = format!("{}", err);
    assert!(display.contains("No documents available"));
}

#[test]
fn test_retrieval_error_debug_format() {
    let err = RetrievalError::JsonError("test error".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("JsonError"));
}

// ============================================================================
// Integration: KB search with custom loaded data
// ============================================================================

#[test]
fn test_kb_search_custom_loaded_data() {
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-CUSTOM-1",
                "name": "Buffer Overflow Custom",
                "description": "A custom buffer overflow vulnerability description",
                "examples": ["Overflow example"],
                "mitigation": "Use safe memory operations"
            },
            {
                "cwe_id": "CWE-CUSTOM-2",
                "name": "XSS Custom",
                "description": "A custom cross-site scripting vulnerability",
                "examples": ["Script injection example"],
                "mitigation": "Escape output properly"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).unwrap();

    let buffer_results = kb.search("buffer overflow", 5);
    assert!(!buffer_results.is_empty());
    assert!(buffer_results.iter().any(|d| d.cwe_id == "CWE-CUSTOM-1"));

    let xss_results = kb.search("cross site scripting", 5);
    assert!(!xss_results.is_empty());
    assert!(xss_results.iter().any(|d| d.cwe_id == "CWE-CUSTOM-2"));
}

#[test]
fn test_kb_search_preserves_ranking_across_queries() {
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-RANK-1",
                "name": "SQL Injection Primary",
                "description": "Primary SQL injection vulnerability with database",
                "examples": [],
                "mitigation": "Use parameterized queries"
            },
            {
                "cwe_id": "CWE-RANK-2",
                "name": "SQL Injection Secondary",
                "description": "Secondary SQL related issue",
                "examples": [],
                "mitigation": "Validate input"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).unwrap();
    let results = kb.search("sql injection database", 2);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].cwe_id, "CWE-RANK-1");
}
