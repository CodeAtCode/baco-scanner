//! Unit tests for BM25 search and CWE knowledge base retrieval.

use baco::retrieval::{Bm25Index, CweKnowledgeBase, RetrievalError};

#[test]
fn test_bm25_basic_search_sql_injection() {
    let docs = vec![
        "This document discusses SQL injection vulnerabilities and prevention",
        "Cross-site scripting attacks involve malicious JavaScript in web pages",
        "Buffer overflow occurs when writing beyond allocated memory bounds",
    ];

    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("sql injection", 3);

    assert!(!results.is_empty());
    assert_eq!(results[0], 0, "SQL injection doc should be ranked first");
}

#[test]
fn test_bm25_empty_query_returns_empty() {
    let docs = vec!["test document with some content"];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("", 3);
    assert!(
        results.is_empty(),
        "Empty query should return no results, not panic"
    );
}

#[test]
fn test_bm25_single_doc_match() {
    let docs = vec!["SQL injection is a critical security vulnerability"];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("sql injection", 1);
    assert_eq!(
        results,
        vec![0],
        "Single matching doc should return index 0"
    );
}

#[test]
fn test_cwe_kb_load_embedded_has_20_docs() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load embedded CWE knowledge base");
    assert_eq!(kb.len(), 20, "Should have exactly 20 CWE documents");
}

#[test]
fn test_cwe_kb_search_sql_injection_returns_cwe89() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("sql injection", 3);

    assert!(
        !results.is_empty(),
        "Should find results for sql injection query"
    );
    let has_cwe89 = results.iter().any(|d| d.cwe_id == "CWE-89");
    assert!(
        has_cwe89,
        "CWE-89 should be in top 3 results for SQL injection"
    );
}

#[test]
fn test_cwe_kb_search_cross_site_scripting_returns_cwe79() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("cross site scripting", 1);

    assert!(
        !results.is_empty(),
        "Should find results for cross-site scripting"
    );
    assert_eq!(
        results[0].cwe_id, "CWE-79",
        "CWE-79 should be at rank 0 for cross-site scripting query"
    );
}

#[test]
fn test_cwe_kb_malformed_json_returns_error() {
    let result = CweKnowledgeBase::load_from_json("{ this is not valid json }");

    assert!(result.is_err(), "Should return error for malformed JSON");

    match result {
        Err(RetrievalError::JsonError(_)) => {
            // Expected - JSON parsing failed
        }
        Err(RetrievalError::Empty) => {
            panic!("Should return JsonError, not Empty");
        }
        Ok(_) => {
            panic!("Should have failed to parse malformed JSON");
        }
    }
}

#[test]
fn test_bm25_tokenization_lowercase() {
    let docs = vec!["UPPERCASE TEXT should be lowercased"];
    let index = Bm25Index::new(docs, 1.2, 0.75);

    // Search with lowercase should match
    let results = index.search("uppercase", 1);
    assert_eq!(
        results,
        vec![0],
        "Should match lowercase query against uppercase text"
    );
}

#[test]
fn test_cwe_kb_search_path_traversal() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("path traversal directory", 3);

    assert!(
        !results.is_empty(),
        "Should find results for path traversal"
    );
    let has_cwe22 = results.iter().any(|d| d.cwe_id == "CWE-22");
    assert!(has_cwe22, "CWE-22 should be found for path traversal query");
}

#[test]
fn test_cwe_kb_search_command_injection() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("os command injection", 3);

    assert!(
        !results.is_empty(),
        "Should find results for command injection"
    );
    let has_cwe78 = results.iter().any(|d| d.cwe_id == "CWE-78");
    assert!(
        has_cwe78,
        "CWE-78 should be found for OS command injection query"
    );
}

#[test]
fn test_cwe_kb_search_buffer_overflow() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("buffer overflow memory", 3);

    assert!(
        !results.is_empty(),
        "Should find results for buffer overflow"
    );
    let has_cwe119 = results.iter().any(|d| d.cwe_id == "CWE-119");
    assert!(
        has_cwe119,
        "CWE-119 should be found for buffer overflow query"
    );
}

#[test]
fn test_cwe_kb_search_hardcoded_credentials() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("hardcoded credentials password", 3);

    assert!(
        !results.is_empty(),
        "Should find results for hardcoded credentials"
    );
    let has_cwe798 = results.iter().any(|d| d.cwe_id == "CWE-798");
    assert!(
        has_cwe798,
        "CWE-798 should be found for hardcoded credentials query"
    );
}

#[test]
fn test_cwe_kb_empty_json_array() {
    let result = CweKnowledgeBase::load_from_json(r#"{"cwe_specifications": []}"#);

    assert!(
        result.is_err(),
        "Should error on empty specifications array"
    );
    match result {
        Err(RetrievalError::Empty) => {
            // Expected - no documents available
        }
        _ => panic!("Should return Empty error for zero documents"),
    }
}

#[test]
fn test_bm25_ranking_order() {
    let docs = vec![
        "SQL injection vulnerability in database queries",
        "Some completely unrelated text about gardening",
        "Another document mentioning SQL but less about injection",
    ];

    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("SQL injection", 3);

    assert!(!results.is_empty());
    assert_eq!(results[0], 0, "Most relevant doc should be first");
}
