//! Migrated inline tests for baco::retrieval module
//!
//! Previously in src/retrieval/mod.rs #[cfg(test)] mod tests

use baco::retrieval::{CweKnowledgeBase, RetrievalError};

#[test]
fn test_load_embedded_success() {
    let kb = CweKnowledgeBase::load_embedded().expect("Failed to load embedded CWE data");
    assert!(!kb.is_empty());
    assert!(kb.len() >= 20, "Should have at least 20 CWE documents");
}

#[test]
fn test_search_sql_injection() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("sql injection", 3);

    assert!(!results.is_empty(), "Should find results for sql injection");
    assert!(
        results.iter().any(|d| d.cwe_id == "CWE-89"),
        "CWE-89 should be in top results for SQL injection"
    );
}

#[test]
fn test_search_xss() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("cross site scripting", 1);

    assert!(!results.is_empty(), "Should find results for XSS");
    assert_eq!(
        results[0].cwe_id, "CWE-79",
        "CWE-79 should be top result for cross-site scripting"
    );
}

#[test]
fn test_search_empty_query() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let results = kb.search("", 10);
    assert!(results.is_empty(), "Empty query should return no results");
}

#[test]
fn test_load_malformed_json() {
    let result = CweKnowledgeBase::load_from_json("{ invalid json }");
    assert!(result.is_err(), "Should fail on malformed JSON");
    match result {
        Err(RetrievalError::JsonError(_)) => (),
        _ => panic!("Should return JsonError variant"),
    }
}

#[test]
fn test_get_cwe_ids() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let ids = kb.get_cwe_ids();
    assert!(ids.contains(&"CWE-79"));
    assert!(ids.contains(&"CWE-89"));
    assert!(ids.contains(&"CWE-22"));
}
