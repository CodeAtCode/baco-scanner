//! Migrated inline tests for baco::retrieval::bm25
//!
//! Previously in src/retrieval/bm25.rs #[cfg(test)] mod tests

use baco::retrieval::bm25::Bm25Index;

#[test]
fn test_basic_search() {
    let docs = vec![
        "This document discusses SQL injection vulnerabilities",
        "Cross-site scripting attacks involve malicious JavaScript",
        "Buffer overflow occurs when writing beyond allocated memory",
    ];

    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("sql injection", 3);

    assert!(!results.is_empty());
    assert_eq!(results[0], 0, "SQL injection doc should be ranked first");
}

#[test]
fn test_empty_query() {
    let docs = vec!["test document"];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("", 3);
    assert!(results.is_empty());
}

#[test]
fn test_single_doc_match() {
    let docs = vec!["SQL injection is a security vulnerability"];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("sql injection", 1);
    assert_eq!(results, vec![0]);
}

#[test]
fn test_tokenization() {
    let docs = vec!["Hello, World! This is a test."];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    assert_eq!(index.docs[0].tokens.len(), 6);
    assert!(index.docs[0].term_freqs.contains_key("hello"));
    assert!(index.docs[0].term_freqs.contains_key("world"));
}

#[test]
fn test_no_matches() {
    let docs = vec!["completely unrelated content"];
    let index = Bm25Index::new(docs, 1.2, 0.75);
    let results = index.search("xyz123abc", 3);
    assert!(results.is_empty());
}
