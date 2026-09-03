//! Migrated inline tests for baco::cpg::queries
//!
//! Previously in src/cpg/queries.rs #[cfg(test)] mod tests

use baco::cpg::queries::{get_query_for_cwe, normalize_cwe_id};

#[test]
fn test_get_query_for_cwe79() {
    let query = get_query_for_cwe("CWE-79", "main");
    assert!(query.contains("sanitize"));
}

#[test]
fn test_get_query_for_cwe89() {
    let query = get_query_for_cwe("CWE-89", "main");
    assert!(query.contains("execute") || query.contains("query"));
}

#[test]
fn test_get_query_for_cwe78() {
    let query = get_query_for_cwe("CWE-78", "main");
    assert!(query.contains("Process") || query.contains("exec"));
}

#[test]
fn test_get_query_for_cwe22() {
    let query = get_query_for_cwe("CWE-22", "main");
    assert!(query.contains("open") || query.contains("read"));
}

#[test]
fn test_get_query_fallback_for_unknown_cwe() {
    let query = get_query_for_cwe("CWE-999", "my_entry_point");
    assert!(query.contains("my_entry_point"));
}

#[test]
fn test_normalize_cwe_id_with_prefix() {
    assert_eq!(normalize_cwe_id("CWE-79"), "cwe-79");
    assert_eq!(normalize_cwe_id("cwe-89"), "cwe-89");
}

#[test]
fn test_normalize_cwe_id_without_prefix() {
    assert_eq!(normalize_cwe_id("79"), "cwe-79");
    assert_eq!(normalize_cwe_id("89"), "cwe-89");
}

#[test]
fn test_normalize_cwe_id_with_whitespace() {
    assert_eq!(normalize_cwe_id("  CWE-79  "), "cwe-79");
}
