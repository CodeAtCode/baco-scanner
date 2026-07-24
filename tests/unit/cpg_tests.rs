//! Unit tests for CPG module (additional coverage beyond cpg_slicer.rs)
//!
//! These tests cover public functions that don't require Joern to be installed.
//! Focus on query construction, data structures, and edge cases.

use baco::cpg::joern::JoernEngine;
use baco::cpg::queries::get_query_for_cwe;
use baco::cpg::slicer::CpgSlicer;
use baco::cpg::{CodeSlice, CpgConfig, CpgError, DataFlowNode, QueryResult};
use std::path::PathBuf;

// ============================================================================
// get_query_for_cwe tests - comprehensive CWE coverage
// ============================================================================

#[test]
fn test_query_cwe79_contains_sanitize() {
    let query = get_query_for_cwe("CWE-79", "main");
    assert!(query.contains("sanitize"));
}

#[test]
fn test_query_cwe89_contains_execute_or_query() {
    let query = get_query_for_cwe("CWE-89", "main");
    assert!(query.contains("execute") || query.contains("query"));
}

#[test]
fn test_query_cwe78_contains_process_or_exec() {
    let query = get_query_for_cwe("CWE-78", "main");
    assert!(query.contains("Process") || query.contains("exec"));
}

#[test]
fn test_query_cwe22_contains_open_or_read() {
    let query = get_query_for_cwe("CWE-22", "main");
    assert!(query.contains("open") || query.contains("read"));
}

#[test]
fn test_query_cwe502_contains_deserialize() {
    let query = get_query_for_cwe("CWE-502", "main");
    assert!(query.contains("deserialize") || query.contains("readObject"));
}

#[test]
fn test_query_cwe798_contains_credential_keywords() {
    let query = get_query_for_cwe("CWE-798", "main");
    assert!(query.contains("password") || query.contains("secret") || query.contains("apiKey"));
}

#[test]
fn test_query_cwe200_contains_log_or_print() {
    let query = get_query_for_cwe("CWE-200", "main");
    assert!(query.contains("log") || query.contains("print"));
}

#[test]
fn test_query_fallback_uses_entry_point() {
    let query = get_query_for_cwe("CWE-999", "my_entry_point");
    assert!(query.contains("my_entry_point"));
    assert!(query.contains("cpg.method.name"));
}

#[test]
fn test_query_numeric_cwe_id_falls_back_correctly() {
    let query = get_query_for_cwe("404", "handler");
    assert!(query.contains("handler"));
}

#[test]
fn test_query_different_entry_points_produce_different_queries() {
    let query1 = get_query_for_cwe("CWE-999", "function_a");
    let query2 = get_query_for_cwe("CWE-999", "function_b");
    assert_ne!(query1, query2);
    assert!(query1.contains("function_a"));
    assert!(query2.contains("function_b"));
}

// ============================================================================
// CpgSlicer tests
// ============================================================================

#[test]
fn test_cpg_slicer_new_creates_instance() {
    // Create a minimal mock engine for testing
    struct MockEngine;
    impl baco::cpg::CpgEngine for MockEngine {
        fn build(&self, _path: &std::path::Path) -> Result<baco::cpg::CpgHandle, CpgError> {
            Err(CpgError::JoernNotInstalled)
        }
        fn run_query(
            &self,
            _cpg: &baco::cpg::CpgHandle,
            _query: &str,
        ) -> Result<QueryResult, CpgError> {
            Ok(QueryResult { nodes: vec![] })
        }
        fn is_available(&self) -> bool {
            false
        }
    }

    let engine = MockEngine;
    let _slicer = CpgSlicer::new(&engine);

    // Just verify we can create the slicer
    assert_eq!(true, true); // Construction test
}

// ============================================================================
// JoernEngine tests
// ============================================================================

#[test]
#[allow(clippy::bool_assert_comparison)]
fn test_joern_engine_new_with_none_path() {
    let _engine = JoernEngine::new(None);
    // Construction test
    assert_eq!(true, true);
}

#[test]
#[allow(clippy::bool_assert_comparison)]
fn test_joern_engine_new_with_some_path() {
    let path = PathBuf::from("/usr/local/bin/joern");
    let _engine = JoernEngine::new(Some(path));
    // Construction test
    assert_eq!(true, true);
}

// ============================================================================
// DataFlowNode tests
// ============================================================================

#[test]
fn test_data_flow_node_creation() {
    let node = DataFlowNode {
        line: 42,
        code: "let x = input".to_string(),
        variable: "x".to_string(),
    };

    assert_eq!(node.line, 42);
    assert_eq!(node.code, "let x = input");
    assert_eq!(node.variable, "x");
}

#[test]
fn test_data_flow_node_empty_fields() {
    let node = DataFlowNode {
        line: 0,
        code: String::new(),
        variable: String::new(),
    };

    assert_eq!(node.line, 0);
    assert!(node.code.is_empty());
    assert!(node.variable.is_empty());
}

#[test]
fn test_data_flow_node_large_line_number() {
    let node = DataFlowNode {
        line: u32::MAX,
        code: "last_line".to_string(),
        variable: "var".to_string(),
    };

    assert_eq!(node.line, u32::MAX);
}

// ============================================================================
// CodeSlice tests
// ============================================================================

#[test]
fn test_code_slice_is_empty_when_source_empty() {
    let slice = CodeSlice {
        source: String::new(),
        line_range: (0, 0),
        related_functions: vec![],
        data_flow: vec![],
    };

    assert!(slice.is_empty());
}

#[test]
fn test_code_slice_is_not_empty_with_source() {
    let slice = CodeSlice {
        source: "fn main() {}".to_string(),
        line_range: (1, 1),
        related_functions: vec![],
        data_flow: vec![],
    };

    assert!(!slice.is_empty());
}

#[test]
fn test_code_slice_is_not_empty_with_data_flow() {
    let slice = CodeSlice {
        source: String::new(),
        line_range: (0, 0),
        related_functions: vec![],
        data_flow: vec![DataFlowNode {
            line: 1,
            code: "x".to_string(),
            variable: "x".to_string(),
        }],
    };

    assert!(!slice.is_empty());
}

#[test]
fn test_code_slice_multiple_functions() {
    let slice = CodeSlice {
        source: "fn a() {} fn b() {}".to_string(),
        line_range: (1, 2),
        related_functions: vec!["a".to_string(), "b".to_string()],
        data_flow: vec![],
    };

    assert_eq!(slice.related_functions.len(), 2);
}

// ============================================================================
// CpgConfig tests
// ============================================================================

#[test]
fn test_cpg_config_enabled_true() {
    let config = CpgConfig {
        enabled: true,
        joern_path: None,
        slice_budget_lines: 500,
    };

    assert!(config.enabled);
    assert_eq!(config.slice_budget_lines, 500);
}

#[test]
fn test_cpg_config_custom_joern_path() {
    let path = PathBuf::from("/custom/path/joern");
    let config = CpgConfig {
        enabled: true,
        joern_path: Some(path.clone()),
        slice_budget_lines: 200,
    };

    assert_eq!(config.joern_path, Some(path));
}

#[test]
fn test_cpg_config_zero_budget() {
    let config = CpgConfig {
        enabled: false,
        joern_path: None,
        slice_budget_lines: 0,
    };

    assert_eq!(config.slice_budget_lines, 0);
}

// ============================================================================
// CpgError tests
// ============================================================================

#[test]
fn test_cpg_error_joern_not_installed_message() {
    let err = CpgError::JoernNotInstalled;
    let msg = format!("{}", err);
    assert!(msg.contains("Joern"));
}

#[test]
fn test_cpg_error_build_failed_message() {
    let err = CpgError::BuildFailed("test failure".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("BuildFailed") || msg.contains("test failure"));
}

#[test]
fn test_cpg_error_query_failed_message() {
    let err = CpgError::QueryFailed("query error".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("query error"));
}

#[test]
fn test_cpg_error_invalid_query_message() {
    let err = CpgError::InvalidQuery("bad syntax".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("InvalidQuery") || msg.contains("bad syntax"));
}

#[test]
fn test_cpg_error_cpg_not_found_message() {
    let path = PathBuf::from("/nonexistent.cpg");
    let err = CpgError::CpgNotFound(path.clone());
    let msg = format!("{}", err);
    assert!(msg.contains("cpg"));
}

// ============================================================================
// QueryResult tests
// ============================================================================

#[test]
fn test_query_result_empty_nodes() {
    let result = QueryResult { nodes: vec![] };
    assert!(result.nodes.is_empty());
}

#[test]
fn test_query_result_single_node() {
    let result = QueryResult {
        nodes: vec![serde_json::json!({"key": "value"})],
    };
    assert_eq!(result.nodes.len(), 1);
}

#[test]
fn test_query_result_multiple_nodes() {
    let result = QueryResult {
        nodes: vec![
            serde_json::json!({"id": 1}),
            serde_json::json!({"id": 2}),
            serde_json::json!({"id": 3}),
        ],
    };
    assert_eq!(result.nodes.len(), 3);
}

// ============================================================================
// Edge cases and boundary tests
// ============================================================================

#[test]
fn test_query_with_empty_entry_point() {
    let query = get_query_for_cwe("CWE-999", "");
    // Should still produce a valid query string
    assert!(!query.is_empty());
}

#[test]
fn test_query_with_whitespace_cwe_id() {
    // Different whitespace formats should produce same query
    let query1 = get_query_for_cwe("  CWE-79  ", "main");
    let query2 = get_query_for_cwe("CWE-79", "main");
    assert_eq!(query1, query2);
}

#[test]
fn test_code_slice_large_line_range() {
    let slice = CodeSlice {
        source: "line1\nline2\nline3".to_string(),
        line_range: (1, 10000),
        related_functions: vec![],
        data_flow: vec![],
    };

    assert_eq!(slice.line_range.0, 1);
    assert_eq!(slice.line_range.1, 10000);
}

#[test]
#[allow(clippy::useless_vec)] // Vec needed for variable-length collection
fn test_data_flow_nodes_preserve_order() {
    let nodes = vec![
        DataFlowNode {
            line: 3,
            code: "c".to_string(),
            variable: "c".to_string(),
        },
        DataFlowNode {
            line: 1,
            code: "a".to_string(),
            variable: "a".to_string(),
        },
        DataFlowNode {
            line: 2,
            code: "b".to_string(),
            variable: "b".to_string(),
        },
    ];

    // Verify we can create nodes in any order
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].line, 3);
    assert_eq!(nodes[1].line, 1);
}
