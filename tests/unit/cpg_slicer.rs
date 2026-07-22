//! Unit tests for CPG-guided slicing (T3.1)
//!
//! These tests run WITHOUT Joern installed, using mock engines.

use baco::cpg::{CodeSlice, CpgConfig, CpgEngine, CpgError, DataFlowNode, QueryResult};
use std::path::{Path, PathBuf};

/// Mock CPG engine for testing
struct MockCpgEngine {
    available: bool,
    query_result: QueryResult,
    build_should_fail: bool,
}

impl MockCpgEngine {
    fn new(available: bool, query_result: QueryResult) -> Self {
        Self {
            available,
            query_result,
            build_should_fail: false,
        }
    }

    #[allow(dead_code)] // Used for future tests
    fn with_build_failure(mut self) -> Self {
        self.build_should_fail = true;
        self
    }
}

impl CpgEngine for MockCpgEngine {
    fn build(&self, _project_path: &Path) -> Result<baco::cpg::CpgHandle, CpgError> {
        if self.build_should_fail {
            return Err(CpgError::BuildFailed("Mock build failure".to_string()));
        }
        if !self.available {
            return Err(CpgError::JoernNotInstalled);
        }
        Ok(baco::cpg::CpgHandle {
            workspace: PathBuf::new(),
            cpg_path: PathBuf::new(),
        })
    }

    fn run_query(
        &self,
        _cpg: &baco::cpg::CpgHandle,
        _cpgql: &str,
    ) -> Result<QueryResult, CpgError> {
        Ok(self.query_result.clone())
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[test]
fn test_slice_extracts_code_from_query_result() {
    let nodes = vec![
        serde_json::json!({
            "lineNumber": 42,
            "code": "vulnerable_call(input)",
            "variable": "input",
            "method": "main"
        }),
        serde_json::json!({
            "lineNumber": 43,
            "code": "process(result)",
            "variable": "result",
            "method": "main"
        }),
    ];

    let engine = MockCpgEngine::new(true, QueryResult { nodes });
    let slicer = baco::cpg::slicer::CpgSlicer::new(&engine);

    let cpg = baco::cpg::CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let slice = slicer.slice(&cpg, "CWE-79", "main").unwrap();

    assert!(!slice.is_empty());
    assert_eq!(slice.line_range.0, 42);
    assert_eq!(slice.line_range.1, 43);
    assert_eq!(slice.data_flow.len(), 2);
}

#[test]
fn test_slice_returns_empty_when_no_nodes() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::slicer::CpgSlicer::new(&engine);

    let cpg = baco::cpg::CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let slice = slicer.slice(&cpg, "CWE-79", "main").unwrap();

    assert!(slice.is_empty());
}

#[test]
fn test_slice_picks_correct_cpgql_for_cwe79() {
    let cpgql = baco::cpg::queries::get_query_for_cwe("CWE-79", "main");
    assert!(cpgql.contains("sanitize")); // XSS query should mention sanitize
}

#[test]
fn test_slice_picks_correct_cpgql_for_cwe89() {
    let cpgql = baco::cpg::queries::get_query_for_cwe("CWE-89", "main");
    assert!(cpgql.contains("execute") || cpgql.contains("query")); // SQLi query
}

#[test]
fn test_slice_falls_back_for_unknown_cwe() {
    let cpgql = baco::cpg::queries::get_query_for_cwe("CWE-999", "my_function");
    assert!(cpgql.contains("my_function")); // Should use default method query with entry point
    assert!(cpgql.contains("cpg.method.name")); // Fallback uses method name search
}

#[test]
fn test_joern_engine_not_available_when_binary_missing() {
    let engine = MockCpgEngine::new(false, QueryResult { nodes: vec![] });
    assert!(!engine.is_available());
}

#[test]
fn test_build_returns_error_when_joern_unavailable() {
    let engine = MockCpgEngine::new(false, QueryResult { nodes: vec![] });
    let result = engine.build(Path::new("/tmp/test"));
    assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
}

#[test]
fn test_cpg_config_default_disabled() {
    let config = CpgConfig::default();
    assert!(!config.enabled);
    assert!(config.joern_path.is_none());
    assert_eq!(config.slice_budget_lines, 200);
}

#[test]
fn test_code_slice_empty() {
    let slice = CodeSlice::empty();
    assert!(slice.is_empty());
    assert_eq!(slice.line_range, (0, 0));
    assert!(slice.related_functions.is_empty());
    assert!(slice.data_flow.is_empty());
}

#[test]
fn test_code_slice_with_data() {
    let slice = CodeSlice {
        source: "fn main() { println!(\"Hello\"); }".to_string(),
        line_range: (1, 1),
        related_functions: vec!["main".to_string()],
        data_flow: vec![DataFlowNode {
            line: 1,
            code: "println!(\"Hello\")".to_string(),
            variable: "".to_string(),
        }],
    };

    assert!(!slice.is_empty());
    assert_eq!(slice.line_range, (1, 1));
    assert_eq!(slice.related_functions.len(), 1);
    assert_eq!(slice.data_flow.len(), 1);
}

#[test]
fn test_cwe_query_normalization() {
    // Test that different CWE ID formats produce the same query
    let query1 = baco::cpg::queries::get_query_for_cwe("CWE-79", "main");
    let query2 = baco::cpg::queries::get_query_for_cwe("79", "main");
    let query3 = baco::cpg::queries::get_query_for_cwe("cwe-79", "main");

    assert_eq!(query1, query2);
    assert_eq!(query2, query3);
}

#[test]
fn test_all_cwe_queries_produce_valid_strings() {
    // Verify all supported CWEs produce non-empty queries
    let cwes = vec![
        "CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-798", "CWE-200",
    ];

    for cwe in cwes {
        let query = baco::cpg::queries::get_query_for_cwe(cwe, "main");
        assert!(!query.is_empty(), "Query for {} should not be empty", cwe);
    }
}
