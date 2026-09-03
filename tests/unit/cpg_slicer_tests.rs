//! Migrated inline tests for baco::cpg::slicer
//!
//! Previously in src/cpg/slicer.rs #[cfg(test)] mod tests

use baco::cpg::{CpgEngine, CpgError, CpgHandle, QueryResult};
use std::path::{Path, PathBuf};

/// Mock CPG engine for testing
struct MockCpgEngine {
    available: bool,
    query_result: QueryResult,
}

impl MockCpgEngine {
    fn new(available: bool, query_result: QueryResult) -> Self {
        Self {
            available,
            query_result,
        }
    }
}

impl CpgEngine for MockCpgEngine {
    fn build(&self, _project_path: &Path) -> Result<CpgHandle, CpgError> {
        if !self.available {
            return Err(CpgError::JoernNotInstalled);
        }
        Ok(CpgHandle {
            workspace: PathBuf::new(),
            cpg_path: PathBuf::new(),
        })
    }

    fn run_query(&self, _cpg: &CpgHandle, _cpgql: &str) -> Result<QueryResult, CpgError> {
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
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
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
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
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
    assert!(cpgql.contains("my_function")); // Should use default with entry point
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
fn test_extract_slice_from_result_no_line_number_returns_empty() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let result = QueryResult {
        nodes: vec![serde_json::json!({
            "code": "some code",
            "variable": "x"
        })],
    };

    let slice = slicer.extract_slice_from_result(&result, &cpg).unwrap();

    assert!(slice.is_empty());
}

#[test]
fn test_extract_slice_from_result_with_filename() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: std::path::PathBuf::from("/tmp/workspace"),
        cpg_path: std::path::PathBuf::new(),
    };

    let result = QueryResult {
        nodes: vec![serde_json::json!({
            "lineNumber": 10,
            "code": "let x = 5",
            "variable": "x",
            "filename": "/path/to/file.rs"
        })],
    };

    let slice = slicer.extract_slice_from_result(&result, &cpg).unwrap();
    assert!(!slice.is_empty());
    assert_eq!(slice.line_range.0, 10);
    assert_eq!(slice.line_range.1, 10);
}

#[test]
fn test_extract_slice_from_result_with_method_field() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let result = QueryResult {
        nodes: vec![serde_json::json!({
            "lineNumber": 15,
            "code": "process(data)",
            "variable": "data",
            "method": "process_data"
        })],
    };

    let slice = slicer.extract_slice_from_result(&result, &cpg).unwrap();
    assert!(!slice.is_empty());
    assert!(slice
        .related_functions
        .contains(&"process_data".to_string()));
}

#[test]
fn test_read_source_from_cpg_with_no_filename_returns_empty() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let source = slicer.read_source_from_cpg(&cpg, None, 1, 10).unwrap();
    assert!(source.is_empty());
}

#[test]
fn test_read_source_from_cpg_with_empty_filename_returns_empty() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let source = slicer.read_source_from_cpg(&cpg, Some(""), 1, 10).unwrap();
    assert!(source.is_empty());
}

#[test]
fn test_read_source_from_cpg_with_absolute_filename() {
    // Create a temp file for testing
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("baco_test_source.rs");
    let test_content = "fn main() {\n    println!(\"Hello\");\n    let x = 42;\n}";

    // Write test file
    std::fs::write(&test_file, test_content).unwrap();

    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    let source = slicer
        .read_source_from_cpg(&cpg, Some(test_file.to_str().unwrap()), 1, 3)
        .unwrap();
    assert!(source.contains("println"));
    assert!(source.contains("let x = 42"));

    // Cleanup
    let _ = std::fs::remove_file(&test_file);
}

#[test]
fn test_read_source_from_cpg_with_nonexistent_filename_returns_empty() {
    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: std::path::PathBuf::from("/tmp/workspace"),
        cpg_path: PathBuf::new(),
    };

    let source = slicer
        .read_source_from_cpg(&cpg, Some("/nonexistent/file/path.rs"), 1, 10)
        .unwrap();
    assert!(source.is_empty());
}

#[test]
fn test_read_source_from_cpg_line_clamping_min_beyond_file_length() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("baco_test_clamp.rs");
    let test_content = "line1\nline2\nline3";

    std::fs::write(&test_file, test_content).unwrap();

    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    // Request lines 100-200 from a 3-line file
    let source = slicer
        .read_source_from_cpg(&cpg, Some(test_file.to_str().unwrap()), 100, 200)
        .unwrap();
    assert!(source.is_empty());

    let _ = std::fs::remove_file(&test_file);
}

#[test]
fn test_read_source_from_cpg_line_clamping_min_greater_than_max() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("baco_test_clamp2.rs");
    let test_content = "line1\nline2\nline3";

    std::fs::write(&test_file, test_content).unwrap();

    let engine = MockCpgEngine::new(true, QueryResult { nodes: vec![] });
    let slicer = baco::cpg::CpgSlicer::new(&engine);

    let cpg = CpgHandle {
        workspace: PathBuf::new(),
        cpg_path: PathBuf::new(),
    };

    // Request lines 5-2 (min > max)
    let source = slicer
        .read_source_from_cpg(&cpg, Some(test_file.to_str().unwrap()), 5, 2)
        .unwrap();
    assert!(source.is_empty());

    let _ = std::fs::remove_file(&test_file);
}
