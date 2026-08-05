//! CPG slicer implementation
//!
//! This module provides the CpgSlicer which extracts code slices from CPG queries.
//! It maps CWE IDs to CPGQL query templates and extracts relevant code regions.

use super::{CodeSlice, CpgEngine, CpgError, DataFlowNode, QueryResult};

/// CPG slicer for extracting code slices from CPG queries
pub struct CpgSlicer<'a> {
    engine: &'a dyn CpgEngine,
}

impl<'a> CpgSlicer<'a> {
    /// Create a new CpgSlicer
    pub fn new(engine: &'a dyn CpgEngine) -> Self {
        Self { engine }
    }

    /// Slice code around a suspected vulnerability
    ///
    /// # Arguments
    /// * `cpg` - The built CPG handle
    /// * `cwe_hint` - CWE ID hint (e.g., "CWE-79", "CWE-89")
    /// * `entry_point` - Entry point function name for default queries
    ///
    /// # Returns
    /// CodeSlice with the sliced code, or empty slice if no nodes found
    pub fn slice(
        &self,
        cpg: &super::CpgHandle,
        cwe_hint: &str,
        entry_point: &str,
    ) -> Result<CodeSlice, CpgError> {
        // Get CPGQL query template for this CWE
        let cpgql = super::queries::get_query_for_cwe(cwe_hint, entry_point);

        // Run the query
        let result = self.engine.run_query(cpg, &cpgql)?;

        // Extract slice from query result
        self.extract_slice_from_result(&result, cpg)
    }

    /// Extract a CodeSlice from a QueryResult
    fn extract_slice_from_result(
        &self,
        result: &QueryResult,
        cpg: &super::CpgHandle,
    ) -> Result<CodeSlice, CpgError> {
        if result.nodes.is_empty() {
            return Ok(CodeSlice::empty());
        }

        // Extract line numbers, code, and filename from nodes
        let mut lines: Vec<(u32, String, String)> = Vec::new();
        let mut functions: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut filename: Option<String> = None;

        for node in &result.nodes {
            // Extract filename from first node that has it
            if filename.is_none() {
                filename = node
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }

            // Extract line number
            if let Some(line_val) = node.get("lineNumber").and_then(|v| v.as_i64()) {
                let line = line_val as u32;

                // Extract code
                let code = node
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Extract variable
                let variable = node
                    .get("variable")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                lines.push((line, code.clone(), variable));

                // Extract function name
                if let Some(func) = node.get("method").and_then(|v| v.as_str()) {
                    functions.insert(func.to_string());
                }
            }
        }

        if lines.is_empty() {
            return Ok(CodeSlice::empty());
        }

        // Sort by line number
        lines.sort_by_key(|(line, _, _)| *line);

        // Get line range
        let min_line = lines.first().map(|(l, _, _)| *l).unwrap_or(0);
        let max_line = lines.last().map(|(l, _, _)| *l).unwrap_or(0);

        // Read source file using the extracted filename
        let source = self.read_source_from_cpg(cpg, filename.as_deref(), min_line, max_line)?;

        // Build data flow nodes
        let data_flow: Vec<DataFlowNode> = lines
            .into_iter()
            .map(|(line, code, variable)| DataFlowNode {
                line,
                code,
                variable,
            })
            .collect();

        Ok(CodeSlice {
            source,
            line_range: (min_line, max_line),
            related_functions: functions.into_iter().collect(),
            data_flow,
        })
    }

    /// Read source code from CPG workspace
    fn read_source_from_cpg(
        &self,
        cpg: &super::CpgHandle,
        filename: Option<&str>,
        min_line: u32,
        max_line: u32,
    ) -> Result<String, CpgError> {
        // Get filename from parameter or try to derive from CPG workspace
        let file_path = match filename {
            Some(name) if !name.is_empty() => {
                // Try absolute path first, then relative to workspace parent
                let path = std::path::Path::new(name);
                if path.is_absolute() && path.exists() {
                    path.to_path_buf()
                } else {
                    // Try relative to workspace parent (project root)
                    cpg.workspace
                        .parent()
                        .map(|p| p.join(name))
                        .ok_or_else(|| {
                            CpgError::QueryFailed("Workspace has no parent directory".to_string())
                        })?
                }
            }
            _ => {
                // No filename available, return empty source gracefully
                return Ok(String::new());
            }
        };

        // Check if file exists
        if !file_path.exists() {
            // File not found - return empty string gracefully
            return Ok(String::new());
        }

        // Read the source file
        let content = std::fs::read_to_string(&file_path).map_err(|e| {
            CpgError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read source file {:?}: {}", file_path, e),
            ))
        })?;

        // Extract lines from min_line to max_line (1-indexed)
        let lines: Vec<&str> = content.lines().collect();

        // Clamp line range to actual file bounds
        let start_idx = (min_line as usize).saturating_sub(1).min(lines.len());
        let end_idx = (max_line as usize).min(lines.len());

        if start_idx >= lines.len() || start_idx > end_idx {
            // Line range out of bounds - return empty gracefully
            return Ok(String::new());
        }

        // Extract the requested lines
        let extracted = lines[start_idx..end_idx].join("\n");

        Ok(extracted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg::{CpgEngine, CpgHandle};
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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

        let cpg = CpgHandle {
            workspace: PathBuf::new(),
            cpg_path: PathBuf::new(),
        };

        let slice = slicer.slice(&cpg, "CWE-79", "main").unwrap();

        assert!(slice.is_empty());
    }

    #[test]
    fn test_slice_picks_correct_cpgql_for_cwe79() {
        let cpgql = super::super::queries::get_query_for_cwe("CWE-79", "main");
        assert!(cpgql.contains("sanitize")); // XSS query should mention sanitize
    }

    #[test]
    fn test_slice_picks_correct_cpgql_for_cwe89() {
        let cpgql = super::super::queries::get_query_for_cwe("CWE-89", "main");
        assert!(cpgql.contains("execute") || cpgql.contains("query")); // SQLi query
    }

    #[test]
    fn test_slice_falls_back_for_unknown_cwe() {
        let cpgql = super::super::queries::get_query_for_cwe("CWE-999", "my_function");
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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
        let slicer = CpgSlicer::new(&engine);

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
}
