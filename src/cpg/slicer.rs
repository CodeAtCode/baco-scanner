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

        // Extract line numbers and code from nodes
        let mut lines: Vec<(u32, String, String)> = Vec::new();
        let mut functions: std::collections::HashSet<String> = std::collections::HashSet::new();

        for node in &result.nodes {
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

        // Read source file - TODO: determine file path from CPG
        let source = self.read_source_from_cpg(cpg, min_line, max_line)?;

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
        _cpg: &super::CpgHandle,
        _min_line: u32,
        _max_line: u32,
    ) -> Result<String, CpgError> {
        // TODO: implement proper source extraction from CPG
        // For now, return empty source - this needs the actual file path from CPG metadata
        Ok(String::new())
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
}
