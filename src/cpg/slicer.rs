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
    pub fn extract_slice_from_result(
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
    pub fn read_source_from_cpg(
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
