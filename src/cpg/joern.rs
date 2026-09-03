//! Joern CPG engine implementation
//!
//! This module provides the JoernEngine which builds and queries Code Property Graphs
//! using the Joern tool. Joern must be installed and available in PATH or at a configured path.

use super::{CpgEngine, CpgError, CpgHandle, QueryResult};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Joern CPG engine
pub struct JoernEngine {
    joern_path: Option<PathBuf>,
}

impl JoernEngine {
    /// Create a new JoernEngine
    ///
    /// If joern_path is None, the engine will search for joern in PATH.
    pub fn new(joern_path: Option<PathBuf>) -> Self {
        Self { joern_path }
    }

    /// Find the joern binary
    pub fn find_joern(&self) -> Result<PathBuf, CpgError> {
        if let Some(ref path) = self.joern_path {
            if path.exists() {
                return Ok(path.clone());
            }
            return Err(CpgError::JoernNotInstalled);
        }

        // Search in PATH
        which::which("joern").map_err(|_| CpgError::JoernNotInstalled)
    }
}

impl CpgEngine for JoernEngine {
    fn build(&self, project_path: &Path) -> Result<CpgHandle, CpgError> {
        // Check if joern is available first
        if !self.is_available() {
            return Err(CpgError::JoernNotInstalled);
        }

        let workspace = project_path
            .parent()
            .ok_or_else(|| CpgError::BuildFailed("Project path has no parent".to_string()))?
            .join(".cpg-workspace");

        std::fs::create_dir_all(&workspace)
            .map_err(|e| CpgError::BuildFailed(format!("Failed to create workspace: {}", e)))?;

        let cpg_path = workspace.join("project.cpg");

        // Run joern-parse to build the CPG
        let parse_output = Command::new(self.find_joern()?)
            .arg("joern-parse")
            .arg(project_path)
            .arg("--output")
            .arg(&cpg_path)
            .output()
            .map_err(|e| CpgError::BuildFailed(format!("Failed to execute joern-parse: {}", e)))?;

        if !parse_output.status.success() {
            let stderr = String::from_utf8_lossy(&parse_output.stderr);
            return Err(CpgError::BuildFailed(format!(
                "joern-parse failed: {}",
                stderr.trim()
            )));
        }

        if !cpg_path.exists() {
            return Err(CpgError::CpgNotFound(cpg_path));
        }

        Ok(CpgHandle {
            workspace,
            cpg_path,
        })
    }

    fn run_query(&self, cpg: &CpgHandle, cpgql: &str) -> Result<QueryResult, CpgError> {
        // Write the query to a temporary file
        let query_file = cpg.workspace.join("query.ql");
        std::fs::write(&query_file, cpgql)
            .map_err(|e| CpgError::QueryFailed(format!("Failed to write query file: {}", e)))?;

        // Run joern with the script
        let output = Command::new(self.find_joern()?)
            .arg("--script")
            .arg(&query_file)
            .arg("--cpg")
            .arg(&cpg.cpg_path)
            .arg("--export")
            .arg("json")
            .output()
            .map_err(|e| CpgError::QueryFailed(format!("Failed to execute joern: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CpgError::QueryFailed(format!(
                "Joern query failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the JSON output
        let nodes: Vec<serde_json::Value> = serde_json::from_str(&stdout)
            .map_err(|e| CpgError::QueryFailed(format!("Failed to parse query result: {}", e)))?;

        Ok(QueryResult { nodes })
    }

    fn is_available(&self) -> bool {
        self.find_joern().is_ok()
    }
}

impl JoernEngine {
    /// Check if joern is available
    pub fn is_available(&self) -> bool {
        self.find_joern().is_ok()
    }

    /// Build a CPG from a project path
    pub fn build_cpg(&self, project_path: &Path) -> Result<CpgHandle, CpgError> {
        self.build(project_path)
    }
}
