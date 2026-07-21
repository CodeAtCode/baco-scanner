//! CPG (Code Property Graph) module for vulnerability slicing
//!
//! This module provides CPG-based code slicing using Joern to reduce the amount
//! of code sent to LLMs while improving multi-function detection robustness.
//!
//! Based on: LLMxCPG (Usenix 2025) - arxiv:2507.16585

pub mod joern;
pub use joern::JoernEngine;
pub mod queries;
pub mod slicer;

use std::path::PathBuf;

/// CPG engine trait for building and querying code property graphs
pub trait CpgEngine: Send + Sync {
    /// Build a CPG from a project path
    fn build(&self, project_path: &std::path::Path) -> Result<CpgHandle, CpgError>;

    /// Run a CPGQL query against a built CPG
    fn run_query(&self, cpg: &CpgHandle, cpgql: &str) -> Result<QueryResult, CpgError>;

    /// Check if the engine is available (Joern binary present)
    fn is_available(&self) -> bool;
}

/// Handle to a built CPG
#[derive(Debug, Clone)]
pub struct CpgHandle {
    /// Workspace directory
    pub workspace: PathBuf,
    /// Path to the generated CPG
    pub cpg_path: PathBuf,
}

/// A sliced code region extracted from CPG analysis
pub struct CodeSlice {
    /// Source code content of the slice
    pub source: String,
    /// Line range (start, end) in the original file
    pub line_range: (u32, u32),
    /// Related function names involved in the data flow
    pub related_functions: Vec<String>,
    /// Data flow nodes within the slice
    pub data_flow: Vec<DataFlowNode>,
}

impl CodeSlice {
    /// Create an empty code slice
    pub fn empty() -> Self {
        Self {
            source: String::new(),
            line_range: (0, 0),
            related_functions: Vec::new(),
            data_flow: Vec::new(),
        }
    }

    /// Check if this slice is empty
    pub fn is_empty(&self) -> bool {
        self.source.is_empty() && self.data_flow.is_empty()
    }
}

/// A single data flow node in the sliced code
pub struct DataFlowNode {
    /// Line number in the source file
    pub line: u32,
    /// Code at this line
    pub code: String,
    /// Variable name involved in the data flow
    pub variable: String,
}

/// Result of a CPGQL query
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Query result nodes as JSON values
    pub nodes: Vec<serde_json::Value>,
}

/// CPG configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CpgConfig {
    /// Whether CPG slicing is enabled
    pub enabled: bool,
    /// Path to Joern binary (None = use PATH)
    pub joern_path: Option<PathBuf>,
    /// Maximum lines to include in a slice
    pub slice_budget_lines: usize,
}

impl Default for CpgConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            joern_path: None,
            slice_budget_lines: 200,
        }
    }
}

/// CPG engine errors
#[derive(Debug, thiserror::Error)]
pub enum CpgError {
    #[error("Joern is not installed or not in PATH")]
    JoernNotInstalled,

    #[error("Failed to build CPG: {0}")]
    BuildFailed(String),

    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CPG not found at {0}")]
    CpgNotFound(PathBuf),

    #[error("Invalid CPGQL query: {0}")]
    InvalidQuery(String),
}

/// CPG handle for the Joern engine
pub struct CpgHandleJoern {
    pub workspace: PathBuf,
    pub cpg_path: PathBuf,
}
