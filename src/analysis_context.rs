//! Analysis context persistence.
//!
//! Serializes/deserializes `AnalysisContext` to `context.json` in the output dir
//! so phases can share state without passing through LLM calls.

use crate::project_type::ProjectType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Persisted analysis state shared across phases.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisContext {
    pub project_type: ProjectType,
    pub architecture_summary: String,
    pub threat_model: Option<String>,
    pub invariants: Vec<String>,
    pub findings_so_far: Vec<String>,
}

impl AnalysisContext {
    /// Write the context as JSON to `context.json` under *path*.
    /// Auto-creates the directory if it does not exist.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        fs::create_dir_all(path)?;
        let out_path = path.join("context.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(out_path, json)?;
        Ok(())
    }

    /// Load the context from `context.json` under *path*.
    /// Returns a default (empty) context if the file does not exist.
    pub fn load(path: &Path) -> std::io::Result<AnalysisContext> {
        let out_path = path.join("context.json");
        match fs::read_to_string(&out_path) {
            Ok(content) => {
                let ctx: AnalysisContext = serde_json::from_str(&content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(ctx)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(AnalysisContext::default())
            }
            Err(err) => Err(err),
        }
    }
}
