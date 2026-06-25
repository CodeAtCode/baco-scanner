//! Analysis context persistence.
//!
//! Serializes/deserializes `AnalysisContext` to `target/baco/context.json`
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
    /// Write the context as JSON to `target/baco/context.json` under *path*.
    /// Auto-creates the directory if it does not exist.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let dir = path.join("target/baco");
        fs::create_dir_all(&dir)?;
        let out_path = dir.join("context.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(out_path, json)?;
        Ok(())
    }

    /// Load the context from `target/baco/context.json` under *path*.
    /// Returns a default (empty) context if the file does not exist.
    pub fn load(path: &Path) -> std::io::Result<AnalysisContext> {
        let out_path = path.join("target/baco/context.json");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_save_load() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = AnalysisContext {
            project_type: ProjectType::CLI,
            architecture_summary: "Test summary".to_string(),
            threat_model: Some("Attacker: anonymous".to_string()),
            invariants: vec!["No unauthenticated access".to_string()],
            findings_so_far: vec!["CWE-79: XSS in header".to_string()],
        };

        ctx.save(tmp.path()).unwrap();

        let loaded = AnalysisContext::load(tmp.path()).unwrap();
        assert_eq!(loaded.project_type, ctx.project_type);
        assert_eq!(loaded.architecture_summary, ctx.architecture_summary);
        assert_eq!(loaded.threat_model, ctx.threat_model);
        assert_eq!(loaded.invariants, ctx.invariants);
        assert_eq!(loaded.findings_so_far, ctx.findings_so_far);
    }

    #[test]
    fn test_context_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = AnalysisContext::load(tmp.path()).unwrap();
        assert!(ctx.architecture_summary.is_empty());
        assert!(ctx.invariants.is_empty());
        assert!(ctx.findings_so_far.is_empty());
        assert_eq!(ctx.threat_model, None);
    }
}
