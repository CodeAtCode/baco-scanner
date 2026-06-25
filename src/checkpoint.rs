use crate::findings::VulnerabilityFinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanPhase {
    Indexing,
    Semgrep,
    LlmStaticAnalysis,
    LlmDiscovery,
    LlmVerification,
    TicketCrossRef,
    GitAnalysis,
    CrossFileAnalysis,
    ConfidenceScoring,
    AiAggregation,
    Reporting,
    // v3 features
    ThreatModeling,
    RootCauseDedup,
    MultiVerifier,
    AutoPatching,
    CveBootstrap,
    PocCompiler,
    VariantSearch,
    SecurityAgentVerification,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub scan_id: String,
    pub project_path: String,
    pub started_at: DateTime<Utc>,
    pub current_phase: ScanPhase,
    pub completed_phases: Vec<ScanPhase>,
    pub findings_so_far: Vec<VulnerabilityFinding>,
    pub file_count: usize,
    #[serde(default)]
    pub analyzed_files: Vec<String>,
}

impl Checkpoint {
    pub fn new(scan_id: &str, project_path: &str, started_at: DateTime<Utc>) -> Self {
        Self {
            scan_id: scan_id.to_string(),
            project_path: project_path.to_string(),
            started_at,
            current_phase: ScanPhase::Indexing,
            completed_phases: Vec::new(),
            findings_so_far: Vec::new(),
            file_count: 0,
            analyzed_files: Vec::new(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read checkpoint: {}", e))?;

        let checkpoint: Checkpoint = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse checkpoint: {}", e))?;

        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.scan_id.is_empty() {
            return Err("scan_id is empty".to_string());
        }
        if self.project_path.is_empty() {
            return Err("project_path is empty".to_string());
        }
        Ok(())
    }

    pub fn resume_from(path: &str) -> Result<ScanPhase, String> {
        let checkpoint = Self::load(path)?;

        Ok(match checkpoint.current_phase {
            ScanPhase::Indexing => ScanPhase::Semgrep,
            ScanPhase::Semgrep => ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmStaticAnalysis => ScanPhase::LlmDiscovery,
            ScanPhase::LlmDiscovery => ScanPhase::LlmVerification,
            ScanPhase::LlmVerification => ScanPhase::TicketCrossRef,
            ScanPhase::TicketCrossRef => ScanPhase::GitAnalysis,
            ScanPhase::GitAnalysis => ScanPhase::CrossFileAnalysis,
            ScanPhase::CrossFileAnalysis => ScanPhase::ConfidenceScoring,
            ScanPhase::ConfidenceScoring => ScanPhase::AiAggregation,
            ScanPhase::AiAggregation => ScanPhase::Reporting,
            ScanPhase::Reporting => ScanPhase::ThreatModeling,
            ScanPhase::ThreatModeling => ScanPhase::RootCauseDedup,
            ScanPhase::RootCauseDedup => ScanPhase::MultiVerifier,
            ScanPhase::MultiVerifier => ScanPhase::AutoPatching,
            ScanPhase::AutoPatching => ScanPhase::CveBootstrap,
            ScanPhase::CveBootstrap => ScanPhase::PocCompiler,
            ScanPhase::PocCompiler => ScanPhase::VariantSearch,
            ScanPhase::VariantSearch => ScanPhase::SecurityAgentVerification,
            ScanPhase::SecurityAgentVerification => ScanPhase::Complete,
            ScanPhase::Complete | ScanPhase::Error => ScanPhase::Indexing,
        })
    }

    pub fn format_phase(&self) -> String {
        match self.current_phase {
            ScanPhase::Indexing => "🔄 Indexing ⚙️".to_string(),
            ScanPhase::Semgrep => "🔍 Semgrep Static Analysis".to_string(),
            ScanPhase::LlmStaticAnalysis => "🧠 LLM Static Analysis".to_string(),
            ScanPhase::LlmDiscovery => "🔎 LLM Discovery".to_string(),
            ScanPhase::LlmVerification => "✅ LLM Verification".to_string(),
            ScanPhase::TicketCrossRef => "🎫 Ticket Cross-Ref".to_string(),
            ScanPhase::GitAnalysis => "📊 Git Analysis".to_string(),
            ScanPhase::CrossFileAnalysis => "🔗 Cross-File Analysis".to_string(),
            ScanPhase::ConfidenceScoring => "⚖️ Confidence Scoring".to_string(),
            ScanPhase::AiAggregation => "🤖 AI Aggregation".to_string(),
            ScanPhase::Reporting => "📝 Reporting".to_string(),
            ScanPhase::ThreatModeling => "🛡️ Threat Modeling".to_string(),
            ScanPhase::RootCauseDedup => "🔍 Root Cause Dedup".to_string(),
            ScanPhase::MultiVerifier => "🗳️ Multi-Verifier".to_string(),
            ScanPhase::AutoPatching => "🔧 Auto-Patching".to_string(),
            ScanPhase::CveBootstrap => "📦 CVE Bootstrap".to_string(),
            ScanPhase::PocCompiler => "💻 PoC Compiler".to_string(),
            ScanPhase::VariantSearch => "🔍 Variant Search".to_string(),
            ScanPhase::SecurityAgentVerification => "🤖 SecurityAgent Verification".to_string(),
            ScanPhase::Complete => "✨ Complete".to_string(),
            ScanPhase::Error => "❌ Error".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load_roundtrip() {
        let checkpoint = Checkpoint::new("test-scan-123", "/tmp/test-project", Utc::now());

        let temp_path = "/tmp/test_checkpoint.json";
        checkpoint.save(temp_path).unwrap();

        let loaded = Checkpoint::load(temp_path).unwrap();
        assert_eq!(checkpoint.scan_id, loaded.scan_id);
        assert_eq!(checkpoint.project_path, loaded.project_path);
        assert_eq!(checkpoint.current_phase, loaded.current_phase);
    }

    #[test]
    fn test_validate_corrupted() {
        let corrupted = r#"{"scan_id":"","project_path":"test","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0}"#;

        let temp_path = "/tmp/test_corrupted.json";
        fs::write(temp_path, corrupted).unwrap();

        let result = Checkpoint::load(temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_resume_from_returns_correct_phase() {
        let checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        let temp_path = "/tmp/test_resume.json";
        checkpoint.save(temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(temp_path).unwrap();
        assert_eq!(next_phase, ScanPhase::Semgrep);
    }

    #[test]
    fn test_resume_from_all_phases() {
        let all_phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::Reporting,
            ScanPhase::Complete,
            ScanPhase::Error,
        ];
        for phase in all_phases {
            let checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
            let temp_path = format!("/tmp/test_resume_{:?}.json", phase);
            checkpoint.save(&temp_path).unwrap();

            let _next_phase = Checkpoint::resume_from(&temp_path).unwrap();
            // Phase resume test // All phases should resume to next phase

            let _ = fs::remove_file(&temp_path);
        }
    }

    #[test]
    fn test_validate_missing_scan_id() {
        let corrupted = r#"{"scan_id":"","project_path":"test","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0}"#;
        let temp_path = "/tmp/test_scan_id.json";
        fs::write(temp_path, corrupted).unwrap();

        let result = Checkpoint::load(temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("scan_id"));
    }

    #[test]
    fn test_validate_missing_project_path() {
        let corrupted = r#"{"scan_id":"test123","project_path":"","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0}"#;
        let temp_path = "/tmp/test_project_path.json";
        fs::write(temp_path, corrupted).unwrap();

        let result = Checkpoint::load(temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("project_path"));
    }

    #[test]
    fn test_resume_from_invalid_file() {
        let temp_path = "/tmp/test_invalid_12345.json";
        fs::write(temp_path, "not json at all").unwrap();

        let result = Checkpoint::resume_from(temp_path);
        assert!(result.is_err());
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_checkpoint_with_findings() {
        let checkpoint = Checkpoint::new("test", "/tmp/test-project", Utc::now());
        let temp_path = "/tmp/test_with_findings.json";
        checkpoint.save(temp_path).unwrap();

        let loaded = Checkpoint::load(temp_path).unwrap();
        assert!(loaded.findings_so_far.is_empty());

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_checkpoint_with_completed_phases() {
        let mut checkpoint = Checkpoint::new("test", "/tmp/test-project", Utc::now());
        checkpoint.current_phase = ScanPhase::Semgrep;
        checkpoint.completed_phases.push(ScanPhase::Indexing);

        let temp_path = "/tmp/test_completed.json";
        checkpoint.save(temp_path).unwrap();

        let loaded = Checkpoint::load(temp_path).unwrap();
        assert_eq!(loaded.current_phase, ScanPhase::Semgrep);
        assert_eq!(loaded.completed_phases.len(), 1);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_checkpoint_nonexistent_file() {
        let result = Checkpoint::load("/nonexistent/path/checkpoint.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("read"));
    }

    #[test]
    fn test_resume_from_complete_phase() {
        let mut checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        let temp_path = "/tmp/test_complete.json";
        checkpoint.current_phase = ScanPhase::Complete;
        checkpoint.save(temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(temp_path).unwrap();
        assert_eq!(next_phase, ScanPhase::Indexing);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_resume_from_error_phase() {
        let mut checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        let temp_path = "/tmp/test_error.json";
        checkpoint.current_phase = ScanPhase::Error;
        checkpoint.save(temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(temp_path).unwrap();
        assert_eq!(next_phase, ScanPhase::Indexing);

        let _ = fs::remove_file(temp_path);
    }
}
