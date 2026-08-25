pub mod executor;
pub mod sandbox;
pub mod session;
pub mod tool_schema;
pub mod tools;

use crate::findings::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

pub type ProgressCallback = Box<dyn Fn(String) + Send + Sync>;

pub use session::AgentSession;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub output: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub finding: VulnerabilityFinding,
    #[serde(default)]
    pub compile_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub test_source_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub test_log: Option<String>,
    #[serde(default)]
    pub agent_turns: u32,
    #[serde(default)]
    pub tools_used: Vec<String>,
}

impl AgentFinding {
    pub fn into_finding(self) -> VulnerabilityFinding {
        let mut f = self.finding;

        let evidence_path = self
            .test_source_path
            .map(|p| p.to_string_lossy().into_owned())
            .or_else(|| self.compile_path.map(|p| p.to_string_lossy().into_owned()));

        if let Some(path) = evidence_path {
            f.agent_evidence_path = Some(path);
        } else if self.agent_turns > 0 {
            f.agent_evidence_path = Some(format!(
                "{} turns, {} tools",
                self.agent_turns,
                self.tools_used.len()
            ));
        }

        if let Some(ref log) = self.test_log {
            if f.verification_notes.is_none() {
                f.verification_notes = Some(log.clone());
            }
        }

        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, VulnerabilityFinding};
    use std::path::PathBuf;

    #[test]
    fn test_into_finding_with_evidence_path() {
        let finding = AgentFinding {
            finding: VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Test Finding".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                confidence_score: 0.9,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: true,
                statement_range: None,
                triage_verdict: None,
                evidence: vec![],
                verification_tier: None,
            },
            compile_path: Some(PathBuf::from("/path/to/compile")),
            test_source_path: Some(PathBuf::from("/path/to/test")),
            test_log: None,
            agent_turns: 0,
            tools_used: vec![],
        };

        let result = finding.into_finding();

        assert_eq!(
            result.agent_evidence_path,
            Some("/path/to/test".to_string())
        );
    }

    #[test]
    fn test_into_finding_with_compile_path_only() {
        let finding = AgentFinding {
            finding: VulnerabilityFinding {
                id: "test-2".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: true,
                statement_range: None,
                triage_verdict: None,
                evidence: vec![],
                verification_tier: None,
            },
            compile_path: Some(PathBuf::from("/path/to/compile")),
            test_source_path: None,
            test_log: None,
            agent_turns: 0,
            tools_used: vec![],
        };

        let result = finding.into_finding();

        assert_eq!(
            result.agent_evidence_path,
            Some("/path/to/compile".to_string())
        );
    }

    #[test]
    fn test_into_finding_with_turns_and_tools() {
        let finding = AgentFinding {
            finding: VulnerabilityFinding {
                id: "test-3".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                severity: Severity::Low,
                confidence_score: 0.3,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: true,
                statement_range: None,
                triage_verdict: None,
                evidence: vec![],
                verification_tier: None,
            },
            compile_path: None,
            test_source_path: None,
            test_log: None,
            agent_turns: 5,
            tools_used: vec!["file_read".to_string(), "pattern_search".to_string()],
        };

        let result = finding.into_finding();

        assert_eq!(
            result.agent_evidence_path,
            Some("5 turns, 2 tools".to_string())
        );
    }

    #[test]
    fn test_into_finding_with_test_log() {
        let finding = AgentFinding {
            finding: VulnerabilityFinding {
                id: "test-4".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                severity: Severity::High,
                confidence_score: 0.8,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: true,
                statement_range: None,
                triage_verdict: None,
                evidence: vec![],
                verification_tier: None,
            },
            compile_path: None,
            test_source_path: None,
            test_log: Some("Test execution log".to_string()),
            agent_turns: 0,
            tools_used: vec![],
        };

        let result = finding.into_finding();

        assert_eq!(
            result.verification_notes,
            Some("Test execution log".to_string())
        );
    }

    #[test]
    fn test_into_finding_preserves_existing_verification_notes() {
        let finding = AgentFinding {
            finding: VulnerabilityFinding {
                id: "test-5".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.6,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: Some("Existing notes".to_string()),
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: true,
                statement_range: None,
                triage_verdict: None,
                evidence: vec![],
                verification_tier: None,
            },
            compile_path: None,
            test_source_path: None,
            test_log: Some("New test log".to_string()),
            agent_turns: 0,
            tools_used: vec![],
        };

        let result = finding.into_finding();

        // Should preserve existing notes
        assert_eq!(
            result.verification_notes,
            Some("Existing notes".to_string())
        );
    }
}
pub mod mock_llm;
