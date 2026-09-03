//! Comprehensive unit tests for agent module
//!
//! Migrated from src/agent/mod.rs inline tests

use baco::agent::AgentFinding;
use baco::findings::{Severity, VulnerabilityFinding};
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
