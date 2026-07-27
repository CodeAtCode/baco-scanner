//! Sequential scanner tests - tests for scanner sequential functionality
//!
//! Note: The sequential module is internal, so we test the ScanPhase enum
//! and related types that are publicly accessible through baco::checkpoint.
//!
//! Tests cover:
//! - ScanPhase enum variants (all phases used in sequential execution)
//! - Severity variants
//! - VulnerabilityFinding structure

use baco::checkpoint::ScanPhase;
use baco::findings::{Severity, VulnerabilityFinding};

// ============================================================================
// ScanPhase variant tests - tests for all sequential phase variants
// ============================================================================

#[test]
fn test_scan_phase_all_variants_exist() {
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
        ScanPhase::RuleSynthesis,
        ScanPhase::Hunt,
        ScanPhase::Validate,
        ScanPhase::IndependentVerify,
        ScanPhase::Complete,
        ScanPhase::Error,
    ];

    assert_eq!(phases.len(), 25);
}

#[test]
fn test_scan_phase_llm_discovery() {
    assert_eq!(format!("{:?}", ScanPhase::LlmDiscovery), "LlmDiscovery");
}

#[test]
fn test_scan_phase_llm_verification() {
    assert_eq!(
        format!("{:?}", ScanPhase::LlmVerification),
        "LlmVerification"
    );
}

#[test]
fn test_scan_phase_security_agent_verification() {
    assert_eq!(
        format!("{:?}", ScanPhase::SecurityAgentVerification),
        "SecurityAgentVerification"
    );
}

#[test]
fn test_scan_phase_ticket_cross_ref() {
    assert_eq!(format!("{:?}", ScanPhase::TicketCrossRef), "TicketCrossRef");
}

#[test]
fn test_scan_phase_git_analysis() {
    assert_eq!(format!("{:?}", ScanPhase::GitAnalysis), "GitAnalysis");
}

#[test]
fn test_scan_phase_cross_file_analysis() {
    assert_eq!(
        format!("{:?}", ScanPhase::CrossFileAnalysis),
        "CrossFileAnalysis"
    );
}

#[test]
fn test_scan_phase_confidence_scoring() {
    assert_eq!(
        format!("{:?}", ScanPhase::ConfidenceScoring),
        "ConfidenceScoring"
    );
}

#[test]
fn test_scan_phase_ai_aggregation() {
    assert_eq!(format!("{:?}", ScanPhase::AiAggregation), "AiAggregation");
}

#[test]
fn test_scan_phase_reporting() {
    assert_eq!(format!("{:?}", ScanPhase::Reporting), "Reporting");
}

#[test]
fn test_scan_phase_threat_modeling() {
    assert_eq!(format!("{:?}", ScanPhase::ThreatModeling), "ThreatModeling");
}

#[test]
fn test_scan_phase_root_cause_dedup() {
    assert_eq!(format!("{:?}", ScanPhase::RootCauseDedup), "RootCauseDedup");
}

#[test]
fn test_scan_phase_multi_verifier() {
    assert_eq!(format!("{:?}", ScanPhase::MultiVerifier), "MultiVerifier");
}

#[test]
fn test_scan_phase_auto_patching() {
    assert_eq!(format!("{:?}", ScanPhase::AutoPatching), "AutoPatching");
}

#[test]
fn test_scan_phase_cve_bootstrap() {
    assert_eq!(format!("{:?}", ScanPhase::CveBootstrap), "CveBootstrap");
}

#[test]
fn test_scan_phase_poc_compiler() {
    assert_eq!(format!("{:?}", ScanPhase::PocCompiler), "PocCompiler");
}

#[test]
fn test_scan_phase_variant_search() {
    assert_eq!(format!("{:?}", ScanPhase::VariantSearch), "VariantSearch");
}

#[test]
fn test_scan_phase_equality() {
    assert_eq!(ScanPhase::LlmDiscovery, ScanPhase::LlmDiscovery);
    assert_ne!(ScanPhase::LlmDiscovery, ScanPhase::Reporting);
}

#[test]
fn test_scan_phase_clone() {
    let phase = ScanPhase::LlmDiscovery;
    let cloned = phase.clone();
    assert_eq!(phase, cloned);
}

// ============================================================================
// Severity variant tests
// ============================================================================

#[test]
fn test_severity_all_variants() {
    let variants = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    assert_eq!(variants.len(), 4);
}

#[test]
fn test_severity_debug_format_low() {
    assert_eq!(format!("{:?}", Severity::Low), "Low");
}

#[test]
fn test_severity_debug_format_medium() {
    assert_eq!(format!("{:?}", Severity::Medium), "Medium");
}

#[test]
fn test_severity_debug_format_high() {
    assert_eq!(format!("{:?}", Severity::High), "High");
}

#[test]
fn test_severity_debug_format_critical() {
    assert_eq!(format!("{:?}", Severity::Critical), "Critical");
}

#[test]
fn test_severity_equality() {
    assert_eq!(Severity::High, Severity::High);
    assert_ne!(Severity::High, Severity::Medium);
}

// ============================================================================
// VulnerabilityFinding field tests
// ============================================================================

#[test]
fn test_finding_creation_with_critical_severity() {
    let finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Critical,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("test_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["test".to_string()],
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
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    };

    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.title, "Test Finding");
    assert_eq!(finding.file_path, "src/test.rs");
    assert_eq!(finding.line_number, Some(42));
}

#[test]
fn test_finding_optional_fields_none() {
    let finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        severity: Severity::Low,
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
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    };

    assert!(finding.cwe_id.is_none());
    assert!(finding.line_number.is_none());
    assert!(finding.code_snippet.is_none());
    assert!(finding.diff_hunk.is_none());
    assert!(finding.recommendation.is_none());
}

#[test]
fn test_finding_sources_empty() {
    let finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
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
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    };

    assert!(finding.sources.is_empty());
}

#[test]
fn test_finding_already_reported_flag() {
    let mut finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
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
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    };

    assert!(!finding.already_reported);
    finding.already_reported = true;
    assert!(finding.already_reported);
}

#[test]
fn test_finding_agent_mode_flag() {
    let finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.7,
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
    };

    assert!(finding.agent_mode);
}

// ============================================================================
// Cross-type tests
// ============================================================================

#[test]
fn test_finding_with_all_phases() {
    // Verify we can create findings for all scan phases
    let phases = vec![
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
    ];

    for phase in phases {
        let _finding = VulnerabilityFinding {
            id: format!("{:?}", phase),
            title: format!("Finding for {:?}", phase),
            description: "Test".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![format!("{:?}", phase)],
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
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        };
    }
}
