//! Unit tests for cross-file analysis.
//!
//! This module tests cross-file reference detection and analysis.
use baco::crossfile::CrossFileAnalyzer;
use baco::findings::{Severity, VulnerabilityFinding};

// ============================================================================
// test_cross_file_analysis()
// ============================================================================

#[test]
fn test_cross_file_analysis() {
    let findings = vec![];
    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
    assert!(result.is_empty());
}

// ============================================================================
// test_analyze_with_findings()
// ============================================================================

#[test]
fn test_analyze_with_findings() {
    let findings = vec![VulnerabilityFinding {
        id: "test1".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: "src/main.c".to_string(),
        line_number: Some(10),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: Some(vec!["src/utils.c".to_string()]),
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
        evidence: vec![],
        verification_tier: None,
    }];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
    assert_eq!(result.len(), 1);
}

// ============================================================================
// test_multi_file_findings_same_cwe()
// ============================================================================

#[test]
fn test_multi_file_findings_same_cwe() {
    let findings = vec![
        VulnerabilityFinding {
            id: "find1".to_string(),
            title: "SQL Injection in auth".to_string(),
            description: "SQL injection in authentication".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/auth.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
        VulnerabilityFinding {
            id: "find2".to_string(),
            title: "SQL Injection in query".to_string(),
            description: "SQL injection in query builder".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.85,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/query.rs".to_string(),
            line_number: Some(100),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
    ];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 2);

    let auth_finding = result.iter().find(|f| f.id == "find1").unwrap();
    assert!(auth_finding.cross_file_references.is_some());
    let refs = auth_finding.cross_file_references.as_ref().unwrap();
    assert!(refs.contains(&"find2".to_string()));

    let query_finding = result.iter().find(|f| f.id == "find2").unwrap();
    assert!(query_finding.cross_file_references.is_some());
    let refs = query_finding.cross_file_references.as_ref().unwrap();
    assert!(refs.contains(&"find1".to_string()));
}

// ============================================================================
// test_cross_file_taint_tracking_same_severity_source()
// ============================================================================

#[test]
fn test_cross_file_taint_tracking_same_severity_source() {
    let findings = vec![
        VulnerabilityFinding {
            id: "source1".to_string(),
            title: "User input source".to_string(),
            description: "Unsanitized user input".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: None,
            file_path: "src/api/handler.rs".to_string(),
            line_number: Some(15),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["user_input".to_string(), "request_body".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
        VulnerabilityFinding {
            id: "sink1".to_string(),
            title: "Database sink".to_string(),
            description: "Direct database write".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "src/db/connector.rs".to_string(),
            line_number: Some(200),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["user_input".to_string(), "db_write".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
    ];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 2);

    let source_finding = result.iter().find(|f| f.id == "source1").unwrap();
    assert!(source_finding.cross_file_references.is_some());
    let refs = source_finding.cross_file_references.as_ref().unwrap();
    assert!(refs.contains(&"sink1".to_string()));

    let sink_finding = result.iter().find(|f| f.id == "sink1").unwrap();
    assert!(sink_finding.cross_file_references.is_some());
    let refs = sink_finding.cross_file_references.as_ref().unwrap();
    assert!(refs.contains(&"source1".to_string()));
}

// ============================================================================
// test_no_findings_empty_input()
// ============================================================================

#[test]
fn test_no_findings_empty_input() {
    let findings: Vec<VulnerabilityFinding> = vec![];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert!(result.is_empty());
}

// ============================================================================
// test_single_file_no_cross_reference()
// ============================================================================

#[test]
fn test_single_file_no_cross_reference() {
    let findings = vec![
        VulnerabilityFinding {
            id: "find1".to_string(),
            title: "Issue 1".to_string(),
            description: "Description 1".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/main.rs".to_string(),
            line_number: Some(10),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
        VulnerabilityFinding {
            id: "find2".to_string(),
            title: "Issue 2".to_string(),
            description: "Description 2".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.7,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/main.rs".to_string(),
            line_number: Some(50),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
    ];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 2);

    for finding in &result {
        assert!(
            finding.cross_file_references.is_none(),
            "Same-file findings should not have cross_file_references"
        );
    }
}

// ============================================================================
// test_mixed_same_and_different_cwe()
// ============================================================================

#[test]
fn test_mixed_same_and_different_cwe() {
    let findings = vec![
        VulnerabilityFinding {
            id: "cwe1_a".to_string(),
            title: "XSS in handler".to_string(),
            description: "Cross-site scripting".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/handler.rs".to_string(),
            line_number: Some(25),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
        VulnerabilityFinding {
            id: "cwe1_b".to_string(),
            title: "XSS in template".to_string(),
            description: "Cross-site scripting in template".to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/template.rs".to_string(),
            line_number: Some(60),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
        VulnerabilityFinding {
            id: "cwe2".to_string(),
            title: "Path traversal".to_string(),
            description: "Directory traversal".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.8,
            cwe_id: Some("CWE-22".to_string()),
            file_path: "src/files.rs".to_string(),
            line_number: Some(100),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            evidence: vec![],
            verification_tier: None,
        },
    ];

    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 3);

    let cwe1_a = result.iter().find(|f| f.id == "cwe1_a").unwrap();
    let cwe1_b = result.iter().find(|f| f.id == "cwe1_b").unwrap();
    let cwe2 = result.iter().find(|f| f.id == "cwe2").unwrap();

    assert!(cwe1_a.cross_file_references.is_some());
    assert!(cwe1_a
        .cross_file_references
        .as_ref()
        .unwrap()
        .contains(&"cwe1_b".to_string()));

    assert!(cwe1_b.cross_file_references.is_some());
    assert!(cwe1_b
        .cross_file_references
        .as_ref()
        .unwrap()
        .contains(&"cwe1_a".to_string()));

    assert!(cwe2.cross_file_references.is_none());
}
