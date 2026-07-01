//! Tests for LLM verification functionality
//!
//! Covers: ExtendedVerificationPhase, verify_finding, calculate_refined_confidence,
//! has_sanitization, is_known_false_positive_pattern, render_template

use baco::context::AnalysisContext;
use baco::findings::VulnerabilityFinding;
use baco::findings::{IssueCategory, SecurityIssue, Severity, VerificationStatus};
use baco::llm_verification::{
    render_template, ExtendedVerificationPhase, VerificationReport, VerificationResult,
};
use baco::project_type::ProjectType;

fn make_test_finding(title: &str, severity: Severity, code: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: code.map(|s| s.to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["static_analysis".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category: IssueCategory::Injection,
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("Injection".to_string()),
            mitre_attack: None,
            custom_tags: vec!["test".to_string()],
        }),
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

#[test]
fn test_verification_phase_initialization_web() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Web);
    assert!(!phase.security_practices().is_empty());
    assert!(phase
        .security_practices()
        .iter()
        .any(|p| p.contains("Input")));
}

#[test]
fn test_verification_phase_initialization_cli() {
    let phase = ExtendedVerificationPhase::new(ProjectType::CLI, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::CLI);
    assert!(phase
        .security_practices()
        .iter()
        .any(|p| p.contains("Argument")));
}

#[test]
fn test_verification_phase_initialization_library() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Library, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Library);
}

#[test]
fn test_verification_phase_initialization_embedded() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Embedded, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Embedded);
    assert!(phase
        .security_practices()
        .iter()
        .any(|p| p.contains("buffer overflow")));
}

#[test]
fn test_has_sanitization_escape() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("escape(user_input)"));
    assert!(phase.has_sanitization("escapeHtml(data)"));
}

#[test]
fn test_has_sanitization_sanitize() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("sanitize(input)"));
    assert!(phase.has_sanitization("sanitize_sql(query)"));
}

#[test]
fn test_has_sanitization_validate() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("validate(input)"));
    assert!(phase.has_sanitization("validate_email(email)"));
}

#[test]
fn test_has_sanitization_parameterized() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("parameterized_query"));
    assert!(phase.has_sanitization("prepared_statement"));
}

#[test]
fn test_has_sanitization_no_sanitization() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(!phase.has_sanitization("exec(user_input)"));
    assert!(!phase.has_sanitization("raw_query"));
}

#[test]
fn test_is_known_false_positive_pattern_test() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("test code"));
    assert!(phase.is_known_false_positive_pattern("unit_test"));
}

#[test]
fn test_is_known_false_positive_pattern_mock() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("mock_data"));
    assert!(phase.is_known_false_positive_pattern("mock_server"));
}

#[test]
fn test_is_known_false_positive_pattern_todo() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("TODO: fix this"));
    assert!(phase.is_known_false_positive_pattern("FIXME: later"));
}

#[test]
fn test_is_known_false_positive_pattern_unreachable() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("if false"));
    assert!(phase.is_known_false_positive_pattern("dead_code"));
}

#[test]
fn test_is_known_false_positive_pattern_real_code() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(!phase.is_known_false_positive_pattern("real_production_code"));
    assert!(!phase.is_known_false_positive_pattern("actual_implementation"));
}

#[test]
fn test_is_cwe_known_false_positive() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_cwe_known_false_positive("CWE-190"));
    assert!(phase.is_cwe_known_false_positive("CWE-191"));
    assert!(phase.is_cwe_known_false_positive("CWE-754"));
    assert!(!phase.is_cwe_known_false_positive("CWE-79"));
    assert!(!phase.is_cwe_known_false_positive("CWE-89"));
}

#[test]
fn test_calculate_refined_confidence_no_mitigations() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Test", Severity::Medium, Some("code"));
    let mitigating_factors: Vec<String> = vec![];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    assert_eq!(confidence, 0.7); // No change
}

#[test]
fn test_calculate_refined_confidence_with_mitigations() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Test", Severity::Medium, Some("code"));
    let mitigating_factors = vec![
        "Input validation".to_string(),
        "Output encoding".to_string(),
    ];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    assert_eq!(confidence, 0.5); // 0.7 - 0.1 * 2
}

#[test]
fn test_calculate_refined_confidence_high_severity_boost() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Critical Issue", Severity::Critical, Some("code"));
    let mitigating_factors: Vec<String> = vec![];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    assert_eq!(confidence, 0.8); // 0.7 + 0.1 for high severity
}

#[test]
fn test_calculate_refined_confidence_already_reported_reduction() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let mut finding = make_test_finding("Test", Severity::Medium, Some("code"));
    finding.already_reported = true;

    let mitigating_factors: Vec<String> = vec![];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    assert_eq!(confidence, 0.65); // 0.7 - 0.05
}

#[test]
fn test_calculate_refined_confidence_confidence_bounds() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Test", Severity::Medium, Some("code"));
    let mitigating_factors = vec![
        "Factor 1".to_string(),
        "Factor 2".to_string(),
        "Factor 3".to_string(),
        "Factor 4".to_string(),
        "Factor 5".to_string(),
    ];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    // Should be clamped to 0.0 minimum
    assert!(confidence >= 0.0);
    assert!(confidence <= 1.0);
}

#[test]
fn test_render_template_basic() {
    let template = "Hello %%NAME%%!";
    let mut variables = std::collections::HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello World!");
}

#[test]
fn test_render_template_multiple_variables() {
    let template = "Verify %%TITLE%% in %%FILE%%";
    let mut variables = std::collections::HashMap::new();
    variables.insert("TITLE".to_string(), "SQL Injection".to_string());
    variables.insert("FILE".to_string(), "src/db.rs".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Verify SQL Injection in src/db.rs");
}

#[test]
fn test_render_template_curly_braces() {
    let template = "Hello {{NAME}}!";
    let mut variables = std::collections::HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello World!");
}

#[test]
fn test_render_template_no_variables() {
    let template = "No variables here!";
    let variables = std::collections::HashMap::new();

    let result = render_template(template, &variables);

    assert_eq!(result, "No variables here!");
}

#[test]
fn test_render_template_missing_variable() {
    let template = "Hello %%NAME%%!";
    let variables = std::collections::HashMap::new();

    let result = render_template(template, &variables);

    // Variable not replaced
    assert_eq!(result, "Hello %%NAME%%!");
}

#[test]
fn test_verification_result_serialization() {
    let result = VerificationResult {
        finding_id: "test-001".to_string(),
        status: VerificationStatus::Confirmed,
        confidence: 0.85,
        notes: "Verified".to_string(),
        mitigating_factors: vec!["Input validation".to_string()],
        related_patterns: vec!["CWE-79".to_string()],
        false_positive_reason: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.finding_id, "test-001");
    assert_eq!(deserialized.status, VerificationStatus::Confirmed);
    assert_eq!(deserialized.confidence, 0.85);
}

#[test]
fn test_verification_report_serialization() {
    let report = VerificationReport {
        total_findings: 10,
        confirmed: 5,
        false_positives: 2,
        needs_review: 3,
        failed: 0,
        results: vec![],
        average_confidence: 0.75,
        high_confidence_findings: vec!["id1".to_string()],
    };

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.total_findings, 10);
    assert_eq!(deserialized.confirmed, 5);
    assert_eq!(deserialized.false_positives, 2);
}

#[test]
fn test_verify_finding_with_sanitization() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("XSS", Severity::High, Some("escape(user_input)"));
    let result = phase.verify_finding(&finding);

    assert!(!result.mitigating_factors.is_empty());
    assert!(result
        .related_patterns
        .contains(&"sanitization_present".to_string()));
}

#[test]
fn test_verify_finding_false_positive_pattern() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Test Issue", Severity::Low, Some("test code here"));
    let result = phase.verify_finding(&finding);

    assert_eq!(result.status, VerificationStatus::FalsePositive);
    assert!(result.false_positive_reason.is_some());
}

#[test]
fn test_verify_finding_no_mitigations() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Critical Vuln", Severity::Critical, Some("exec(cmd)"));
    let result = phase.verify_finding(&finding);

    assert!(result.mitigating_factors.is_empty());
    assert_eq!(result.status, VerificationStatus::Confirmed);
}

#[test]
fn test_verify_finding_cwe_known_fp() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let mut finding = make_test_finding("Test", Severity::Medium, Some("code"));
    finding.security_issue = Some(SecurityIssue {
        category: IssueCategory::Custom("Other".to_string()),
        cwe_id: Some("CWE-190".to_string()), // Known FP
        owasp_category: None,
        mitre_attack: None,
        custom_tags: vec![],
    });

    let result = phase.verify_finding(&finding);

    assert!(result.false_positive_reason.is_some());
    assert!(result.false_positive_reason.unwrap().contains("CWE-190"));
}

#[test]
fn test_security_practices_content() {
    let web_practices = ExtendedVerificationPhase::get_security_practices(ProjectType::Web);

    assert!(web_practices.iter().any(|p| p.contains("Input validation")));
    assert!(web_practices.iter().any(|p| p.contains("Parameterized")));
    assert!(web_practices.iter().any(|p| p.contains("XSS")));
    assert!(web_practices.iter().any(|p| p.contains("CSRF")));

    let cli_practices = ExtendedVerificationPhase::get_security_practices(ProjectType::CLI);
    assert!(cli_practices.iter().any(|p| p.contains("Argument")));
    assert!(cli_practices.iter().any(|p| p.contains("shell")));

    let embedded_practices =
        ExtendedVerificationPhase::get_security_practices(ProjectType::Embedded);
    assert!(embedded_practices
        .iter()
        .any(|p| p.contains("buffer overflow")));
}
