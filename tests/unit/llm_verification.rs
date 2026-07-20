//! Comprehensive unit tests for LLM verification functionality
//!
//! Tests cover: ExtendedVerificationPhase, verification logic, sanitization detection,
//! false positive detection, confidence scoring, prompt templates, and report generation

use baco::analysis_context::AnalysisContext;
use baco::findings::{IssueCategory, SecurityIssue, Severity, VerificationStatus};
use baco::llm_verification::{
    render_template, ExtendedVerificationPhase, VerificationReport, VerificationResult,
};
use baco::project_type::ProjectType;
use std::collections::HashMap;

// Import consolidated test helpers
use crate::helpers::llm::make_test_finding;

// ============================================================================
// Extension Verification Phase Initialization Tests
// ============================================================================

#[test]
fn test_verification_phase_initialization_web() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Web);
    assert!(!phase.security_practices().is_empty());
    assert_eq!(phase.security_practices().len(), 7); // Web has 7 practices
}

#[test]
fn test_verification_phase_initialization_cli() {
    let phase = ExtendedVerificationPhase::new(ProjectType::CLI, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::CLI);
    assert_eq!(phase.security_practices().len(), 4); // CLI has 4 practices
}

#[test]
fn test_verification_phase_initialization_library() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Library, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Library);
    assert_eq!(phase.security_practices().len(), 4);
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
fn test_verification_phase_initialization_firmware() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Firmware, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Firmware);
    assert!(phase
        .security_practices()
        .iter()
        .any(|p| p.contains("hardcoded")));
}

#[test]
fn test_verification_phase_initialization_desktop() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Desktop, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Desktop);
}

#[test]
fn test_verification_phase_initialization_game() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Game, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Game);
}

#[test]
fn test_verification_phase_initialization_unknown() {
    let phase =
        ExtendedVerificationPhase::new(ProjectType::Unknown, AnalysisContext::default(), None);

    assert_eq!(*phase.project_type(), ProjectType::Unknown);
    assert_eq!(phase.security_practices().len(), 3); // Unknown has 3 practices
}

// ============================================================================
// Sanitization Detection Tests
// ============================================================================

#[test]
fn test_has_sanitization_escape() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("escape(user_input)"));
    assert!(phase.has_sanitization("escapeHtml(data)"));
    assert!(phase.has_sanitization("htmlspecialchars($var)"));
}

#[test]
fn test_has_sanitization_sanitize() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("sanitize(input)"));
    assert!(phase.has_sanitization("sanitize_sql(query)"));
    assert!(phase.has_sanitization("sanitize_html(content)"));
}

#[test]
fn test_has_sanitization_validate() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("validate(input)"));
    assert!(phase.has_sanitization("validate_email(email)"));
    assert!(phase.has_sanitization("filter_input($var)"));
}

#[test]
fn test_has_sanitization_parameterized_queries() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("parameterized_query"));
    assert!(phase.has_sanitization("prepared_statement"));
    assert!(phase.has_sanitization("bind_param"));
}

#[test]
fn test_has_sanitization_encoding() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.has_sanitization("urlencode($var)"));
    assert!(phase.has_sanitization("base64_encode($data)"));
    assert!(phase.has_sanitization("htmlentities($str)"));
}

#[test]
fn test_has_sanitization_no_sanitization() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(!phase.has_sanitization("exec(user_input)"));
    assert!(!phase.has_sanitization("raw_query"));
    assert!(!phase.has_sanitization("system(command)"));
}

// ============================================================================
// False Positive Pattern Detection Tests
// ============================================================================

#[test]
fn test_is_known_false_positive_pattern_test() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("test code"));
    assert!(phase.is_known_false_positive_pattern("unit_test"));
    assert!(phase.is_known_false_positive_pattern("integration_test"));
}

#[test]
fn test_is_known_false_positive_pattern_mock() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("mock_data"));
    assert!(phase.is_known_false_positive_pattern("mock_server"));
    assert!(phase.is_known_false_positive_pattern("mock_database"));
}

#[test]
fn test_is_known_false_positive_pattern_examples() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("example code"));
    assert!(phase.is_known_false_positive_pattern("sample_data"));
    assert!(phase.is_known_false_positive_pattern("demo_function"));
}

#[test]
fn test_is_known_false_positive_pattern_todo() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("TODO: fix this"));
    assert!(phase.is_known_false_positive_pattern("FIXME: later"));
    assert!(phase.is_known_false_positive_pattern("xxx warning"));
}

#[test]
fn test_is_known_false_positive_pattern_unreachable() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("if false"));
    assert!(phase.is_known_false_positive_pattern("dead_code"));
    assert!(phase.is_known_false_positive_pattern("unreachable code"));
}

#[test]
fn test_is_known_false_positive_pattern_real_code() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(!phase.is_known_false_positive_pattern("real_production_code"));
    assert!(!phase.is_known_false_positive_pattern("actual_implementation"));
    assert!(!phase.is_known_false_positive_pattern("business_logic"));
}

#[test]
fn test_is_known_false_positive_pattern_hack() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_known_false_positive_pattern("hack: temporary fix"));
}

// ============================================================================
// CWE False Positive Detection Tests
// ============================================================================

#[test]
fn test_is_cwe_known_false_positive_overflow() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_cwe_known_false_positive("CWE-190")); // Integer overflow
}

#[test]
fn test_is_cwe_known_false_positive_underflow() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_cwe_known_false_positive("CWE-191")); // Integer underflow
}

#[test]
fn test_is_cwe_known_false_positive_division() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(phase.is_cwe_known_false_positive("CWE-754")); // Division by zero
}

#[test]
fn test_is_cwe_known_false_positive_real_issues() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    assert!(!phase.is_cwe_known_false_positive("CWE-79")); // XSS
    assert!(!phase.is_cwe_known_false_positive("CWE-89")); // SQL Injection
    assert!(!phase.is_cwe_known_false_positive("CWE-119")); // Buffer overflow
}

// ============================================================================
// Confidence Score Refinement Tests
// ============================================================================

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
fn test_calculate_refined_confidence_with_one_mitigation() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let finding = make_test_finding("Test", Severity::Medium, Some("code"));
    let mitigating_factors = vec!["Input validation".to_string()];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    assert_eq!(confidence, 0.6); // 0.7 - 0.1 * 1
}

#[test]
fn test_calculate_refined_confidence_with_multiple_mitigations() {
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
fn test_calculate_refined_confidence_confidence_lower_bound() {
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
    assert_eq!(confidence, 0.0);
}

#[test]
fn test_calculate_refined_confidence_confidence_upper_bound() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let mut finding = make_test_finding("Critical", Severity::Critical, Some("code"));
    finding.confidence_score = 0.95; // Start high
    let mitigating_factors: Vec<String> = vec![];
    let related_patterns: Vec<String> = vec![];

    let confidence =
        phase.calculate_refined_confidence(&finding, &mitigating_factors, &related_patterns);

    // Should be clamped to 1.0 maximum (0.95 + 0.1 = 1.05 -> 1.0)
    assert_eq!(confidence, 1.0);
}

// ============================================================================
// Template Rendering Tests
// ============================================================================

#[test]
fn test_render_template_percent_syntax() {
    let template = "Hello %%NAME%%!";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello World!");
}

#[test]
fn test_render_template_curly_braces_syntax() {
    let template = "Hello {{NAME}}!";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello World!");
}

#[test]
fn test_render_template_multiple_variables() {
    let template = "Verify %%TITLE%% in {{FILE}}";
    let mut variables = HashMap::new();
    variables.insert("TITLE".to_string(), "SQL Injection".to_string());
    variables.insert("FILE".to_string(), "src/db.rs".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Verify SQL Injection in src/db.rs");
}

#[test]
fn test_render_template_no_variables() {
    let template = "No variables here!";
    let variables = HashMap::new();

    let result = render_template(template, &variables);

    assert_eq!(result, "No variables here!");
}

#[test]
fn test_render_template_missing_variable_unchanged() {
    let template = "Hello %%NAME%%!";
    let variables = HashMap::new();

    let result = render_template(template, &variables);

    // Variable not replaced, stays as-is
    assert_eq!(result, "Hello %%NAME%%!");
}

#[test]
fn test_render_template_empty_template() {
    let template = "";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "");
}

#[test]
fn test_render_template_empty_variables() {
    let template = "Static text only";
    let variables = HashMap::new();

    let result = render_template(template, &variables);

    assert_eq!(result, "Static text only");
}

// ============================================================================
// Verification Result Tests
// ============================================================================

#[test]
fn test_verification_result_serialization() {
    let result = VerificationResult {
        finding_id: "test-001".to_string(),
        status: VerificationStatus::Confirmed,
        confidence: 0.85,
        notes: "Verified via heuristic".to_string(),
        mitigating_factors: vec!["Input validation".to_string()],
        related_patterns: vec!["CWE-79".to_string()],
        false_positive_reason: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.finding_id, "test-001");
    assert_eq!(deserialized.status, VerificationStatus::Confirmed);
    assert_eq!(deserialized.confidence, 0.85);
    assert_eq!(deserialized.mitigating_factors.len(), 1);
}

#[test]
fn test_verification_result_false_positive_serialization() {
    let result = VerificationResult {
        finding_id: "test-002".to_string(),
        status: VerificationStatus::FalsePositive,
        confidence: 0.3,
        notes: "Known false positive".to_string(),
        mitigating_factors: vec![],
        related_patterns: vec!["test_code".to_string()],
        false_positive_reason: Some("Test code detected".to_string()),
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.status, VerificationStatus::FalsePositive);
    assert!(deserialized.false_positive_reason.is_some());
}

// ============================================================================
// Verification Report Tests
// ============================================================================

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
        high_confidence_findings: vec!["id1".to_string(), "id2".to_string()],
    };

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.total_findings, 10);
    assert_eq!(deserialized.confirmed, 5);
    assert_eq!(deserialized.false_positives, 2);
    assert_eq!(deserialized.needs_review, 3);
}

#[test]
fn test_verification_report_empty_results() {
    let report = VerificationReport {
        total_findings: 0,
        confirmed: 0,
        false_positives: 0,
        needs_review: 0,
        failed: 0,
        results: vec![],
        average_confidence: 0.0,
        high_confidence_findings: vec![],
    };

    assert_eq!(report.total_findings, 0);
    assert_eq!(report.average_confidence, 0.0);
}

// ============================================================================
// Full Verification Flow Tests
// ============================================================================

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
fn test_verify_finding_no_mitigations_confirmed() {
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
}

#[test]
fn test_verify_finding_needs_review_with_mitigations() {
    let phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    // Finding with sanitization but not a known FP -> NeedsReview
    let finding = make_test_finding("Potential Issue", Severity::Medium, Some("sanitize(input)"));
    let result = phase.verify_finding(&finding);

    // Has mitigating factors but not a false positive -> NeedsReview
    assert_eq!(result.status, VerificationStatus::NeedsReview);
}

// ============================================================================
// Execution and Report Generation Tests
// ============================================================================

#[test]
fn test_execute_verification_multiple_findings() {
    let mut phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let findings = vec![
        make_test_finding("SQL Injection", Severity::Critical, Some("exec(query)")),
        make_test_finding("XSS", Severity::High, Some("escape(input)")),
        make_test_finding("Test Code", Severity::Low, Some("test_mock_data")),
    ];

    let report = phase.execute(&findings).unwrap();

    assert_eq!(report.total_findings, 3);
    assert!(report.confirmed + report.false_positives + report.needs_review + report.failed == 3);
}

#[test]
fn test_execute_verification_empty_findings() {
    let mut phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];

    let report = phase.execute(&findings).unwrap();

    assert_eq!(report.total_findings, 0);
    assert_eq!(report.confirmed, 0);
    assert_eq!(report.false_positives, 0);
    assert_eq!(report.average_confidence, 0.0);
}

#[test]
fn test_report_high_confidence_findings() {
    let mut phase = ExtendedVerificationPhase::new(ProjectType::Web, AnalysisContext::default(), None);

    let findings = vec![
        make_test_finding("Critical 1", Severity::Critical, Some("exec(cmd1)")),
        make_test_finding("Critical 2", Severity::Critical, Some("exec(cmd2)")),
        make_test_finding("Low", Severity::Low, Some("test_code")),
    ];

    let report = phase.execute(&findings).unwrap();

    // High confidence findings should be those with confidence >= 0.7 and Confirmed status
    // This test verifies the field exists and logic runs
    assert!(report.high_confidence_findings.len() <= report.confirmed);
}

// ============================================================================
// Security Practices Tests
// ============================================================================

#[test]
fn test_security_practices_web_content() {
    let practices = ExtendedVerificationPhase::get_security_practices(ProjectType::Web);

    assert!(practices.iter().any(|p| p.contains("Input validation")));
    assert!(practices.iter().any(|p| p.contains("Parameterized")));
    assert!(practices.iter().any(|p| p.contains("XSS")));
    assert!(practices.iter().any(|p| p.contains("CSRF")));
    assert!(practices.iter().any(|p| p.contains("Session")));
    assert!(practices.iter().any(|p| p.contains("Authentication")));
    assert!(practices.iter().any(|p| p.contains("Authorization")));
}

#[test]
fn test_security_practices_cli_content() {
    let practices = ExtendedVerificationPhase::get_security_practices(ProjectType::CLI);

    assert!(practices.iter().any(|p| p.contains("Argument")));
    assert!(practices.iter().any(|p| p.contains("shell")));
    assert!(practices.iter().any(|p| p.contains("traversal")));
    assert!(practices.iter().any(|p| p.contains("temporary")));
}

#[test]
fn test_security_practices_library_content() {
    let practices = ExtendedVerificationPhase::get_security_practices(ProjectType::Library);

    assert!(practices.iter().any(|p| p.contains("panic")));
    assert!(practices.iter().any(|p| p.contains("thread-safe")));
    assert!(practices.iter().any(|p| p.contains("error handling")));
    assert!(practices.iter().any(|p| p.contains("unsafe")));
}

#[test]
fn test_get_security_practices_all_types() {
    // Verify all project types return non-empty practices
    let types = vec![
        ProjectType::Web,
        ProjectType::CLI,
        ProjectType::Library,
        ProjectType::Embedded,
        ProjectType::Firmware,
        ProjectType::Desktop,
        ProjectType::Game,
        ProjectType::Unknown,
    ];

    for pt in types {
        let practices = ExtendedVerificationPhase::get_security_practices(pt.clone());
        assert!(!practices.is_empty(), "ProjectType {:?} should have practices", pt);
    }
}

mod helpers;
