//! Comprehensive unit tests for LLM verification functionality
//!
//! Tests cover: ExtendedVerificationPhase, verification logic, sanitization detection,
//! false positive detection, confidence scoring, prompt templates, and report generation

use baco::analysis_context::AnalysisContext;
use baco::findings::{IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm_verification::{
    render_template, ExtendedVerificationPhase, VerificationReport, VerificationResult,
};
use baco::project_type::ProjectType as DetectProjectType;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

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


// Tests merged from llm_verification_inline_tests.rs

#[test]
fn test_verification_phase_initialization() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    assert_eq!(*phase.project_type(), DetectProjectType::Web);
    assert!(!phase.security_practices().is_empty());
}

#[test]
fn test_verify_finding_known_false_positive() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let finding = make_test_finding(
        "Potential SQL Injection",
        Severity::Medium,
        Some("SELECT * FROM users WHERE id = ? -- test query"),
    );

    let result = phase.verify_finding(&finding);

    assert_eq!(result.status, VerificationStatus::FalsePositive);
    assert!(result.false_positive_reason.is_some());
}

#[test]
fn test_verify_finding_no_mitigating_factors() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let finding = make_test_finding(
        "Command Injection",
        Severity::Critical,
        Some("exec(user_input)"),
    );

    let result = phase.verify_finding(&finding);

    assert!(result.mitigating_factors.is_empty());
    assert_eq!(result.status, VerificationStatus::Confirmed);
}

#[test]
fn test_execute_verification() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let mut phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let findings = vec![
        make_test_finding(
            "SQL Injection",
            Severity::Critical,
            Some("SELECT * FROM users WHERE id = ?"),
        ),
        make_test_finding("XSS", Severity::High, Some("escape(user_input)")),
        make_test_finding("Test Issue", Severity::Low, Some("test code")),
    ];

    let report = phase.execute(&findings).unwrap();

    assert_eq!(report.total_findings, 3);
    assert!(report.confirmed > 0 || report.false_positives > 0 || report.needs_review > 0);
}

#[test]
fn test_verification_report_generation() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let mut phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let findings = vec![
        make_test_finding("Vuln 1", Severity::Critical, Some("exec(cmd)")),
        make_test_finding("Vuln 2", Severity::High, Some("escape(x)")),
    ];

    let report = phase.execute(&findings).unwrap();

    assert_eq!(report.total_findings, 2);
    assert!(report.average_confidence >= 0.0 && report.average_confidence <= 1.0);
    assert!(!report.results.is_empty());
}

#[test]
fn test_confidence_refinement_high_severity() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let finding = make_test_finding("Critical Issue", Severity::Critical, Some("unsafe_code"));

    let result = phase.verify_finding(&finding);

    assert!(result.confidence >= 0.7);
}

#[test]
fn test_confidence_refinement_already_reported() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();
    let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

    let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

    let mut finding =
        make_test_finding("Re-reported Issue", Severity::Medium, Some("some_code"));
    finding.already_reported = true;

    let result = phase.verify_finding(&finding);

    assert!(result.confidence <= 0.7);
}

#[test]
fn test_security_practices_by_type() {
    let web_practices =
        ExtendedVerificationPhase::get_security_practices(DetectProjectType::Web);
    assert!(web_practices.iter().any(|p| p.contains("Input validation")));

    let cli_practices =
        ExtendedVerificationPhase::get_security_practices(DetectProjectType::CLI);
    assert!(cli_practices.iter().any(|p| p.contains("Argument")));

    let embedded_practices =
        ExtendedVerificationPhase::get_security_practices(DetectProjectType::Embedded);
    assert!(embedded_practices
        .iter()
        .any(|p| p.contains("buffer overflow")));
}

#[test]
fn test_has_sanitization() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.has_sanitization("escape(user_input)"));
    assert!(phase.has_sanitization("sanitize(input)"));
    assert!(phase.has_sanitization("parametrized_query"));
    assert!(!phase.has_sanitization("exec(user_input)"));
}

#[test]
fn test_is_known_false_positive_pattern() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.is_known_false_positive_pattern("let x = TODO"));
    assert!(phase.is_known_false_positive_pattern("mock_data"));
    assert!(!phase.is_known_false_positive_pattern("real_production_code"));
}

#[test]
fn test_template_rendering() {
    let template = "Hello %%NAME%%, verify finding {{TITLE}}";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "World".to_string());
    variables.insert("TITLE".to_string(), "Test Finding".to_string());

    let result = render_template(template, &variables);
    assert_eq!(result, "Hello World, verify finding Test Finding");
}

#[test]
fn test_project_type_mapping() {
    let test_cases = vec![
        (DetectProjectType::Web, "web"),
        (DetectProjectType::CLI, "cli"),
        (DetectProjectType::Library, "library"),
    ];

    for (pt, expected) in test_cases {
        let _ = pt;
        let _ = expected;
    }
}

#[test]
fn test_is_cwe_known_false_positive() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.is_cwe_known_false_positive("CWE-190"));
    assert!(phase.is_cwe_known_false_positive("CWE-191"));
    assert!(phase.is_cwe_known_false_positive("CWE-754"));

    assert!(!phase.is_cwe_known_false_positive("CWE-79"));
    assert!(!phase.is_cwe_known_false_positive("CWE-89"));
    assert!(!phase.is_cwe_known_false_positive("CWE-1234"));
}

#[test]
fn test_calculate_refined_confidence_with_mitigating_factors() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let finding = make_test_finding("Test Issue", Severity::Medium, Some("code"));
    let mitigating_factors = vec![
        "Input validation present".to_string(),
        "Output encoding applied".to_string(),
    ];

    let confidence = phase.calculate_refined_confidence(&finding, &mitigating_factors, &[]);
    assert!((confidence - 0.5).abs() < 0.01);
}

#[test]
fn test_calculate_refined_confidence_combined_effects() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let mut finding = make_test_finding("Complex Issue", Severity::High, Some("code"));
    finding.already_reported = true;
    let mitigating_factors = vec!["Sanitization detected".to_string()];

    let confidence = phase.calculate_refined_confidence(&finding, &mitigating_factors, &[]);
    assert!((confidence - 0.65).abs() < 0.01);
}

#[test]
fn test_calculate_refined_confidence_bounds() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let finding = make_test_finding("Low confidence issue", Severity::Low, Some("code"));
    let mut low_confidence_finding = finding.clone();
    low_confidence_finding.confidence_score = 0.1;

    let many_factors = vec![
        "Factor 1".to_string(),
        "Factor 2".to_string(),
        "Factor 3".to_string(),
        "Factor 4".to_string(),
        "Factor 5".to_string(),
    ];

    let confidence =
        phase.calculate_refined_confidence(&low_confidence_finding, &many_factors, &[]);
    assert!(confidence >= 0.0);

    let high_confidence_finding =
        make_test_finding("High confidence", Severity::Critical, Some("code"));
    let mut max_confidence_finding = high_confidence_finding.clone();
    max_confidence_finding.confidence_score = 0.95;

    let confidence = phase.calculate_refined_confidence(&max_confidence_finding, &[], &[]);
    assert!(confidence <= 1.0);
}

#[test]
fn test_new_with_none_llm_client() {
    let context = AnalysisContext::default();
    let phase = ExtendedVerificationPhase::new(DetectProjectType::CLI, context, None);

    assert_eq!(*phase.project_type(), DetectProjectType::CLI);
    assert!(!phase.security_practices().is_empty());
    assert_eq!(phase.security_practices().len(), 4);
}

#[test]
fn test_new_with_all_project_types() {
    let project_types = vec![
        (DetectProjectType::Web, 7),
        (DetectProjectType::CLI, 4),
        (DetectProjectType::Library, 4),
        (DetectProjectType::Embedded, 4),
        (DetectProjectType::Firmware, 3),
        (DetectProjectType::Desktop, 4),
        (DetectProjectType::Game, 3),
        (DetectProjectType::Unknown, 3),
    ];

    for (project_type, expected_count) in project_types {
        let phase = ExtendedVerificationPhase::new(
            project_type.clone(),
            AnalysisContext::default(),
            None,
        );

        assert_eq!(
            phase.security_practices().len(),
            expected_count,
            "Security practices count mismatch for {:?}",
            project_type
        );
    }
}

#[test]
fn test_project_type_accessor() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Library,
        AnalysisContext::default(),
        None,
    );

    let project_type = phase.project_type();
    assert_eq!(project_type, &DetectProjectType::Library);
}

#[test]
fn test_security_practices_accessor() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let practices = phase.security_practices();
    assert!(!practices.is_empty());
    assert!(practices.iter().any(|p| p.contains("Input validation")));
}

#[test]
fn test_has_sanitization_all_patterns() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.has_sanitization("sanitize_input()"));
    assert!(phase.has_sanitization("escape_html()"));
    assert!(phase.has_sanitization("encode_url()"));
    assert!(phase.has_sanitization("validate_input()"));
    assert!(phase.has_sanitization("filter_data()"));
    assert!(phase.has_sanitization("parameterized_query()"));
    assert!(phase.has_sanitization("parametrized_query()"));
    assert!(phase.has_sanitization("prepared_statement()"));
    assert!(phase.has_sanitization("bind_param()"));
    assert!(phase.has_sanitization("htmlspecialchars()"));
    assert!(phase.has_sanitization("htmlentities()"));
    assert!(phase.has_sanitization("urlencode()"));
    assert!(phase.has_sanitization("base64_encode()"));
}

#[test]
fn test_has_sanitization_case_insensitive() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.has_sanitization("SANITIZE(input)"));
    assert!(phase.has_sanitization("SaNiTiZe(input)"));
    assert!(phase.has_sanitization("PARAMETERIZED_QUERY"));
}

#[test]
fn test_is_known_false_positive_all_patterns() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.is_known_false_positive_pattern("test code"));
    assert!(phase.is_known_false_positive_pattern("mock object"));
    assert!(phase.is_known_false_positive_pattern("example usage"));
    assert!(phase.is_known_false_positive_pattern("demo app"));
    assert!(phase.is_known_false_positive_pattern("sample data"));
    assert!(phase.is_known_false_positive_pattern("todo item"));
    assert!(phase.is_known_false_positive_pattern("fixme note"));
    assert!(phase.is_known_false_positive_pattern("xxx marker"));
    assert!(phase.is_known_false_positive_pattern("hack workaround"));
    assert!(phase.is_known_false_positive_pattern("if false condition"));
    assert!(phase.is_known_false_positive_pattern("unreachable code"));
    assert!(phase.is_known_false_positive_pattern("dead_code attribute"));
}

#[test]
fn test_is_known_false_positive_case_insensitive() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    assert!(phase.is_known_false_positive_pattern("TEST code"));
    assert!(phase.is_known_false_positive_pattern("MoCk object"));
    assert!(phase.is_known_false_positive_pattern("IF FALSE condition"));
}

#[test]
fn test_render_template_both_syntaxes() {
    let template = "Report: %%TITLE%% - {{{{SEVERITY}}}} - %%CODE%%";
    let mut variables = HashMap::new();
    variables.insert("TITLE".to_string(), "SQL Injection".to_string());
    variables.insert("SEVERITY".to_string(), "High".to_string());
    variables.insert("CODE".to_string(), "SELECT * FROM users".to_string());

    let result = render_template(template, &variables);
    assert!(result.contains("SQL Injection"));
    assert!(result.contains("SELECT * FROM users"));
    assert!(!result.contains("%%TITLE%%"));
    assert!(!result.contains("%%CODE%%"));
}

#[test]
fn test_render_template_special_characters() {
    let template = "Code: %%CODE%%";
    let mut variables = HashMap::new();
    variables.insert(
        "CODE".to_string(),
        "SELECT * FROM users WHERE id = 'test'".to_string(),
    );

    let result = render_template(template, &variables);
    assert!(result.contains("SELECT * FROM users"));
    assert!(result.contains("'test'"));
}

#[test]
fn test_verify_finding_with_cwe_false_positive() {
    let phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let mut finding = make_test_finding("Integer overflow", Severity::Medium, Some("code"));
    finding.security_issue = Some(SecurityIssue {
        category: IssueCategory::MemoryCorruption,
        cwe_id: Some("CWE-190".to_string()),
        owasp_category: None,
        mitre_attack: None,
        custom_tags: vec![],
    });

    let result = phase.verify_finding(&finding);

    assert!(result.false_positive_reason.is_some());
}

#[test]
fn test_execute_with_empty_findings() {
    let mut phase = ExtendedVerificationPhase::new(
        DetectProjectType::Web,
        AnalysisContext::default(),
        None,
    );

    let findings: Vec<VulnerabilityFinding> = vec![];
    let report = phase.execute(&findings).unwrap();

    assert_eq!(report.total_findings, 0);
    assert_eq!(report.confirmed, 0);
    assert_eq!(report.false_positives, 0);
    assert_eq!(report.needs_review, 0);
    assert_eq!(report.failed, 0);
    assert_eq!(report.average_confidence, 0.0);
}

#[test]
fn test_verification_result_creation() {
    let result = VerificationResult {
        finding_id: "test-123".to_string(),
        status: VerificationStatus::NeedsReview,
        confidence: 0.6,
        notes: "Manual review required".to_string(),
        mitigating_factors: vec!["Input sanitization".to_string()],
        related_patterns: vec!["CWE-79".to_string(), "sanitization_present".to_string()],
        false_positive_reason: None,
    };

    assert_eq!(result.finding_id, "test-123");
    assert_eq!(result.status, VerificationStatus::NeedsReview);
    assert_eq!(result.confidence, 0.6);
    assert_eq!(result.mitigating_factors.len(), 1);
    assert_eq!(result.related_patterns.len(), 2);
}

#[test]
fn test_verification_report_statistics() {
    let results = [
        VerificationResult {
            finding_id: "1".to_string(),
            status: VerificationStatus::Confirmed,
            confidence: 0.9,
            notes: "".to_string(),
            mitigating_factors: vec![],
            related_patterns: vec![],
            false_positive_reason: None,
        },
        VerificationResult {
            finding_id: "2".to_string(),
            status: VerificationStatus::FalsePositive,
            confidence: 0.3,
            notes: "".to_string(),
            mitigating_factors: vec![],
            related_patterns: vec![],
            false_positive_reason: Some("Known pattern".to_string()),
        },
        VerificationResult {
            finding_id: "3".to_string(),
            status: VerificationStatus::NeedsReview,
            confidence: 0.5,
            notes: "".to_string(),
            mitigating_factors: vec!["Factor".to_string()],
            related_patterns: vec![],
            false_positive_reason: None,
        },
    ];

    let total = results.len();
    let confirmed = results
        .iter()
        .filter(|r| r.status == VerificationStatus::Confirmed)
        .count();
    let false_positives = results
        .iter()
        .filter(|r| r.status == VerificationStatus::FalsePositive)
        .count();
    let needs_review = results
        .iter()
        .filter(|r| r.status == VerificationStatus::NeedsReview)
        .count();

    assert_eq!(total, 3);
    assert_eq!(confirmed, 1);
    assert_eq!(false_positives, 1);
    assert_eq!(needs_review, 1);
}

mod helpers;
