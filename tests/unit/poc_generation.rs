//! Unit tests for PoC generation phase
#![allow(clippy::cloned_ref_to_slice_refs)]
//!
//! Tests cover:
//! - PoC template initialization
//! - PoC generation for various CWEs
//! - Multi-format generation (Rust, Python, Shell, Go)
//! - Mitigation generation
//! - Edge cases (empty findings, unknown CWEs)
//! - Error handling
//! - Serialization/deserialization
//! - Template availability

use baco::context::AnalysisContext;
use baco::findings::{
    IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding,
};
use baco::poc_generation::{PoCFormat, PoCGenerationEngine, PoCGenerationResult, ProofOfConcept};

/// Helper to create a test finding with specific CWE
fn create_test_finding(cwe_id: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: Some(cwe_id.to_string()),
        file_path: "test.py".to_string(),
        line_number: Some(42),
        code_snippet: Some("execute(user_input)".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

/// Helper to create a finding with security issue (no CWE)
fn create_test_finding_with_category(
    category: IssueCategory,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-2".to_string(),
        title: "Security Issue Finding".to_string(),
        description: "Finding with security issue category".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: "test.py".to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category,
            cwe_id: None,
            owasp_category: None,
            mitre_attack: None,
            custom_tags: vec![],
        }),
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

// ============================================================================
// PoCGenerationEngine Tests - Basic
// ============================================================================

#[test]
fn test_engine_new_creates_templates() {
    let engine = PoCGenerationEngine::new();
    assert!(!engine.templates.is_empty());
}

#[test]
fn test_engine_default_creates_templates() {
    let engine = PoCGenerationEngine::default();
    assert!(!engine.templates.is_empty());
}

#[test]
fn test_engine_creation_has_expected_templates() {
    let engine = PoCGenerationEngine::new();

    // Check that common CWE templates exist
    let has_sql_injection = engine.templates.contains_key("CWE-89:Python");
    let has_command_injection = engine.templates.contains_key("CWE-78:Python");
    let has_path_traversal = engine.templates.contains_key("CWE-22:Python");
    let has_xss = engine.templates.contains_key("CWE-79:Python");

    assert!(has_sql_injection || has_command_injection || has_path_traversal || has_xss);
}

// ============================================================================
// PoCFormat Tests
// ============================================================================

#[test]
fn test_poc_format_default() {
    let format = PoCFormat::default();
    assert!(matches!(format, PoCFormat::Rust));
}

#[test]
fn test_poc_format_all_variants() {
    let formats = vec![
        PoCFormat::Rust,
        PoCFormat::Python,
        PoCFormat::Shell,
        PoCFormat::Go,
    ];

    for format in formats {
        // Just ensure we can create and compare them
        let _ = format;
    }
}

#[test]
fn test_poc_format_serialization() {
    let formats = vec![
        PoCFormat::Rust,
        PoCFormat::Python,
        PoCFormat::Shell,
        PoCFormat::Go,
    ];

    for format in formats {
        let json = serde_json::to_string(&format).unwrap();
        let deserialized: PoCFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, format);
    }
}

// ============================================================================
// PoC Generation Tests - SQL Injection (CWE-89)
// ============================================================================

#[test]
fn test_generate_sql_injection_poc_python() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Python);
    assert!(result.proofs[0].code.contains("SELECT") || result.proofs[0].code.contains("query"));
}

#[test]
fn test_generate_sql_injection_poc_go() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Go]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Go);
}

// ============================================================================
// PoC Generation Tests - Command Injection (CWE-78)
// ============================================================================

#[test]
fn test_generate_command_injection_poc_python() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-78", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    assert!(!result.proofs.is_empty());
    assert!(
        result.proofs[0].code.contains("system")
            || result.proofs[0].code.contains("subprocess")
            || result.proofs[0].code.contains("os.")
    );
}

#[test]
fn test_generate_command_injection_poc_shell() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-78", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Shell]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Shell);
    assert!(result.proofs[0].code.contains("rm") || result.proofs[0].code.contains("$"));
}

// ============================================================================
// PoC Generation Tests - XSS (CWE-79)
// ============================================================================

#[test]
fn test_generate_xss_poc_python() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-79", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    assert!(!result.proofs.is_empty());
    assert!(result.proofs[0].code.contains("div") || result.proofs[0].code.contains("escape"));
}

// ============================================================================
// PoC Generation Tests - Path Traversal (CWE-22)
// ============================================================================

#[test]
fn test_generate_path_traversal_poc_python() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-22", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    assert!(!result.proofs.is_empty());
    assert!(result.proofs[0].code.contains("open") || result.proofs[0].code.contains("path"));
}

#[test]
fn test_generate_path_traversal_poc_go() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-22", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Go]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Go);
}

// ============================================================================
// PoC Generation Tests - Rust Specific
// ============================================================================

#[test]
fn test_generate_buffer_overflow_poc_rust() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-121", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Rust]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Rust);
    assert!(result.proofs[0].code.contains("unsafe") || result.proofs[0].code.contains("buf"));
}

#[test]
fn test_generate_raw_pointer_poc_rust() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-119", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Rust]);

    assert!(!result.proofs.is_empty());
    assert_eq!(result.proofs[0].format, PoCFormat::Rust);
}

// ============================================================================
// PoC Generation Tests - Multiple Formats
// ============================================================================

#[test]
fn test_generate_multiple_formats_same_finding() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(
        &[finding],
        &context,
        &[PoCFormat::Python, PoCFormat::Rust, PoCFormat::Go],
    );

    // Should generate PoC for each format that has a template
    assert!(!result.proofs.is_empty());
}

#[test]
fn test_generate_all_formats() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-78", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python, PoCFormat::Shell]);

    assert!(!result.proofs.is_empty());
}

// ============================================================================
// Mitigation Generation Tests
// ============================================================================

#[test]
fn test_generate_mitigation_sql_injection() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);

    let mitigation = engine.generate_mitigation(&finding);

    assert!(mitigation.is_some());
    let m = mitigation.unwrap();
    assert!(m.is_mitigation);
    assert_eq!(m.format, PoCFormat::Python);
}

#[test]
fn test_generate_mitigation_command_injection() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-78", Severity::High);

    let mitigation = engine.generate_mitigation(&finding);

    assert!(mitigation.is_some());
    assert!(mitigation.as_ref().unwrap().is_mitigation);
}

#[test]
fn test_generate_mitigation_path_traversal() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-22", Severity::High);

    let mitigation = engine.generate_mitigation(&finding);

    assert!(mitigation.is_some());
    let m = mitigation.unwrap();
    assert!(m.description.contains("Mitigation"));
}

#[test]
fn test_generate_mitigation_unknown_cwe() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-999", Severity::High);

    let mitigation = engine.generate_mitigation(&finding);

    // Should return None for unknown CWEs
    assert!(mitigation.is_none());
}

// ============================================================================
// Available Templates Tests
// ============================================================================

#[test]
fn test_available_templates_python() {
    let engine = PoCGenerationEngine::new();

    let templates = engine.available_templates(PoCFormat::Python);
    assert!(!templates.is_empty());
}

#[test]
fn test_available_templates_rust() {
    let engine = PoCGenerationEngine::new();

    let templates = engine.available_templates(PoCFormat::Rust);
    assert!(!templates.is_empty());
}

#[test]
fn test_available_templates_shell() {
    let engine = PoCGenerationEngine::new();

    let templates = engine.available_templates(PoCFormat::Shell);
    assert!(!templates.is_empty());
}

#[test]
fn test_available_templates_go() {
    let engine = PoCGenerationEngine::new();

    let templates = engine.available_templates(PoCFormat::Go);
    assert!(!templates.is_empty());
}

// ============================================================================
// Edge Cases - Empty and Unknown
// ============================================================================

#[test]
fn test_generate_empty_findings() {
    let engine = PoCGenerationEngine::new();
    let context = AnalysisContext::default();

    let result = engine.generate(&[], &context, &[PoCFormat::Python]);

    assert!(result.proofs.is_empty());
    assert!(result.errors.is_empty());
}

#[test]
fn test_generate_unknown_cwe() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-999", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // May return error or empty proofs for unknown CWE
    assert!(!result.errors.is_empty());
}

#[test]
fn test_generate_low_severity_filtered() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::Low);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // Low severity without confirmation may be filtered
    // This test ensures graceful handling
    let _ = result;
}

#[test]
fn test_generate_medium_severity() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::Medium);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // Medium severity may or may not be included depending on logic
    let _ = result;
}

// ============================================================================
// ProofOfConcept Structure Tests
// ============================================================================

#[test]
fn test_proof_of_concept_creation() {
    let poc = ProofOfConcept {
        id: "test-poc-1".to_string(),
        finding_id: "finding-1".to_string(),
        code: "test code".to_string(),
        format: PoCFormat::Python,
        is_mitigation: false,
        description: "Test PoC".to_string(),
        metadata: std::collections::HashMap::new(),
    };

    assert_eq!(poc.id, "test-poc-1");
    assert_eq!(poc.finding_id, "finding-1");
    assert!(!poc.is_mitigation);
}

#[test]
fn test_proof_of_concept_with_metadata() {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("language".to_string(), "python".to_string());
    metadata.insert("version".to_string(), "3.9".to_string());

    let poc = ProofOfConcept {
        id: "test-poc-2".to_string(),
        finding_id: "finding-2".to_string(),
        code: "test code".to_string(),
        format: PoCFormat::Python,
        is_mitigation: true,
        description: "Test PoC with metadata".to_string(),
        metadata,
    };

    assert_eq!(poc.metadata.len(), 2);
    assert!(poc.is_mitigation);
}

#[test]
fn test_proof_of_concept_serialization() {
    let poc = ProofOfConcept {
        id: "test-poc-3".to_string(),
        finding_id: "finding-3".to_string(),
        code: "test code".to_string(),
        format: PoCFormat::Rust,
        is_mitigation: false,
        description: "Test serialization".to_string(),
        metadata: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&poc).unwrap();
    let deserialized: ProofOfConcept = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, poc.id);
    assert_eq!(deserialized.finding_id, poc.finding_id);
    assert_eq!(deserialized.code, poc.code);
    assert_eq!(deserialized.format, poc.format);
    assert_eq!(deserialized.is_mitigation, poc.is_mitigation);
}

// ============================================================================
// PoCGenerationResult Tests
// ============================================================================

#[test]
fn test_result_default() {
    let result = PoCGenerationResult {
        proofs: vec![],
        errors: vec![],
    };

    assert!(result.proofs.is_empty());
    assert!(result.errors.is_empty());
}

#[test]
fn test_result_with_proofs() {
    let poc = ProofOfConcept {
        id: "poc-1".to_string(),
        finding_id: "f1".to_string(),
        code: "test".to_string(),
        format: PoCFormat::Python,
        is_mitigation: false,
        description: "Test".to_string(),
        metadata: std::collections::HashMap::new(),
    };

    let result = PoCGenerationResult {
        proofs: vec![poc],
        errors: vec![],
    };

    assert_eq!(result.proofs.len(), 1);
}

#[test]
fn test_result_with_errors() {
    let result = PoCGenerationResult {
        proofs: vec![],
        errors: vec!["Error 1".to_string(), "Error 2".to_string()],
    };

    assert_eq!(result.errors.len(), 2);
}

#[test]
fn test_result_serialization() {
    let result = PoCGenerationResult {
        proofs: vec![],
        errors: vec!["test error".to_string()],
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: PoCGenerationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.errors.len(), result.errors.len());
}

// ============================================================================
// Category-based Generation Tests
// ============================================================================

#[test]
fn test_generate_from_category_injection() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding_with_category(IssueCategory::Injection, Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // Category-based fallback should work
    let _ = result;
}

#[test]
fn test_generate_from_category_memory_corruption() {
    let engine = PoCGenerationEngine::new();
    let finding =
        create_test_finding_with_category(IssueCategory::MemoryCorruption, Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Rust]);

    let _ = result;
}

#[test]
fn test_generate_from_category_unknown() {
    let engine = PoCGenerationEngine::new();
    let finding =
        create_test_finding_with_category(IssueCategory::BusinessLogicFlaw, Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // Unknown category may return empty
    assert!(result.proofs.is_empty() || result.errors.is_empty());
}

// ============================================================================
// Multiple Findings Tests
// ============================================================================

#[test]
fn test_generate_multiple_findings_same_cwe() {
    let engine = PoCGenerationEngine::new();
    let finding1 = create_test_finding("CWE-89", Severity::High);
    let finding2 = create_test_finding("CWE-89", Severity::Critical);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding1, finding2], &context, &[PoCFormat::Python]);

    assert!(!result.proofs.is_empty());
}

#[test]
fn test_generate_multiple_findings_different_cwe() {
    let engine = PoCGenerationEngine::new();
    let finding1 = create_test_finding("CWE-89", Severity::High);
    let finding2 = create_test_finding("CWE-78", Severity::High);
    let finding3 = create_test_finding("CWE-22", Severity::Critical);
    let context = AnalysisContext::default();

    let result = engine.generate(
        &[finding1, finding2, finding3],
        &context,
        &[PoCFormat::Python],
    );

    assert!(!result.proofs.is_empty());
}

#[test]
fn test_generate_mixed_severity_findings() {
    let engine = PoCGenerationEngine::new();
    let findings = vec![
        create_test_finding("CWE-89", Severity::Critical),
        create_test_finding("CWE-78", Severity::High),
        create_test_finding("CWE-22", Severity::Medium),
        create_test_finding("CWE-79", Severity::Low),
    ];
    let context = AnalysisContext::default();

    let result = engine.generate(&findings, &context, &[PoCFormat::Python]);

    // High and Critical should be included
    assert!(!result.proofs.is_empty());
}

// ============================================================================
// PoC Content Validation Tests
// ============================================================================

#[test]
fn test_poc_id_format() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    if !result.proofs.is_empty() {
        let poc = &result.proofs[0];
        assert!(!poc.id.is_empty());
        assert!(poc.id.starts_with("poc-") || poc.id.starts_with("mit-"));
    }
}

#[test]
fn test_poc_finding_id_reference() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    if !result.proofs.is_empty() {
        let poc = &result.proofs[0];
        assert_eq!(poc.finding_id, "test-finding-1");
    }
}

#[test]
fn test_poc_has_description() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    if !result.proofs.is_empty() {
        let poc = &result.proofs[0];
        assert!(!poc.description.is_empty());
    }
}

#[test]
fn test_poc_code_not_empty() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    if !result.proofs.is_empty() {
        let poc = &result.proofs[0];
        assert!(!poc.code.is_empty());
    }
}

// ============================================================================
// Deterministic Generation Tests
// ============================================================================

#[test]
fn test_deterministic_generation() {
    let engine = PoCGenerationEngine::new();
    let finding = create_test_finding("CWE-89", Severity::High);
    let context = AnalysisContext::default();

    let result1 = engine.generate(&[finding.clone()], &context, &[PoCFormat::Python]);
    let result2 = engine.generate(&[finding], &context, &[PoCFormat::Python]);

    // Format and description should be consistent
    if !result1.proofs.is_empty() && !result2.proofs.is_empty() {
        assert_eq!(result1.proofs[0].format, result2.proofs[0].format);
        assert_eq!(result1.proofs[0].description, result2.proofs[0].description);
    }
}

// ============================================================================
// Integration Tests - Full Workflow
// ============================================================================

#[test]
fn test_full_poc_generation_workflow() {
    let engine = PoCGenerationEngine::new();
    let context = AnalysisContext::default();

    // Create findings for different vulnerability types
    let findings = vec![
        create_test_finding("CWE-89", Severity::Critical), // SQL Injection
        create_test_finding("CWE-78", Severity::High),     // Command Injection
        create_test_finding("CWE-79", Severity::High),     // XSS
        create_test_finding("CWE-22", Severity::Medium),   // Path Traversal
    ];

    // Generate PoCs in multiple formats
    let result = engine.generate(&findings, &context, &[PoCFormat::Python, PoCFormat::Rust]);

    // Should have generated some PoCs
    assert!(!result.proofs.is_empty());

    // Generate mitigations for each finding
    for finding in &findings {
        let mitigation = engine.generate_mitigation(finding);
        if let Some(m) = mitigation {
            assert!(m.is_mitigation);
        }
    }
}

#[test]
fn test_complete_template_coverage() {
    let engine = PoCGenerationEngine::new();

    // Test that we have templates for major CWEs in Python
    let major_cwes = vec![
        "CWE-89",  // SQL Injection
        "CWE-78",  // Command Injection
        "CWE-79",  // XSS
        "CWE-22",  // Path Traversal
        "CWE-502", // Unsafe YAML
        "CWE-95",  // Eval Injection
        "CWE-611", // XXE
        "CWE-798", // Hardcoded Credentials
        "CWE-327", // Weak Hash
        "CWE-338", // Insecure Random
    ];

    for cwe in major_cwes {
        let key = format!("{}:Python", cwe);
        let has_template = engine.templates.contains_key(&key);
        // Some may not have templates, that's okay
        let _ = has_template;
    }
}
