//! Unit tests for cross-file analysis phase
//!
//! Tests cover:
//! - Cross-file pattern matching
//! - Dependency analysis
//! - Data flow detection
//! - Import/export issue detection
//! - Configuration inconsistency detection
//! - Edge cases (empty files, missing dependencies)
//! - Error handling
//! - Serialization/deserialization

use baco::context::AnalysisContext;
use baco::cross_file_analysis::{
    ConfigInconsistency, CrossFileAnalysisPhase, CrossFileAnalysisResult, CrossFileFinding,
    CrossFileVulnerabilityType, DataFlowStep, DataFlowType, ImportExportIssue,
    ImportExportIssueType, ModuleBoundaryTracker,
};
use baco::findings::{
    IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding,
};

/// Helper to create a finding with custom parameters
fn create_finding(
    id: &str,
    title: &str,
    severity: Severity,
    cwe_id: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: cwe_id.map(|s| s.to_string()),
        file_path: "src/test.rs".to_string(),
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
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

/// Helper to create a finding with security issue
fn create_finding_with_security_issue(
    id: &str,
    category: IssueCategory,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Security Issue Finding".to_string(),
        description: "Finding with security issue".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: "src/test.rs".to_string(),
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
// CrossFileAnalysisPhase Tests
// ============================================================================

#[test]
fn test_phase_creation() {
    let phase = CrossFileAnalysisPhase::new();
    assert!(phase.boundary_tracker().is_entry_point("pub fn test()"));
}

#[test]
fn test_phase_default() {
    let phase = CrossFileAnalysisPhase::default();
    assert!(phase.boundary_tracker().is_sensitive_sink("eval(x)"));
}

#[test]
fn test_run_empty_findings() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let result = phase.run(vec![], &context);

    assert!(result.cross_file_findings.is_empty());
    assert!(result.import_export_issues.is_empty());
    assert!(result.config_inconsistencies.is_empty());
    assert!(result.analyzed_files.is_empty());
    assert_eq!(result.statistics.total_files, 0);
    assert_eq!(result.statistics.files_with_vulnerabilities, 0);
    assert_eq!(result.statistics.total_chains, 0);
    assert_eq!(result.statistics.import_export_issues_count, 0);
    assert_eq!(result.statistics.config_issues_count, 0);
}

#[test]
fn test_run_single_finding() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));

    let result = phase.run(vec![finding], &context);

    assert_eq!(result.analyzed_files.len(), 1);
    assert!(result.analyzed_files.contains(&"src/test.rs".to_string()));
    assert_eq!(result.statistics.total_files, 1);
}

#[test]
fn test_run_multiple_findings_same_file() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Finding 1", Severity::High, Some("CWE-79")),
        create_finding("f2", "Finding 2", Severity::Medium, Some("CWE-89")),
        create_finding("f3", "Finding 3", Severity::Critical, Some("CWE-22")),
    ];

    let result = phase.run(findings, &context);

    // All findings are in the same file
    assert_eq!(result.statistics.total_files, 1);
}

#[test]
fn test_run_findings_different_files() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let mut finding1 = create_finding("f1", "Finding 1", Severity::High, Some("CWE-79"));
    finding1.file_path = "src/main.rs".to_string();

    let mut finding2 = create_finding("f2", "Finding 2", Severity::Medium, Some("CWE-89"));
    finding2.file_path = "src/utils.rs".to_string();

    let mut finding3 = create_finding("f3", "Finding 3", Severity::Critical, Some("CWE-22"));
    finding3.file_path = "src/lib.rs".to_string();

    let result = phase.run(vec![finding1, finding2, finding3], &context);

    assert_eq!(result.statistics.total_files, 3);
    assert!(result.analyzed_files.contains(&"src/main.rs".to_string()));
    assert!(result.analyzed_files.contains(&"src/utils.rs".to_string()));
    assert!(result.analyzed_files.contains(&"src/lib.rs".to_string()));
}

#[test]
fn test_run_with_cross_file_references() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));
    finding.cross_file_references = Some(vec![
        "src/utils.rs".to_string(),
        "src/helpers.rs".to_string(),
    ]);

    let result = phase.run(vec![finding], &context);

    assert!(result.analyzed_files.contains(&"src/utils.rs".to_string()));
    assert!(result
        .analyzed_files
        .contains(&"src/helpers.rs".to_string()));
    assert!(result.analyzed_files.contains(&"src/test.rs".to_string()));
}

#[test]
fn test_run_with_context() {
    let phase = CrossFileAnalysisPhase::new();

    let context = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Test architecture".to_string(),
        threat_model: Some("Test threat model".to_string()),
        invariants: vec!["Test invariant".to_string()],
        findings_so_far: vec!["previous finding".to_string()],
    };

    let finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));

    let result = phase.run(vec![finding], &context);

    assert_eq!(result.statistics.total_files, 1);
}

// ============================================================================
// ModuleBoundaryTracker Tests
// ============================================================================

#[test]
fn test_tracker_creation() {
    let tracker = ModuleBoundaryTracker::new();
    assert!(tracker.is_entry_point("pub fn test()"));
    assert!(tracker.is_sensitive_sink("eval(x)"));
    assert!(tracker.is_input_source("request.params"));
}

#[test]
fn test_tracker_default() {
    let tracker = ModuleBoundaryTracker::default();
    assert!(tracker.is_entry_point("export function test()"));
}

#[test]
fn test_is_entry_point_various_formats() {
    let tracker = ModuleBoundaryTracker::new();

    // Rust public functions
    assert!(tracker.is_entry_point("pub fn handle_request()"));
    assert!(tracker.is_entry_point("pub async fn process_data()"));
    assert!(tracker.is_entry_point("pub fn* stream_handler()"));

    // JavaScript/TypeScript exports
    assert!(tracker.is_entry_point("export function getUser()"));
    assert!(tracker.is_entry_point("export async function fetchData()"));

    // Python functions
    assert!(tracker.is_entry_point("def main()"));
    assert!(tracker.is_entry_point("async def process_request()"));

    // Private/internal functions should not be entry points
    assert!(!tracker.is_entry_point("fn internal_helper()"));
    assert!(!tracker.is_entry_point("function privateFunc()"));
    assert!(!tracker.is_entry_point("def _private_method()"));
}

#[test]
fn test_is_sensitive_sink_various_sinks() {
    let tracker = ModuleBoundaryTracker::new();

    // Code execution sinks
    assert!(tracker.is_sensitive_sink("eval(user_input)"));
    assert!(tracker.is_sensitive_sink("exec(cmd)"));
    assert!(tracker.is_sensitive_sink("system(command)"));
    assert!(tracker.is_sensitive_sink("shell_exec(cmd)"));
    assert!(tracker.is_sensitive_sink("popen(cmd)"));

    // File operations
    assert!(tracker.is_sensitive_sink("writeFile(path, data)"));
    assert!(tracker.is_sensitive_sink("write_file(path, data)"));

    // Database/Query operations
    assert!(tracker.is_sensitive_sink("execute(query)"));
    assert!(tracker.is_sensitive_sink("db.query(sql)"));

    // Safe operations should not be sinks
    assert!(!tracker.is_sensitive_sink("console.log(message)"));
    assert!(!tracker.is_sensitive_sink("print(message)"));
    assert!(!tracker.is_sensitive_sink("log.info(data)"));
}

#[test]
fn test_is_input_source_various_sources() {
    let tracker = ModuleBoundaryTracker::new();

    // HTTP request sources
    assert!(tracker.is_input_source("let name = request.params.name"));
    assert!(tracker.is_input_source("let query = request.query"));
    assert!(tracker.is_input_source("let body = request.body"));
    assert!(tracker.is_input_source("let headers = request.headers"));
    assert!(tracker.is_input_source("let cookie = request.cookie"));

    // Session and input sources
    assert!(tracker.is_input_source("let session = request.session"));
    assert!(tracker.is_input_source("let input = argv[1]"));
    assert!(tracker.is_input_source("let data = stdin.read()"));
    assert!(tracker.is_input_source("let env = environ['KEY']"));
    assert!(tracker.is_input_source("let val = getenv('PATH')"));

    // Non-input sources should not match
    assert!(!tracker.is_input_source("let config = read_file()"));
    assert!(!tracker.is_input_source("let data = internal_var"));
    assert!(!tracker.is_input_source("const x = 42"));
}

#[test]
fn test_analyze_data_flow_external_input_to_sink() {
    let tracker = ModuleBoundaryTracker::new();

    // Test input detection
    let input_code = "let user_input = request.params.input;";
    let input_flow = tracker.analyze_data_flow(input_code, "test.rs");
    let input_steps: Vec<_> = input_flow
        .iter()
        .filter(|s| matches!(s.flow_type, DataFlowType::ExternalInput))
        .collect();
    assert!(!input_steps.is_empty(), "Should detect external input");

    // Test sink detection
    let sink_code = "let result = eval(user_input);";
    let sink_flow = tracker.analyze_data_flow(sink_code, "test.rs");
    let sink_steps: Vec<_> = sink_flow
        .iter()
        .filter(|s| matches!(s.flow_type, DataFlowType::VulnerabilitySink))
        .collect();
    assert!(!sink_steps.is_empty(), "Should detect eval sink");
}

#[test]
fn test_analyze_data_flow_entry_point() {
    let tracker = ModuleBoundaryTracker::new();

    let code = "pub async fn handle_request() {";

    let flow = tracker.analyze_data_flow(code, "test.rs");

    let entry_points: Vec<_> = flow
        .iter()
        .filter(|s| matches!(s.flow_type, DataFlowType::FunctionCall))
        .collect();
    assert!(!entry_points.is_empty(), "Should detect entry point");
}

#[test]
fn test_analyze_data_flow_empty_code() {
    let tracker = ModuleBoundaryTracker::new();

    let flow = tracker.analyze_data_flow("", "test.rs");

    assert!(flow.is_empty());
}

#[test]
fn test_analyze_data_flow_no_patterns() {
    let tracker = ModuleBoundaryTracker::new();

    let code = r#"
        let x = 42;
        let y = x + 1;
        println!("{}", y);
    "#;

    let flow = tracker.analyze_data_flow(code, "test.rs");

    assert!(flow.is_empty());
}

// ============================================================================
// CrossFileFinding Tests
// ============================================================================

#[test]
fn test_cross_file_finding_creation() {
    let finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));

    let cross_finding = CrossFileFinding {
        primary_finding: finding,
        involved_files: vec!["src/main.rs".to_string(), "src/utils.rs".to_string()],
        data_flow: vec![],
        import_export_issues: vec![],
        config_inconsistencies: vec![],
        vulnerability_type: CrossFileVulnerabilityType::InputValidationChain,
    };

    assert_eq!(cross_finding.involved_files.len(), 2);
    assert!(matches!(
        cross_finding.vulnerability_type,
        CrossFileVulnerabilityType::InputValidationChain
    ));
}

#[test]
fn test_cross_file_finding_serialization() {
    let finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));

    let cross_finding = CrossFileFinding {
        primary_finding: finding,
        involved_files: vec!["src/main.rs".to_string()],
        data_flow: vec![],
        import_export_issues: vec![],
        config_inconsistencies: vec![],
        vulnerability_type: CrossFileVulnerabilityType::InjectionChain,
    };

    let json = serde_json::to_string(&cross_finding).unwrap();
    let deserialized: CrossFileFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.involved_files, cross_finding.involved_files);
    assert!(matches!(
        deserialized.vulnerability_type,
        CrossFileVulnerabilityType::InjectionChain
    ));
}

// ============================================================================
// DataFlowStep Tests
// ============================================================================

#[test]
fn test_data_flow_step_creation() {
    let step = DataFlowStep {
        file: "test.rs".to_string(),
        line: Some(42),
        description: "Test step".to_string(),
        flow_type: DataFlowType::FunctionCall,
    };

    assert_eq!(step.file, "test.rs");
    assert_eq!(step.line, Some(42));
    assert!(matches!(step.flow_type, DataFlowType::FunctionCall));
}

#[test]
fn test_data_flow_step_serialization() {
    let step = DataFlowStep {
        file: "test.rs".to_string(),
        line: Some(42),
        description: "Test step".to_string(),
        flow_type: DataFlowType::ParameterPassing,
    };

    let json = serde_json::to_string(&step).unwrap();
    let deserialized: DataFlowStep = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.file, step.file);
    assert_eq!(deserialized.line, step.line);
    assert_eq!(deserialized.description, step.description);
    assert!(matches!(
        deserialized.flow_type,
        DataFlowType::ParameterPassing
    ));
}

#[test]
fn test_data_flow_step_without_line() {
    let step = DataFlowStep {
        file: "test.rs".to_string(),
        line: None,
        description: "Test step without line".to_string(),
        flow_type: DataFlowType::StateStorage,
    };

    assert!(step.line.is_none());
}

// ============================================================================
// DataFlowType Tests
// ============================================================================

#[test]
fn test_all_data_flow_types() {
    let types = vec![
        DataFlowType::FunctionCall,
        DataFlowType::ParameterPassing,
        DataFlowType::StateStorage,
        DataFlowType::EnvironmentVariable,
        DataFlowType::ConfigFile,
        DataFlowType::ExternalInput,
        DataFlowType::VulnerabilitySink,
    ];

    for flow_type in types {
        let step = DataFlowStep {
            file: "test.rs".to_string(),
            line: Some(1),
            description: "Test".to_string(),
            flow_type,
        };

        let json = serde_json::to_string(&step).unwrap();
        let _deserialized: DataFlowStep = serde_json::from_str(&json).unwrap();
    }
}

// ============================================================================
// ImportExportIssue Tests
// ============================================================================

#[test]
fn test_import_export_issue_creation() {
    let issue = ImportExportIssue {
        file: "src/main.rs".to_string(),
        line: Some(42),
        issue_type: ImportExportIssueType::UnsafeImport,
        description: "Unsafe eval usage".to_string(),
    };

    assert_eq!(issue.file, "src/main.rs");
    assert!(matches!(
        issue.issue_type,
        ImportExportIssueType::UnsafeImport
    ));
}

#[test]
fn test_import_export_issue_serialization() {
    let issue = ImportExportIssue {
        file: "src/main.rs".to_string(),
        line: Some(42),
        issue_type: ImportExportIssueType::MissingExportProtection,
        description: "Missing export protection".to_string(),
    };

    let json = serde_json::to_string(&issue).unwrap();
    let deserialized: ImportExportIssue = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.file, issue.file);
    assert!(matches!(
        deserialized.issue_type,
        ImportExportIssueType::MissingExportProtection
    ));
}

#[test]
fn test_all_import_export_issue_types() {
    let issue_types = vec![
        ImportExportIssueType::UnsafeImport,
        ImportExportIssueType::MissingExportProtection,
        ImportExportIssueType::CircularImport,
        ImportExportIssueType::DynamicImport,
        ImportExportIssueType::ReExportUnsafe,
    ];

    for issue_type in issue_types {
        let issue = ImportExportIssue {
            file: "test.rs".to_string(),
            line: Some(1),
            issue_type,
            description: "Test".to_string(),
        };

        let json = serde_json::to_string(&issue).unwrap();
        let _deserialized: ImportExportIssue = serde_json::from_str(&json).unwrap();
    }
}

// ============================================================================
// ConfigInconsistency Tests
// ============================================================================

#[test]
fn test_config_inconsistency_creation() {
    let mut values = std::collections::HashMap::new();
    values.insert("file1.rs".to_string(), "value1".to_string());
    values.insert("file2.rs".to_string(), "value2".to_string());

    let inconsistency = ConfigInconsistency {
        config_key: "SECRET_KEY".to_string(),
        values_by_file: values,
        severity: Severity::Medium,
        description: "Config inconsistency".to_string(),
    };

    assert_eq!(inconsistency.config_key, "SECRET_KEY");
    assert_eq!(inconsistency.values_by_file.len(), 2);
    assert!(matches!(inconsistency.severity, Severity::Medium));
}

#[test]
fn test_config_inconsistency_serialization() {
    let mut values = std::collections::HashMap::new();
    values.insert("file1.rs".to_string(), "value1".to_string());

    let inconsistency = ConfigInconsistency {
        config_key: "API_KEY".to_string(),
        values_by_file: values,
        severity: Severity::High,
        description: "API key inconsistency".to_string(),
    };

    let json = serde_json::to_string(&inconsistency).unwrap();
    let deserialized: ConfigInconsistency = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.config_key, inconsistency.config_key);
    assert_eq!(deserialized.values_by_file, inconsistency.values_by_file);
}

// ============================================================================
// CrossFileVulnerabilityType Tests
// ============================================================================

#[test]
fn test_all_cross_file_vulnerability_types() {
    let vuln_types = vec![
        CrossFileVulnerabilityType::InputValidationChain,
        CrossFileVulnerabilityType::AuthBypassChain,
        CrossFileVulnerabilityType::DataLeakageChain,
        CrossFileVulnerabilityType::PathTraversalChain,
        CrossFileVulnerabilityType::InjectionChain,
        CrossFileVulnerabilityType::ConfigDrift,
        CrossFileVulnerabilityType::UnsafeDependencyChain,
        CrossFileVulnerabilityType::Custom("custom_type".to_string()),
    ];

    for vuln_type in vuln_types {
        let json = serde_json::to_string(&vuln_type).unwrap();
        let _deserialized: CrossFileVulnerabilityType = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn test_custom_vulnerability_type() {
    let vuln_type = CrossFileVulnerabilityType::Custom("my_custom_type".to_string());

    let json = serde_json::to_string(&vuln_type).unwrap();
    let deserialized: CrossFileVulnerabilityType = serde_json::from_str(&json).unwrap();

    match deserialized {
        CrossFileVulnerabilityType::Custom(s) => assert_eq!(s, "my_custom_type"),
        _ => panic!("Expected Custom type"),
    }
}

// ============================================================================
// CrossFileAnalysisResult Tests
// ============================================================================

#[test]
fn test_result_default() {
    let result = CrossFileAnalysisResult::default();

    assert!(result.cross_file_findings.is_empty());
    assert!(result.import_export_issues.is_empty());
    assert!(result.config_inconsistencies.is_empty());
    assert!(result.analyzed_files.is_empty());
}

#[test]
fn test_result_serialization() {
    let mut result = CrossFileAnalysisResult::default();
    result.cross_file_findings.push(CrossFileFinding {
        primary_finding: create_finding("f1", "Test", Severity::High, Some("CWE-79")),
        involved_files: vec!["src/main.rs".to_string()],
        data_flow: vec![],
        import_export_issues: vec![],
        config_inconsistencies: vec![],
        vulnerability_type: CrossFileVulnerabilityType::InputValidationChain,
    });

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: CrossFileAnalysisResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.cross_file_findings.len(), 1);
}

// ============================================================================
// CrossFileAnalysisStats Tests
// ============================================================================

#[test]
fn test_stats_default() {
    let stats = baco::cross_file_analysis::CrossFileAnalysisStats::default();

    assert_eq!(stats.total_files, 0);
    assert_eq!(stats.files_with_vulnerabilities, 0);
    assert_eq!(stats.total_chains, 0);
    assert_eq!(stats.import_export_issues_count, 0);
    assert_eq!(stats.config_issues_count, 0);
}

#[test]
fn test_stats_update() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Finding 1", Severity::High, Some("CWE-79")),
        create_finding("f2", "Finding 2", Severity::Medium, Some("CWE-89")),
    ];

    let result = phase.run(findings, &context);

    assert!(result.statistics.total_files > 0);
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

#[test]
fn test_analysis_with_empty_code_snippet() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));
    finding.code_snippet = None;

    let result = phase.run(vec![finding], &context);

    // Should handle gracefully without data flow
    assert_eq!(result.analyzed_files.len(), 1);
}

#[test]
fn test_analysis_with_empty_data_flow() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));
    finding.code_snippet = Some("console.log('safe code')".to_string());

    let result = phase.run(vec![finding], &context);

    // Finding with no data flow patterns should still be analyzed
    assert_eq!(result.statistics.total_files, 1);
}

#[test]
fn test_multiple_findings_with_cross_references() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let mut finding1 = create_finding("f1", "Finding 1", Severity::High, Some("CWE-79"));
    finding1.cross_file_references = Some(vec!["src/utils.rs".to_string()]);

    let mut finding2 = create_finding("f2", "Finding 2", Severity::Medium, Some("CWE-89"));
    finding2.file_path = "src/utils.rs".to_string();
    finding2.cross_file_references = Some(vec!["src/main.rs".to_string()]);

    let result = phase.run(vec![finding1, finding2], &context);

    // Both files should be in analyzed_files
    assert!(result.analyzed_files.contains(&"src/main.rs".to_string()));
    assert!(result.analyzed_files.contains(&"src/utils.rs".to_string()));
}

#[test]
fn test_severity_variety() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Critical", Severity::Critical, Some("CWE-79")),
        create_finding("f2", "High", Severity::High, Some("CWE-89")),
        create_finding("f3", "Medium", Severity::Medium, Some("CWE-22")),
        create_finding("f4", "Low", Severity::Low, Some("CWE-287")),
        create_finding("f5", "Info", Severity::Info, Some("CWE-552")),
    ];

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_files, 1);
}

#[test]
fn test_deterministic_analysis() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let finding = create_finding("f1", "Test finding", Severity::High, Some("CWE-79"));

    // Run twice and compare results
    let result1 = phase.run(vec![finding.clone()], &context);
    let result2 = phase.run(vec![finding], &context);

    assert_eq!(
        result1.statistics.total_files,
        result2.statistics.total_files
    );
    assert_eq!(result1.analyzed_files.len(), result2.analyzed_files.len());
}

// ============================================================================
// Integration Tests with SecurityIssue
// ============================================================================

#[test]
fn test_analysis_with_security_issue_category() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let finding =
        create_finding_with_security_issue("f1", IssueCategory::Injection, Severity::High);

    let result = phase.run(vec![finding], &context);

    assert_eq!(result.statistics.total_files, 1);
}

#[test]
fn test_analysis_with_all_issue_categories() {
    let phase = CrossFileAnalysisPhase::new();
    let context = AnalysisContext::default();

    let categories = vec![
        IssueCategory::MemoryCorruption,
        IssueCategory::Injection,
        IssueCategory::AuthenticationBypass,
        IssueCategory::BusinessLogicFlaw,
        IssueCategory::RaceCondition,
        IssueCategory::DataLeakage,
        IssueCategory::Misconfiguration,
        IssueCategory::UnsafeDependency,
        IssueCategory::CryptographicMisuse,
    ];

    let findings: Vec<_> = categories
        .into_iter()
        .map(|cat| create_finding_with_security_issue("f", cat, Severity::High))
        .collect();

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_files, 1);
}
