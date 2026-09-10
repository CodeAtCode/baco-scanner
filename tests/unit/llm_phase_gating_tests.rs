//! LLM phase gating tests for static_analysis and security_agent_verification phases.
//!
//! Tests cover:
//! - Gating: phase skips gracefully when LLM config incomplete (no api_key/base_url/models)
//! - Prompt building: prompts include file path, code snippet, gate instructions
//! - Response parsing: valid JSON object, array-wrapped, malformed → documented behavior
//! - LLM config construction: phase_llm_config with various inputs
//!
//! Note: helpers.rs functions (detect_language, extract_function_name_from_finding) are pub(super)
//! and not accessible from tests. They are tested indirectly through phase execution.

use baco::checkpoint::ScanPhase;
use baco::config::{AgentConfig, LlmPhaseConfig, LlmPhasesConfig, ScannerSettings};
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm_metrics::LlmMetricsTracker;
use baco::scanner::phases::{run_phase, PhaseConfig};
use baco::scanner::Scanner;
use indicatif::ProgressBar;
use std::path::PathBuf;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_finding(id: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability for gating tests".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "/tmp/test/test.py".to_string(),
        line_number: Some(42),
        code_snippet: Some("execute(user_input)".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.7),
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
    }
}

fn create_test_config_with_static_analysis() -> baco::config::ScannerConfig {
    baco::config::ScannerConfig {
        project: baco::config::ProjectConfig {
            name: "test-project".to_string(),
            path: ".".to_string(),
            languages: vec!["python".to_string()],
        },
        output: baco::config::OutputConfig {
            dir: "/tmp/test_output".to_string(),
            evidence_gate: false,
            include_rejected: false,
        },
        scanner: ScannerSettings {
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: baco::config::SemgrepSettings::default(),
            performance: baco::config::PerformanceSettings::default(),
        },
        llm: baco::config::LlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            max_concurrent: 3,
            temperature: 0.5,
            phases: LlmPhasesConfig {
                static_analysis: LlmPhaseConfig {
                    base_url: "http://localhost:8080".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "test-model".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                },
                security_agent_verification: LlmPhaseConfig {
                    base_url: "http://localhost:8080".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "test-model".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                },
                ..Default::default()
            },
            max_reasoning_tokens: Some(32768),
            enable_llm_cache: false,
            cache_dir: None,
        },
        tickets: baco::config::TicketConfig { systems: vec![] },
        agent: AgentConfig::default(),
        router: baco::config::RouterConfig::default(),
        aggregation: baco::config::AggregationConfig::default(),
        rulesynth: baco::config::RuleSynthConfig::default(),
        normalization: baco::config::NormalizationConfig::default(),
        cpg: baco::config::CpgConfig::default(),
        exploit: baco::config::ExploitConfig::default(),
        validate: Default::default(),
        vultriage: Default::default(),
        policy_sampling: Default::default(),
        agent_scaffold: Default::default(),
        pacvd: Default::default(),
        agent_flow: Default::default(),
        vuln_spec: Default::default(),
        citation_verification: Default::default(),
        prior_runs: Default::default(),
        triage: Default::default(),
        priority: Default::default(),
        budget: Default::default(),
        org_context: Default::default(),
        knowledge: Default::default(),
    }
}

fn create_test_scanner_with_config(config: baco::config::ScannerConfig) -> Scanner {
    Scanner::new(config, PathBuf::from("."), false)
}

// ============================================================================
// LLM Phase Gating Tests - static_analysis
// ============================================================================

#[tokio::test]
async fn test_llm_static_analysis_skips_without_api_key() {
    let mut config = create_test_config_with_static_analysis();
    config.llm.phases.static_analysis.api_key = None;

    let scanner = create_test_scanner_with_config(config);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmStaticAnalysis,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &scanner.config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok(), "Phase should complete without error");
    let (updated_findings, _, _) = result.unwrap();
    assert_eq!(
        updated_findings.len(),
        findings.len(),
        "Findings should be preserved when phase skips"
    );
}

#[tokio::test]
async fn test_llm_static_analysis_skips_without_base_url() {
    let mut config = create_test_config_with_static_analysis();
    config.llm.phases.static_analysis.base_url = String::new();

    let scanner = create_test_scanner_with_config(config);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmStaticAnalysis,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &scanner.config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(
        result.is_ok(),
        "Phase should complete without error even with invalid config"
    );
    let (updated_findings, _, _) = result.unwrap();
    assert_eq!(
        updated_findings.len(),
        findings.len(),
        "Findings should be preserved when phase skips"
    );
}

#[tokio::test]
async fn test_llm_static_analysis_skips_without_models() {
    let mut config = create_test_config_with_static_analysis();
    config.llm.phases.static_analysis.model = String::new();
    config.llm.phases.static_analysis.models = vec![];

    let scanner = create_test_scanner_with_config(config);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmStaticAnalysis,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &scanner.config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok(), "Phase should complete without error");
    let (updated_findings, _, _) = result.unwrap();
    assert_eq!(
        updated_findings.len(),
        findings.len(),
        "Findings should be preserved when phase skips"
    );
}

// ============================================================================
// LLM Phase Gating Tests - security_agent_verification
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_skips_when_agent_disabled() {
    let config = create_test_config_with_static_analysis();
    let scanner = create_test_scanner_with_config(config);

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &scanner.config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok(), "Phase should complete without error");
    let (updated_findings, _, _) = result.unwrap();
    assert_eq!(
        updated_findings.len(),
        findings.len(),
        "Findings should be preserved when phase skips"
    );
}

#[tokio::test]
async fn test_security_agent_verification_skips_without_api_key() {
    let mut config = create_test_config_with_static_analysis();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = None;

    let scanner = create_test_scanner_with_config(config);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &scanner.config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok(), "Phase should complete without error");
    let (updated_findings, _, _) = result.unwrap();
    assert_eq!(
        updated_findings.len(),
        findings.len(),
        "Findings should be preserved when phase skips"
    );
}

// ============================================================================
// Prompt Building Tests
// ============================================================================

#[test]
fn test_build_stable_verification_prefix_includes_seven_question_gate() {
    let findings = vec![create_test_finding("test-1", Severity::High)];
    let hunt_prompts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let required_primitives: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    let prefix = baco::scanner::phases::llm_phases::verification::build_stable_verification_prefix(
        &findings,
        &hunt_prompts,
        &required_primitives,
    );

    assert!(
        prefix.contains("7-Question Gate"),
        "Prefix should include 7-question gate"
    );
    assert!(
        prefix.contains("Reachability"),
        "Prefix should include reachability question"
    );
    assert!(
        prefix.contains("Controllability"),
        "Prefix should include controllability question"
    );
    assert!(
        prefix.contains("Preconditions"),
        "Prefix should include preconditions question"
    );
}

#[test]
fn test_build_volatile_verification_tail_includes_file_path_and_snippet() {
    use std::collections::HashMap;

    let findings = vec![create_test_finding("test-1", Severity::High)];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = baco::scanner::phases::llm_phases::verification::build_volatile_verification_tail(
        &findings,
        &hunt_prompts,
    );

    assert!(
        tail.contains("/tmp/test/test.py"),
        "Tail should include file path"
    );
    assert!(
        tail.contains("execute(user_input)"),
        "Tail should include code snippet"
    );
    assert!(
        tail.contains("Test Vulnerability"),
        "Tail should include finding title"
    );
}

// ============================================================================
// Response Parsing Tests
// ============================================================================

#[test]
fn test_parse_batch_verification_valid_json_array() {
    let json_response = r#"[
        {
            "index": 0,
            "verification_status": "confirmed",
            "verification_notes": "True positive - SQL injection detected"
        }
    ]"#;

    let results = baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict(
        json_response,
        1,
    );

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert!(results[0].1.contains("SQL injection"));
}

#[test]
fn test_parse_batch_verification_array_wrapped_seven_question_gate() {
    let json_response = r#"[
        {
            "index": 0,
            "verification_status": "false_positive",
            "verification_notes": "Not reachable from user input",
            "seven_question_gate": {
                "reachability": "no",
                "controllability": "unknown",
                "preconditions": "unknown",
                "impact": "unknown",
                "context": "unknown",
                "evidence": "unknown",
                "confidence": "no"
            }
        }
    ]"#;

    let results = baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict(
        json_response,
        1,
    );

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::FalsePositive);
}

#[test]
fn test_parse_batch_verification_malformed_json_returns_needs_review() {
    let malformed_response = "This is not valid JSON {{{";

    let results = baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict(
        malformed_response,
        3,
    );

    assert_eq!(
        results.len(),
        3,
        "Should return placeholder for all expected findings"
    );
    for (status, notes) in &results {
        assert_eq!(
            *status,
            VerificationStatus::NeedsReview,
            "Parse failure should mark as NeedsReview"
        );
        assert!(!notes.is_empty(), "Notes should contain error information");
    }
}

#[test]
fn test_parse_batch_verification_code_fence_stripping() {
    let json_with_fence = r#"```json
[
    {
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "Verified"
    }
]
```"#;

    let results = baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict(
        json_with_fence,
        1,
    );

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
}

#[test]
fn test_parse_batch_verification_multiple_findings() {
    let json_response = r#"[
        {"index": 0, "verification_status": "confirmed", "verification_notes": "OK"},
        {"index": 1, "verification_status": "false_positive", "verification_notes": "Not exploitable"},
        {"index": 2, "verification_status": "needs_review", "verification_notes": "Unclear"}
    ]"#;

    let results = baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict(
        json_response,
        3,
    );

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
}

// ============================================================================
// LLM Client Construction Tests
// ============================================================================

#[test]
fn test_phase_llm_config_missing_base_url_errors() {
    let mut config = create_test_config_with_static_analysis();
    config.llm.phases.static_analysis.base_url = String::new();

    let result = baco::llm::phase_llm_config(&config, "static_analysis", None);
    assert!(result.is_err(), "Should error when base_url is missing");
}

#[test]
fn test_phase_llm_config_missing_models_errors() {
    let mut config = create_test_config_with_static_analysis();
    config.llm.phases.static_analysis.model = String::new();
    config.llm.phases.static_analysis.models = vec![];

    let result = baco::llm::phase_llm_config(&config, "static_analysis", None);
    assert!(result.is_err(), "Should error when no models configured");
}

#[test]
fn test_phase_llm_config_happy_path() {
    let config = create_test_config_with_static_analysis();

    let result = baco::llm::phase_llm_config(&config, "static_analysis", None);
    assert!(result.is_ok(), "Should succeed with valid config");

    let llm_config = result.unwrap();
    assert_eq!(llm_config.base_url, "http://localhost:8080");
    assert_eq!(llm_config.api_key, "test-key");
    assert_eq!(llm_config.model, "test-model");
    assert_eq!(llm_config.timeout, 30);
}
