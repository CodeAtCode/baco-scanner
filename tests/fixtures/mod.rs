//! Centralized test fixtures for baco test suite.
//!
//! This module consolidates duplicate test fixture code to reduce maintenance
//! overhead and ensure consistency across test files.

#![allow(dead_code)] // Some helpers are only used by unit tests, not integration tests

use baco::config::{
    LlmConfig, LlmPhaseConfig, OutputConfig, PerformanceSettings, ProjectConfig, ScannerConfig,
    ScannerSettings, SemgrepSettings,
};
use std::path::PathBuf;
use tempfile::TempDir;

/// Mock LLM client for testing
#[path = "agent/mock_llm.rs"]
pub mod mock_llm;

// ============================================================================
// ScannerConfig Builders
// ============================================================================

/// Create a minimal ScannerConfig for unit tests.
///
/// This provides a working configuration with sensible defaults for most tests.
/// Uses local Ollama endpoint by default.
///
/// # Example
///
/// ```rust,ignore
/// use fixtures::create_test_config;
///
/// let config = create_test_config();
/// let scanner = Scanner::new(config, "/tmp/test".into(), false);
/// ```
pub fn create_test_config() -> ScannerConfig {
    ScannerConfig {
        eval: Default::default(),
        project: ProjectConfig {
            name: "test-project".to_string(),
            path: ".".to_string(),
            languages: vec!["rust".to_string()],
        },
        output: OutputConfig {
            dir: "/tmp/baco-test-output".to_string(),
            evidence_gate: false,
            include_rejected: false,
        },
        scanner: ScannerSettings {
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            profile: baco::config::scanner::ScanPipelineProfile::Core,
            semgrep: SemgrepSettings {
                ..Default::default()
            },
            performance: PerformanceSettings {
                enable_confidence_refinement: false,
                early_termination_threshold: 100.0, // DEBUG: shared fixture value
                ..Default::default()
            },
        },
        llm: LlmConfig {
            base_url: String::new(),
            timeout_secs: 30,
            max_retries: 0,
            retry_backoff_ms: 0,
            max_concurrent: 4,
            temperature: 0.7,
            phases: baco::config::LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                verification: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                aggregation: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                static_analysis: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                security_agent_verification: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                threat_modeling: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                    temperature: None,
                    agent_flow: Default::default(),
                },
                prompt_overrides: Default::default(),
            },
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            pricing: Default::default(),
        },
        agent: Default::default(),
        tickets: Default::default(),
        router: Default::default(),
        aggregation: Default::default(),
        rulesynth: Default::default(),
        normalization: Default::default(),
        cpg: Default::default(),
        exploit: Default::default(),
        validate: Default::default(),
        vultriage: Default::default(),
        triage: Default::default(),
        priority: Default::default(),
        budget: Default::default(),
        policy_sampling: Default::default(),
        agent_scaffold: Default::default(),
        pacvd: Default::default(),
        agent_flow: Default::default(),
        vuln_spec: Default::default(),
        citation_verification: Default::default(),
        prior_runs: Default::default(),
        org_context: Default::default(),
        knowledge: Default::default(),
    }
}

/// Create a ScannerConfig with static analysis enabled.
///
/// Useful for tests that need semgrep or other static analysis tools.
pub fn create_test_config_with_static_analysis() -> ScannerConfig {
    let mut config = create_test_config();
    config.scanner.semgrep.rulesets = vec!["p/security".to_string()];
    config
}

/// Create a ScannerConfig with LLM discovery key configured.
pub fn create_test_config_with_discovery_key() -> ScannerConfig {
    let mut config = create_test_config();
    config.llm.phases.discovery.api_key = Some("test-key".to_string());
    config
}

/// Create a ScannerConfig with all features enabled.
pub fn create_test_config_all_features() -> ScannerConfig {
    let mut config = create_test_config();
    config.scanner.semgrep.rulesets = vec!["p/security".to_string()];
    config.llm.phases.discovery.api_key = Some("test-key".to_string());
    config.llm.phases.verification.api_key = Some("test-key".to_string());
    config
}

// ============================================================================
// TempDir Helpers
// ============================================================================

/// Create a shared temporary directory for tests.
///
/// Returns the path and a TempDir handle that will be cleaned up when dropped.
pub fn shared_temp_dir() -> (String, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let path = temp_dir.path().to_string_lossy().to_string();
    (path, temp_dir)
}

/// Create a subdirectory within a shared temp directory.
pub fn create_subdir_in_shared(parent: &TempDir, name: &str) -> PathBuf {
    let subdir = parent.path().join(name);
    std::fs::create_dir_all(&subdir).expect("Failed to create subdirectory");
    subdir
}

/// Minimal finding builder for report/renderer tests (title, file, line, severity).
pub fn make_finding(
    title: &str,
    file: &str,
    line: u32,
    severity: baco::findings::Severity,
) -> baco::findings::VulnerabilityFinding {
    let mut f = create_test_finding(&format!("finding-{}", line), title, file, line);
    f.severity = severity;
    f.confidence_score = 0.5;
    f.verification_status = Some(baco::findings::VerificationStatus::NeedsReview);
    f
}

pub fn make_finding_phase(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test description".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
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

/// Helper to create a minimal test finding for report tests.
///
/// This matches the signature used in tests/unit/report_fixtures.rs.
pub fn make_finding_report(
    id: &str,
    severity: baco::findings::Severity,
    file: &str,
    line: Option<u32>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
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
        evidence: vec![],
        verification_tier: None,
    }
}

/// Create a test finding with the specified parameters (integration test style)
///
/// This matches the signature used in tests/integration/common.rs.
pub fn create_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(line),
        code_snippet: Some("test code".to_string()),
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
        evidence: vec![],
        verification_tier: None,
    }
}

/// Create a test finding with minimal required fields (aggregation test style)
///
/// Used by aggregation and report tests that need customizable severity/confidence.
pub fn make_aggregation_finding(
    id: &str,
    severity: baco::findings::Severity,
    confidence: f32,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    verification: Option<baco::findings::VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test finding description".to_string(),
        severity,
        confidence_score: confidence,
        cwe_id: cwe.map(String::from),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test_code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: verification,
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

/// Create a minimal test finding (HTML renderer style)
///
/// Used by HTML rendering tests that need basic finding structure.
pub fn make_finding_html(
    id: &str,
    severity: baco::findings::Severity,
    file: &str,
    line: Option<u32>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
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
        evidence: vec![],
        verification_tier: None,
    }
}

/// Create a finding with CWE ID (CWE routing test style)
pub fn make_finding_cwe(
    id: &str,
    cwe_id: Option<&str>,
    file_path: &str,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: "test finding".to_string(),
        description: "test".to_string(),
        severity: baco::findings::Severity::Medium,
        confidence_score: 0.5,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number: Some(1),
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
        evidence: vec![],
        verification_tier: None,
    }
}

/// Create a finding with code snippet (chain/root-cause test style)
pub fn make_finding_snippet(
    id: &str,
    file_path: &str,
    title: &str,
    code_snippet: Option<&str>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: baco::findings::Severity::Medium,
        confidence_score: 0.7,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.5),
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

/// Create a finding with severity and sources (confidence test style)
pub fn make_finding_confidence(
    severity: baco::findings::Severity,
    sources: Vec<&str>,
    verification_status: Option<baco::findings::VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: "test-finding".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: sources.into_iter().map(String::from).collect(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status,
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

/// Create a finding with custom parameters (report aggregation test style)
pub fn make_finding_report_agg(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    cwe_id: Option<&str>,
    severity: baco::findings::Severity,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: Some("test_code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(baco::findings::VerificationStatus::NeedsReview),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        agent_mode: false,
        llm_model: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}
