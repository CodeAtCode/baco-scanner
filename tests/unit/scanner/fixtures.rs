//! Test fixtures for scanner tests
#![allow(dead_code)]

use baco::config::{
    AgentConfig, LlmConfig, LlmPhaseConfig, OutputConfig, PerformanceSettings, ProjectConfig,
    ScannerConfig, ScannerSettings, SemgrepSettings,
};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner_types::project::ProjectStack;
use std::fs;
use std::path::PathBuf;

/// Create a minimal valid ScannerConfig for tests
pub fn create_test_config() -> ScannerConfig {
    ScannerConfig {
        project: ProjectConfig {
            name: "test-project".to_string(),
            path: ".".to_string(),
            languages: vec!["rust".to_string()],
        },
        output: OutputConfig {
            dir: "/tmp/baco-test-output".to_string(),
            format: vec!["json".to_string()],
        },
        scanner: ScannerSettings {
            commit_lookback_days: 30,
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: SemgrepSettings {
                enabled: false, // Disable semgrep in tests
                ..Default::default()
            },
            performance: PerformanceSettings {
                enable_confidence_refinement: false,
                early_termination_threshold: 0.0,
                ..Default::default()
            },
        },
        llm: LlmConfig {
            timeout_secs: 30,
            max_retries: 0,
            retry_backoff_ms: 0,
            max_concurrent: 4,
            phases: baco::config::LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                },
                verification: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                },
                aggregation: LlmPhaseConfig {
                    base_url: "http://localhost:11434".to_string(),
                    api_key: None,
                    model: "llama3.1".to_string(),
                    models: vec![],
                    timeout_secs: Some(30),
                },
                semgrep: Default::default(),
                ticket_crossref: Default::default(),
                git_analysis: Default::default(),
                cross_file_analysis: Default::default(),
                confidence_scoring: Default::default(),
                ai_aggregation: Default::default(),
                reporting: Default::default(),
                indexing: Default::default(),
                prompt_overrides: Default::default(),
            },
        },
        tickets: Default::default(),
        agent: AgentConfig {
            enabled: false,
            ..Default::default()
        },
    }
}

/// Create a minimal finding for tests
pub fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
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
    }
}

/// Create multiple test findings
pub fn create_test_findings(count: usize) -> Vec<VulnerabilityFinding> {
    (0..count)
        .map(|i| {
            let mut finding = create_test_finding();
            finding.id = format!("test-finding-{}", i);
            finding
        })
        .collect()
}

/// Create a test project stack
pub fn create_test_project_stack() -> ProjectStack {
    ProjectStack {
        languages: vec!["rust".to_string()],
        frameworks: vec![],
        dependencies: vec![],
    }
}

/// Ensure test output directory exists
pub fn ensure_test_output_dir() {
    let output_dir = PathBuf::from("/tmp/baco-test-output");
    let _ = fs::create_dir_all(&output_dir);
}
