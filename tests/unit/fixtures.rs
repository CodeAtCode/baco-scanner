#![allow(dead_code)]
//! Centralized test fixtures for all BACO tests.
//!
//! This module consolidates duplicate test fixture creation code across the test suite
//! to reduce setup time and maintain consistency.
//!
//! # Usage
//!
//! ```rust,ignore
//! use tests::fixtures::{
//!     create_test_finding, create_test_config, create_test_scanner,
//!     shared_temp_dir, create_subdir_in_shared
//! };
//!
//! #[test]
//! fn test_something() {
//!     let finding = create_test_finding("SQL Injection", "src/auth.rs", 42, Severity::High);
//!     let config = create_test_config();
//! }
//! ```
//!
//! # Fixture Categories
//!
//! - **Findings**: `create_test_finding*` - Create test vulnerability findings
//! - **Config**: `create_test_config*` - Create test scanner configurations  
//! - **Scanner**: `create_test_scanner*` - Create test scanner instances
//! - **TempDir**: `shared_temp_dir*` - Manage temporary directories
//! - **Helpers**: Various utility functions for common test setups

// ============================================================================
// Finding Fixtures
// ============================================================================

use baco::config::{
    AgentConfig, LlmConfig, LlmPhaseConfig, OutputConfig, PerformanceSettings, ProjectConfig,
    ScannerConfig, ScannerSettings, SemgrepSettings, TicketConfig,
};
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::Scanner;
use baco::scanner_types::project::ProjectStack;
use indicatif::ProgressBar;
use std::sync::LazyLock;
use tempfile::TempDir;

/// Create a test vulnerability finding with default values.
///
/// This is the primary fixture for creating test findings. Uses sensible defaults
/// that work for most test scenarios.
///
/// # Arguments
/// * `title` - Title of the finding
/// * `file_path` - Path to the file containing the finding
/// * `line` - Line number where the finding occurs
/// * `severity` - Severity level of the finding
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_test_finding;
/// use baco::findings::Severity;
///
/// let finding = create_test_finding("SQL Injection", "src/auth.rs", 42, Severity::High);
/// ```
pub fn create_test_finding(
    title: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.replace(' ', "-").to_lowercase()),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(line),
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
    }
}

/// Create a test finding with customizable ID, title, and severity.
///
/// Use this when you need specific values for testing edge cases or parameterized tests.
///
/// # Arguments
/// * `id` - Unique identifier for the finding
/// * `title` - Title of the finding
/// * `severity` - Severity level of the finding
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_finding_with_params;
/// use baco::findings::Severity;
///
/// let finding = create_finding_with_params("custom-id", "XSS", Severity::Medium);
/// ```
pub fn create_finding_with_params(
    id: &str,
    title: &str,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(10),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(VerificationStatus::NeedsReview),
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
    }
}

/// Create a minimal test finding with default values.
///
/// This is a simpler version that works for tests that only need basic finding structure.
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_minimal_finding;
///
/// let finding = create_minimal_finding();
/// assert_eq!(finding.id, "test-finding-id");
/// ```
pub fn create_minimal_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-id".to_string(),
        title: "SQL Injection".to_string(),
        description: "SQL injection vulnerability in user authentication".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/auth.rs".to_string(),
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
        statement_range: None,
    }
}

/// Create a complete finding with all fields populated.
///
/// Use this for tests that need to verify all finding fields are properly handled.
pub fn create_complete_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "complete-finding-id".to_string(),
        title: "Complete SQL Injection Finding".to_string(),
        description:
            "Comprehensive SQL injection vulnerability with all fields populated for testing"
                .to_string(),
        file_path: "src/database.rs".to_string(),
        line_number: Some(42),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-89".to_string()),
        code_snippet: Some("vulnerable_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: Some("complete.rs:42".to_string()),
        already_reported: false,
        sources: vec!["semgrep".to_string(), "llm".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.85),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Verified".to_string()),
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: Some("llama3.1".to_string()),
        agent_mode: false,
        statement_range: None,
    }
}

/// Create multiple test findings with sequential IDs.
///
/// # Arguments
/// * `count` - Number of findings to create
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_test_findings;
///
/// let findings = create_test_findings(5);
/// assert_eq!(findings.len(), 5);
/// ```
pub fn create_test_findings(count: usize) -> Vec<VulnerabilityFinding> {
    (0..count)
        .map(|i| {
            let mut finding = create_minimal_finding();
            finding.id = format!("test-finding-{}", i);
            finding
        })
        .collect()
}

// ============================================================================
// Config Fixtures
// ============================================================================

/// Create a minimal valid ScannerConfig for tests.
///
/// This provides a working configuration with sensible defaults that won't
/// trigger external dependencies (e.g., LLM calls, semgrep).
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_test_config;
///
/// let config = create_test_config();
/// let scanner = Scanner::new(config, "/tmp/test".into(), false);
/// ```
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
            tgi: baco::config::TgiConfig::default(),
        },
        tickets: TicketConfig::default(),
        agent: AgentConfig {
            enabled: false,
            ..Default::default()
        },
        router: Default::default(),
        aggregation: Default::default(),
        rulesynth: Default::default(),
        orchestration: Default::default(),
        normalization: Default::default(),
        cpg: Default::default(),
        exploit: Default::default(),
    }
}

/// Create a test config with minimal settings.
///
/// Simpler version for tests that only need basic config structure.
pub fn create_minimal_config() -> ScannerConfig {
    ScannerConfig {
        project: ProjectConfig {
            name: "test".to_string(),
            path: ".".to_string(),
            languages: vec!["rust".to_string()],
        },
        output: OutputConfig {
            dir: "/tmp/baco_test_output".to_string(),
            format: vec!["html".to_string()],
        },
        scanner: ScannerSettings {
            commit_lookback_days: 30,
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: SemgrepSettings::default(),
            performance: PerformanceSettings::default(),
        },
        llm: LlmConfig {
            phases: baco::config::LlmPhasesConfig::default(),
            timeout_secs: 60,
            max_retries: 3,
            retry_backoff_ms: 1000,
            ..Default::default()
        },
        agent: AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        },
        tickets: TicketConfig::default(),
        router: Default::default(),
        aggregation: Default::default(),
        rulesynth: Default::default(),
        orchestration: Default::default(),
        normalization: Default::default(),
        cpg: Default::default(),
        exploit: Default::default(),
    }
}

/// Create test config with LLM discovery API key.
pub fn create_test_config_with_discovery_key() -> ScannerConfig {
    let mut config = create_minimal_config();
    config.llm.phases.discovery.api_key = Some("test-key".to_string());
    config.llm.phases.discovery.base_url = "http://localhost:11434".to_string();
    config
}

/// Create test config with all features enabled.
pub fn create_test_config_all_features() -> ScannerConfig {
    let mut config = create_minimal_config();
    config.scanner.performance.enable_confidence_refinement = true;
    config.scanner.performance.enable_threat_modeling = true;
    config.scanner.performance.enable_root_cause_dedup = true;
    config.scanner.performance.enable_multi_verifier = true;
    config.scanner.performance.enable_auto_patching = true;
    config.scanner.performance.enable_cve_bootstrap = true;
    config.scanner.performance.enable_poc_compilation = true;
    config.scanner.performance.enable_variant_search = true;
    config
}

// ============================================================================
// Scanner Fixtures
// ============================================================================

/// Create a test scanner with default configuration.
///
/// # Returns
/// A tuple of (Scanner, TempDir) where the TempDir is the scanner's working directory.
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_test_scanner;
///
/// let (scanner, temp_dir) = create_test_scanner();
/// // Use scanner for testing
/// ```
pub fn create_test_scanner() -> (Scanner, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, temp_dir)
}

/// Create a test scanner with custom configuration.
///
/// # Arguments
/// * `config` - Optional configuration. If None, default config is used.
/// * `temp_dir` - Optional temporary directory. If None, a new one is created.
///
/// # Returns
/// A tuple of (Scanner, Option<TempDir>) where TempDir is Some if a new temp dir was created.
pub fn create_test_scanner_with_options(
    temp_dir: Option<TempDir>,
    config: Option<ScannerConfig>,
) -> (Scanner, Option<TempDir>) {
    let temp_dir = temp_dir.unwrap_or_else(|| TempDir::new().unwrap());
    let config = config.unwrap_or_default();

    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, Some(temp_dir))
}

/// Create a test scanner with default settings (alias for create_test_scanner).
pub fn create_default_test_scanner() -> (Scanner, TempDir) {
    create_test_scanner()
}

// ============================================================================
// TempDir Helpers
// ============================================================================

/// Shared static TempDir for tests that can reuse a single directory.
///
/// This is initialized lazily on first access and lives for the duration of the test run.
/// Use this for tests that:
/// - Don't modify shared state in ways that would affect other tests
/// - Create files in unique subdirectories
/// - Are read-only or use isolated paths
///
/// # Warning
///
/// DO NOT use this for tests that:
/// - Write to the same filenames (will cause collisions)
/// - Need complete filesystem isolation
/// - Test cleanup/deletion behavior
static SHARED_TEMP_DIR: LazyLock<TempDir> =
    LazyLock::new(|| tempfile::tempdir().expect("Failed to create shared temp directory"));

/// Get a reference to the shared temp directory.
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::shared_temp_dir;
///
/// #[test]
/// fn test_example() {
///     let temp_dir = shared_temp_dir();
///     let path = temp_dir.path().join("my_unique_test_file.txt");
///     std::fs::write(&path, "content").unwrap();
/// }
/// ```
pub fn shared_temp_dir() -> &'static TempDir {
    &SHARED_TEMP_DIR
}

/// Create a unique subdirectory within the shared temp directory.
///
/// This is useful for tests that need isolation but can share the parent temp directory.
/// Each call creates a new subdirectory with the given name.
///
/// # Arguments
/// * `subdir_name` - A unique name for the subdirectory (should include test name or ID)
///
/// # Returns
/// A `TempDir` pointing to the new subdirectory
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::create_subdir_in_shared;
///
/// #[test]
/// fn test_foo() {
///     let temp_dir = create_subdir_in_shared("test_foo");
///     // temp_dir is isolated from other tests
/// }
/// ```
pub fn create_subdir_in_shared(_subdir_name: &str) -> TempDir {
    let shared = shared_temp_dir();
    tempfile::tempdir_in(shared.path()).expect("Failed to create subdirectory in shared temp dir")
}

// ============================================================================
// Environment Variable Helpers
// ============================================================================

/// Guard for environment variables that auto-cleans on drop.
/// This allows safe parallel execution of tests that need env var isolation.
///
/// # Example
///
/// ```rust,ignore
/// use tests::fixtures::EnvVarGuard;
///
/// #[test]
/// fn test_with_env_vars() {
///     let _guard = EnvVarGuard::set(&[("MY_VAR", "value")]);
///     assert_eq!(std::env::var("MY_VAR").unwrap(), "value");
///     // When _guard drops, vars are restored automatically
/// }
/// ```
use std::collections::HashMap;

pub struct EnvVarGuard {
    vars: HashMap<String, Option<String>>,
}

impl EnvVarGuard {
    /// Set multiple environment variables, returning a guard that restores them on drop.
    pub fn set(vars: &[(&str, &str)]) -> Self {
        let mut previous = HashMap::new();
        for &(key, value) in vars {
            let old_value = std::env::var(key).ok();
            std::env::set_var(key, value);
            previous.insert(key.to_string(), old_value);
        }
        Self { vars: previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, old_value) in &self.vars {
            match old_value {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test project stack.
pub fn create_test_project_stack() -> ProjectStack {
    ProjectStack {
        languages: vec!["rust".to_string()],
        frameworks: vec![],
        dependencies: vec![],
    }
}

/// Create a progress bar for testing (hidden output).
pub fn create_test_progress_bar() -> ProgressBar {
    let pb = ProgressBar::new(100);
    pb.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    pb
}

/// Ensure test output directory exists.
pub fn ensure_test_output_dir() {
    use std::fs;
    use std::path::PathBuf;
    let output_dir = PathBuf::from("/tmp/baco-test-output");
    let _ = fs::create_dir_all(&output_dir);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_finding() {
        let finding = create_test_finding("SQL Injection", "src/auth.rs", 42, Severity::High);

        assert_eq!(finding.id, "test-sql-injection");
        assert_eq!(finding.title, "SQL Injection");
        assert_eq!(finding.file_path, "src/auth.rs");
        assert_eq!(finding.line_number, Some(42));
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_create_finding_with_params() {
        let finding = create_finding_with_params("custom-id", "XSS", Severity::Medium);

        assert_eq!(finding.id, "custom-id");
        assert_eq!(finding.title, "XSS");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_create_minimal_finding() {
        let finding = create_minimal_finding();

        assert_eq!(finding.id, "test-finding-id");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_create_complete_finding() {
        let finding = create_complete_finding();

        assert_eq!(finding.id, "complete-finding-id");
        assert!(finding.code_snippet.is_some());
        assert!(finding.recommendation.is_some());
        assert_eq!(
            finding.verification_status,
            Some(VerificationStatus::Confirmed)
        );
    }

    #[test]
    fn test_create_test_findings() {
        let findings = create_test_findings(5);

        assert_eq!(findings.len(), 5);
        for (i, finding) in findings.iter().enumerate() {
            assert_eq!(finding.id, format!("test-finding-{}", i));
        }
    }

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();

        assert_eq!(config.project.name, "test-project");
        assert!(!config.scanner.semgrep.enabled);
    }

    #[test]
    fn test_create_test_scanner() {
        let (scanner, temp_dir) = create_test_scanner();

        assert!(temp_dir.path().exists());
        assert_eq!(scanner.target_path(), temp_dir.path());
    }

    #[test]
    fn test_shared_temp_dir() {
        let temp_dir = shared_temp_dir();

        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[test]
    fn test_create_subdir_in_shared() {
        let subdir = create_subdir_in_shared("test_subdir_123");

        assert!(subdir.path().exists());
        assert!(subdir.path().is_dir());
    }

    #[test]
    fn test_create_test_project_stack() {
        let stack = create_test_project_stack();

        assert_eq!(stack.languages, vec!["rust".to_string()]);
        assert!(stack.frameworks.is_empty());
    }

    #[test]
    fn test_create_test_progress_bar() {
        let pb = create_test_progress_bar();

        // Just verify it was created without panicking
        assert!(pb.position() <= 100);
    }
}
