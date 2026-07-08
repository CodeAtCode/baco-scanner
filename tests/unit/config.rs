//! Unit tests for src/config.rs
#![allow(dead_code)]
//!
//! Covers:
//! - TOML parsing
//! - Environment variable overrides
//! - Default values
//! - Validation logic
//! - LLM phase configurations

use baco::config::{
    apply_env_overrides, AgentConfig, LlmPhaseConfig, PerformanceSettings, ScannerConfig,
};
use serial_test::serial;
use std::collections::HashMap;

/// Test helper for environment variable management
struct EnvVarGuard {
    vars: HashMap<String, Option<String>>,
}

impl EnvVarGuard {
    fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        let prev = std::env::var(key).ok();
        self.vars.insert(key.to_string(), prev);
        std::env::set_var(key, value);
    }

    fn clear(&mut self, key: &str) {
        let prev = std::env::var(key).ok();
        self.vars.insert(key.to_string(), prev);
        std::env::remove_var(key);
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

// ============================================================================
// ScannerConfig Tests
// ============================================================================

#[test]
fn test_default_config() {
    let config = ScannerConfig::default();

    assert_eq!(config.project.name, "");
    assert_eq!(config.project.path, "");
    assert!(config.project.languages.is_empty());
    assert_eq!(config.output.dir, "");
    assert!(config.output.format.is_empty());
    assert_eq!(config.scanner.commit_lookback_days, 0);
    assert_eq!(config.scanner.max_file_size_kb, 0);
    assert!(config.scanner.exclude_paths.is_empty());
    assert!(config.scanner.semgrep.enabled); // default_true
    assert!(!config.scanner.performance.enable_parallel_phases);
}

#[test]
fn test_parse_minimal_config() {
    let toml_str = r#"
        [project]
        name = "minimal"
        path = "/tmp/minimal"

        [output]
        dir = "./output"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.project.name, "minimal");
    assert_eq!(config.project.path, "/tmp/minimal");
    assert_eq!(config.output.dir, "./output");
    assert_eq!(config.scanner.commit_lookback_days, 30);
    assert_eq!(config.llm.max_retries, 2);
    assert!(config.scanner.semgrep.enabled);
}

#[test]
fn test_parse_full_config() {
    let toml_str = r#"
        [project]
        name = "full-test"
        path = "/tmp/full-test"
        languages = ["rust", "python", "typescript"]

        [output]
        dir = "./baco-output"
        format = ["json", "html", "markdown"]

        [scanner]
        commit_lookback_days = 180
        max_file_size_kb = 1024
        exclude_paths = ["tests/", "vendor/", "node_modules/"]

        [scanner.semgrep]
        enabled = true
        cache_dir = "/tmp/semgrep-cache"
        exclude_rules = ["rust-security.insecure-crypto"]

        [scanner.performance]
        enable_parallel_phases = true
        max_parallel_tasks = 8
        enable_llm_cache = true
        enable_incremental_scan = true
        llm_cache_dir = "/tmp/llm-cache"
        enable_file_filtering = true
        enable_batch_llm = true
        batch_size = 16
        early_termination_threshold = 500.0
        enable_v3_features = true
        enable_threat_modeling = true
        enable_root_cause_dedup = true
        enable_multi_verifier = true
        enable_auto_patching = true
        enable_poc_compilation = true
        enable_confidence_refinement = true
        enable_cve_bootstrap = true
        enable_variant_search = true

        [llm]
        timeout_secs = 120
        max_retries = 5
        retry_backoff_ms = 5000
        max_concurrent = 8

        [llm.phases.discovery]
        base_url = "https://api.openai.com/v1"
        api_key = "sk-test"
        model = "gpt-4"

        [llm.phases.verification]
        base_url = "https://api.anthropic.com/v1"
        models = ["claude-3-opus", "claude-3-sonnet"]

        [llm.phases.aggregation]
        base_url = "https://api.mistral.ai/v1"
        model = "mistral-large"

        [tickets]
        [[tickets.systems]]
        system_type = "github"
        url = "https://github.com/example/repo"
        api_key = "ghp-test"
        project = "example"

        [[tickets.systems]]
        system_type = "jira"
        url = "https://example.atlassian.net"
        api_key = "jira-token"
        project = "SEC"

        [agent]
        enabled = true
        max_turns = 20
        tool_timeout_secs = 60
        trusted_paths = ["/safe/path", "./trusted"]
        keep_artifacts = true
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.project.name, "full-test");
    assert_eq!(config.project.languages.len(), 3);
    assert_eq!(config.output.format.len(), 3);
    assert_eq!(config.scanner.exclude_paths.len(), 3);
    assert_eq!(
        config.scanner.semgrep.cache_dir,
        Some("/tmp/semgrep-cache".to_string())
    );
    assert_eq!(config.scanner.semgrep.exclude_rules.len(), 1);
    assert_eq!(config.scanner.performance.max_parallel_tasks, 8);
    assert_eq!(config.scanner.performance.batch_size, 16);
    assert!(config.scanner.performance.enable_threat_modeling);
    assert_eq!(config.llm.max_concurrent, 8);
    assert_eq!(config.llm.phases.discovery.model, "gpt-4");
    assert_eq!(config.llm.phases.verification.models.len(), 2);
    assert_eq!(config.tickets.systems.len(), 2);
    assert!(config.agent.enabled);
    assert_eq!(config.agent.max_turns, 20);
}

#[test]
fn test_parse_models_field_precedence() {
    // models field takes precedence over model field
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "legacy-model"
        models = ["new-model-1", "new-model-2"]
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let models = config.llm.phases.discovery.get_models();

    // models field should take precedence
    assert_eq!(models.len(), 2);
    assert_eq!(models[0], "new-model-1");
    assert_eq!(models[1], "new-model-2");
}

#[test]
fn test_parse_legacy_model_field() {
    // Only model field (legacy) should work
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "legacy-only-model"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let models = config.llm.phases.discovery.get_models();

    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "legacy-only-model");
}

#[test]
fn test_parse_empty_models() {
    // No models specified should return empty vector
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let models = config.llm.phases.discovery.get_models();

    assert!(models.is_empty());
}

// ============================================================================
// Environment Override Tests
// ============================================================================

#[test]
#[serial]
fn test_env_override_discovery_only() {
    let mut guard = EnvVarGuard::new();
    guard.set("LLM_DISCOVERY_KEY", "env-discovery-key");

    let toml_str = base_config_toml();
    let mut config: ScannerConfig = toml::from_str(&toml_str).unwrap();

    apply_env_overrides(&mut config);

    assert_eq!(
        config.llm.phases.discovery.api_key,
        Some("env-discovery-key".to_string())
    );
    assert!(config.llm.phases.verification.api_key.is_none());
    assert!(config.llm.phases.aggregation.api_key.is_none());
}

#[test]
#[serial]
fn test_env_override_all_phases() {
    let mut guard = EnvVarGuard::new();
    guard.set("LLM_DISCOVERY_KEY", "env-discovery");
    guard.set("LLM_VERIFICATION_KEY", "env-verification");
    guard.set("LLM_AGGREGATION_KEY", "env-aggregation");

    let toml_str = base_config_toml();
    let mut config: ScannerConfig = toml::from_str(&toml_str).unwrap();

    apply_env_overrides(&mut config);

    assert_eq!(
        config.llm.phases.discovery.api_key,
        Some("env-discovery".to_string())
    );
    assert_eq!(
        config.llm.phases.verification.api_key,
        Some("env-verification".to_string())
    );
    assert_eq!(
        config.llm.phases.aggregation.api_key,
        Some("env-aggregation".to_string())
    );
}

#[test]
#[serial]
fn test_env_override_toml_takes_precedence() {
    let mut guard = EnvVarGuard::new();
    guard.set("LLM_DISCOVERY_KEY", "env-key");
    guard.set("LLM_VERIFICATION_KEY", "env-key");
    guard.set("LLM_AGGREGATION_KEY", "env-key");

    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        api_key = "toml-discovery"

        [llm.phases.verification]
        base_url = "http://test"
        api_key = "toml-verification"

        [llm.phases.aggregation]
        base_url = "http://test"
    "#;

    let mut config: ScannerConfig = toml::from_str(toml_str).unwrap();
    apply_env_overrides(&mut config);

    // TOML keys should be preserved
    assert_eq!(
        config.llm.phases.discovery.api_key,
        Some("toml-discovery".to_string())
    );
    assert_eq!(
        config.llm.phases.verification.api_key,
        Some("toml-verification".to_string())
    );
    // Aggregation has no TOML key, so env should apply
    assert_eq!(
        config.llm.phases.aggregation.api_key,
        Some("env-key".to_string())
    );
}

#[test]
#[serial]
fn test_env_override_unknown_phase() {
    let mut guard = EnvVarGuard::new();
    // This env var doesn't correspond to any known phase
    guard.set("LLM_UNKNOWN_PHASE_KEY", "unknown-key");

    let toml_str = base_config_toml();
    let mut config: ScannerConfig = toml::from_str(&toml_str).unwrap();

    // Should not panic, just log warning
    apply_env_overrides(&mut config);

    // No changes expected
    assert!(config.llm.phases.discovery.api_key.is_none());
}

fn base_config_toml() -> String {
    r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"

        [llm.phases.verification]
        base_url = "http://test"

        [llm.phases.aggregation]
        base_url = "http://test"
    "#
    .to_string()
}

// ============================================================================
// Validation Tests
// ============================================================================

#[test]
fn test_validate_missing_base_url() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = ""
        api_key = "test-key"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.to_string().contains("discovery"));
    assert!(err_msg.to_string().contains("base_url"));
}

#[test]
fn test_validate_missing_model() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        api_key = "test-key"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.to_string().contains("discovery"));
    assert!(err_msg.to_string().contains("model"));
}

#[test]
fn test_validate_empty_api_key_skips_validation() {
    // Empty api_key should skip validation for that phase
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    // This will fail on semgrep check, but not on LLM validation
    let result = config.validate();

    // May fail due to semgrep not being installed, but not due to LLM config
    if let Err(err_msg) = result {
        assert!(!err_msg.to_string().contains("base_url"));
        assert!(!err_msg.to_string().contains("model"));
    }
}

#[test]
fn test_validate_none_api_key_skips_validation() {
    // None api_key should skip validation for that phase
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    // Verify api_key is None
    assert!(config.llm.phases.discovery.api_key.is_none());

    // Validation should skip LLM checks for phases without api_key
    let result = config.validate();

    if let Err(err_msg) = result {
        assert!(!err_msg.to_string().contains("base_url"));
        assert!(!err_msg.to_string().contains("model"));
    }
}

#[test]
fn test_validate_nonexistent_project_path() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/nonexistent/path/that/does/not/exist"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.to_string().contains("does not exist"));
}

#[test]
fn test_from_file_success() {
    let temp_dir = std::env::temp_dir().join("baco_config_test_from_file");
    let _ = std::fs::create_dir_all(&temp_dir);
    let config_file = temp_dir.join("test.toml");

    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    std::fs::write(&config_file, toml_str).unwrap();
    let result = ScannerConfig::from_file(config_file.to_str().unwrap());

    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.project.name, "test");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_from_file_not_found() {
    let result = ScannerConfig::from_file("/nonexistent/config.toml");
    assert!(result.is_err());
}

#[test]
fn test_from_file_invalid_toml() {
    let temp_dir = std::env::temp_dir().join("baco_config_test_invalid");
    let _ = std::fs::create_dir_all(&temp_dir);
    let config_file = temp_dir.join("invalid.toml");

    std::fs::write(&config_file, "invalid toml {{{").unwrap();
    let result = ScannerConfig::from_file(config_file.to_str().unwrap());

    assert!(result.is_err());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// Performance Settings Tests
// ============================================================================

#[test]
fn test_performance_settings_defaults() {
    let settings = PerformanceSettings::default();

    assert!(!settings.enable_parallel_phases);
    assert_eq!(settings.max_parallel_tasks, 4);
    assert!(!settings.enable_llm_cache);
    assert!(!settings.enable_incremental_scan);
    assert!(settings.enable_file_filtering);
    assert!(!settings.enable_batch_llm);
    assert_eq!(settings.batch_size, 8);
    assert!(!settings.enable_v3_features);
    assert!(!settings.enable_threat_modeling);
    assert!(!settings.enable_root_cause_dedup);
    assert!(!settings.enable_multi_verifier);
    assert!(!settings.enable_auto_patching);
    assert!(!settings.enable_poc_compilation);
    assert!(settings.enable_confidence_refinement);
    assert!(settings.enable_cve_bootstrap);
    assert!(settings.enable_variant_search);
}

#[test]
fn test_performance_settings_custom() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [scanner.performance]
        enable_parallel_phases = true
        max_parallel_tasks = 16
        enable_llm_cache = true
        enable_file_filtering = false
        batch_size = 32
        early_termination_threshold = 100.0

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let perf = &config.scanner.performance;

    assert!(perf.enable_parallel_phases);
    assert_eq!(perf.max_parallel_tasks, 16);
    assert!(perf.enable_llm_cache);
    assert!(!perf.enable_file_filtering);
    assert_eq!(perf.batch_size, 32);
    assert_eq!(perf.early_termination_threshold, 100.0);
}

// ============================================================================
// Agent Config Tests
// ============================================================================

#[test]
fn test_agent_config_defaults() {
    let config = AgentConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.max_turns, 10);
    assert_eq!(config.tool_timeout_secs, 30);
    assert_eq!(config.trusted_paths, vec![".".to_string()]);
    assert!(!config.keep_artifacts);
}

#[test]
fn test_agent_config_custom() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"

        [agent]
        enabled = true
        max_turns = 50
        tool_timeout_secs = 120
        trusted_paths = ["/safe", "./trusted"]
        keep_artifacts = true
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    let agent = &config.agent;

    assert!(agent.enabled);
    assert_eq!(agent.max_turns, 50);
    assert_eq!(agent.tool_timeout_secs, 120);
    assert_eq!(agent.trusted_paths.len(), 2);
    assert!(agent.keep_artifacts);
}

// ============================================================================
// LLM Phase Config Tests
// ============================================================================

#[test]
fn test_llm_phase_config_get_models_priority() {
    // Test that models list takes precedence over single model string
    let phase = LlmPhaseConfig {
        base_url: "http://test".to_string(),
        api_key: Some("key".to_string()),
        model: "single-model".to_string(),
        models: vec!["multi-1".to_string(), "multi-2".to_string()],
        timeout_secs: None,
    };

    let models = phase.get_models();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0], "multi-1");
}

#[test]
fn test_llm_phase_config_fallback_to_single_model() {
    // Test fallback to single model when models list is empty
    let phase = LlmPhaseConfig {
        base_url: "http://test".to_string(),
        api_key: Some("key".to_string()),
        model: "single-model".to_string(),
        models: vec![],
        timeout_secs: None,
    };

    let models = phase.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "single-model");
}

#[test]
fn test_llm_phase_config_empty_when_both_missing() {
    // Test empty result when both model and models are empty
    let phase = LlmPhaseConfig {
        base_url: "http://test".to_string(),
        api_key: Some("key".to_string()),
        model: "".to_string(),
        models: vec![],
        timeout_secs: None,
    };

    let models = phase.get_models();
    assert!(models.is_empty());
}

// ============================================================================
// Ticket Config Tests
// ============================================================================

#[test]
fn test_ticket_system_config_parsing() {
    let toml_str = r#"
        [project]
        name = "test"
        path = "/tmp/test"

        [output]
        dir = "./out"

        [scanner]
        commit_lookback_days = 30
        max_file_size_kb = 100

        [llm]
        timeout_secs = 30
        max_retries = 2
        retry_backoff_ms = 1000

        [llm.phases.discovery]
        base_url = "http://test"
        model = "test"

        [llm.phases.verification]
        base_url = "http://test"
        model = "test"

        [llm.phases.aggregation]
        base_url = "http://test"
        model = "test"

        [tickets]
        [[tickets.systems]]
        system_type = "github"
        url = "https://github.com/org/repo"
        api_key = "ghp-token"
        project = "myproject"

        [[tickets.systems]]
        system_type = "jira"
        url = "https://company.atlassian.net"
        project = "SEC"
    "#;

    let config: ScannerConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.tickets.systems.len(), 2);

    let github = &config.tickets.systems[0];
    assert_eq!(github.system_type, "github");
    assert_eq!(github.url, "https://github.com/org/repo");
    assert_eq!(github.api_key, Some("ghp-token".to_string()));
    assert_eq!(github.project, Some("myproject".to_string()));

    let jira = &config.tickets.systems[1];
    assert_eq!(jira.system_type, "jira");
    assert_eq!(jira.url, "https://company.atlassian.net");
    assert!(jira.api_key.is_none());
    assert_eq!(jira.project, Some("SEC".to_string()));
}
