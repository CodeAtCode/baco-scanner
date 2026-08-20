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
        enable_incremental_scan = true
        early_termination_threshold = 500.0
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
    assert_eq!(config.scanner.semgrep.exclude_rules.len(), 1);
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
fn test_env_overrides() {
    let cases = vec![
        (
            "discovery_only",
            vec![("LLM_DISCOVERY_KEY", "env-discovery-key")],
            Some("env-discovery-key"),
            None,
            None,
        ),
        (
            "all_phases",
            vec![
                ("LLM_DISCOVERY_KEY", "env-discovery"),
                ("LLM_VERIFICATION_KEY", "env-verification"),
                ("LLM_AGGREGATION_KEY", "env-aggregation"),
            ],
            Some("env-discovery"),
            Some("env-verification"),
            Some("env-aggregation"),
        ),
        (
            "toml_takes_precedence",
            vec![
                ("LLM_DISCOVERY_KEY", "env-key"),
                ("LLM_VERIFICATION_KEY", "env-key"),
                ("LLM_AGGREGATION_KEY", "env-key"),
            ],
            Some("toml-discovery"),
            Some("toml-verification"),
            Some("env-key"),
        ),
        (
            "unknown_phase",
            vec![("LLM_UNKNOWN_PHASE_KEY", "unknown-key")],
            None,
            None,
            None,
        ),
    ];

    for (name, env_vars, expected_discovery, expected_verification, expected_aggregation) in cases {
        let mut guard = EnvVarGuard::new();
        for (key, value) in env_vars {
            guard.set(key, value);
        }

        let toml_str = if name == "toml_takes_precedence" {
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
                api_key = "toml-discovery"

                [llm.phases.verification]
                base_url = "http://test"
                api_key = "toml-verification"

                [llm.phases.aggregation]
                base_url = "http://test"
            "#
            .to_string()
        } else {
            base_config_toml()
        };

        let mut config: ScannerConfig = toml::from_str(&toml_str).unwrap();
        apply_env_overrides(&mut config);

        assert_eq!(
            config.llm.phases.discovery.api_key.as_deref(),
            expected_discovery,
            "{}: discovery key",
            name
        );
        assert_eq!(
            config.llm.phases.verification.api_key.as_deref(),
            expected_verification,
            "{}: verification key",
            name
        );
        assert_eq!(
            config.llm.phases.aggregation.api_key.as_deref(),
            expected_aggregation,
            "{}: aggregation key",
            name
        );
    }
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
fn test_validate_errors() {
    let cases = vec![
        (
            "missing_base_url",
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
                base_url = ""
                api_key = "test-key"
                model = "test"

                [llm.phases.verification]
                base_url = "http://test"
                model = "test"

                [llm.phases.aggregation]
                base_url = "http://test"
                model = "test"
            "#,
            true,
            Some("discovery"),
            Some("base_url"),
            None,
        ),
        (
            "missing_model",
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
                api_key = "test-key"

                [llm.phases.verification]
                base_url = "http://test"
                model = "test"

                [llm.phases.aggregation]
                base_url = "http://test"
                model = "test"
            "#,
            true,
            Some("discovery"),
            Some("model"),
            None,
        ),
        (
            "empty_api_key_skips_validation",
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
                model = "test"

                [llm.phases.verification]
                base_url = "http://test"
                model = "test"

                [llm.phases.aggregation]
                base_url = "http://test"
                model = "test"
            "#,
            false,
            None,
            None,
            Some("base_url"),
        ),
        (
            "none_api_key_skips_validation",
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
                model = "test"

                [llm.phases.verification]
                base_url = "http://test"
                model = "test"

                [llm.phases.aggregation]
                base_url = "http://test"
                model = "test"
            "#,
            false,
            None,
            None,
            Some("base_url"),
        ),
        (
            "nonexistent_project_path",
            r#"
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
            "#,
            true,
            None,
            None,
            Some("does not exist"),
        ),
    ];

    for (
        name,
        toml_str,
        expect_llm_error,
        expected_field1,
        expected_field2,
        skip_llm_check_field,
    ) in cases {
        let config: ScannerConfig = toml::from_str(toml_str).unwrap();
        
        if name == "none_api_key_skips_validation" {
            assert!(config.llm.phases.discovery.api_key.is_none(), "{}: api_key is None", name);
        }
        
        let result = config.validate();

        if expect_llm_error {
            assert!(result.is_err(), "{}: expected error", name);
            let err_msg = result.unwrap_err().to_string();
            if let Some(field1) = expected_field1 {
                assert!(err_msg.contains(field1), "{}: error should contain '{}'", name, field1);
            }
            if let Some(field2) = expected_field2 {
                assert!(err_msg.contains(field2), "{}: error should contain '{}'", name, field2);
            }
        } else {
            if let Err(err_msg) = result {
                let err_str = err_msg.to_string();
                if let Some(skip_field) = skip_llm_check_field {
                    assert!(!err_str.contains(skip_field), "{}: should not contain '{}' (LLM validation skipped)", name, skip_field);
                    if let Some(field2) = expected_field2 {
                        assert!(!err_str.contains(field2), "{}: should not contain '{}' (LLM validation skipped)", name, field2);
                    }
                }
            }
        }
    }
}

#[test]
fn test_from_file_errors() {
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

    assert!(!settings.enable_incremental_scan);
    assert!(!settings.enable_threat_modeling);
    assert!(settings.enable_root_cause_dedup);
    assert!(settings.enable_multi_verifier);
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
fn test_llm_phase_config_get_models() {
    let cases = vec![
        (
            "priority_models_list",
            LlmPhaseConfig {
                base_url: "http://test".to_string(),
                api_key: Some("key".to_string()),
                model: "single-model".to_string(),
                models: vec!["multi-1".to_string(), "multi-2".to_string()],
                timeout_secs: None,
            },
            vec!["multi-1", "multi-2"],
        ),
        (
            "fallback_single_model",
            LlmPhaseConfig {
                base_url: "http://test".to_string(),
                api_key: Some("key".to_string()),
                model: "single-model".to_string(),
                models: vec![],
                timeout_secs: None,
            },
            vec!["single-model"],
        ),
        (
            "empty_when_both_missing",
            LlmPhaseConfig {
                base_url: "http://test".to_string(),
                api_key: Some("key".to_string()),
                model: "".to_string(),
                models: vec![],
                timeout_secs: None,
            },
            vec![],
        ),
    ];

    for (name, phase, expected_models) in cases {
        let models = phase.get_models();
        assert_eq!(
            models.len(),
            expected_models.len(),
            "{}: model count",
            name
        );
        for (i, expected) in expected_models.iter().enumerate() {
            assert_eq!(models[i], *expected, "{}: model {}", name, i);
        }
    }
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
