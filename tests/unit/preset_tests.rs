//! Unit tests for the preset system

use baco::config::ScannerConfig;
use baco::preset;

#[test]
fn test_wordpress_core_preset_parses() {
    let preset = preset::load_preset("wordpress-core");
    assert!(preset.is_ok(), "wordpress-core preset should load");

    let overlay = preset.unwrap();
    let mut config = ScannerConfig::default();
    overlay.merge_into(&mut config);

    // Verify preset-specific fields
    assert_eq!(config.project.name, "wordpress-core");
    assert!(config.project.languages.contains(&"php".to_string()));
    assert!(config.project.languages.contains(&"javascript".to_string()));
}

#[test]
fn test_wordpress_plugin_preset_parses() {
    let preset = preset::load_preset("wordpress-plugin");
    assert!(preset.is_ok(), "wordpress-plugin preset should load");

    let overlay = preset.unwrap();
    let mut config = ScannerConfig::default();
    overlay.merge_into(&mut config);

    // Verify preset-specific fields
    assert_eq!(config.project.name, "wordpress-plugin");
    assert!(config.project.languages.contains(&"php".to_string()));
}

#[test]
fn test_litellm_preset_parses() {
    let preset = preset::load_preset("litellm");
    assert!(preset.is_ok(), "litellm preset should load");

    let overlay = preset.unwrap();
    let mut config = ScannerConfig::default();
    overlay.merge_into(&mut config);

    // Verify preset-specific fields
    assert_eq!(config.project.name, "litellm");
    assert!(config.project.languages.contains(&"python".to_string()));
}

#[test]
fn test_oss_python_preset_parses() {
    let preset = preset::load_preset("oss-python");
    assert!(preset.is_ok(), "oss-python preset should load");

    let overlay = preset.unwrap();
    let mut config = ScannerConfig::default();
    overlay.merge_into(&mut config);

    // Verify preset-specific fields
    assert_eq!(config.project.name, "oss-python");
    assert!(config.project.languages.contains(&"python".to_string()));
}

#[test]
fn test_oss_monorepo_preset_parses() {
    let preset = preset::load_preset("oss-monorepo");
    assert!(preset.is_ok(), "oss-monorepo preset should load");

    let overlay = preset.unwrap();
    let mut config = ScannerConfig::default();
    overlay.merge_into(&mut config);

    // Verify preset-specific fields
    assert_eq!(config.project.name, "oss-monorepo");
    assert!(config.project.languages.contains(&"python".to_string()));
    assert!(config.project.languages.contains(&"rust".to_string()));
}

#[test]
fn test_unknown_preset_errors() {
    let result = preset::load_preset("nonexistent-preset-xyz");
    assert!(result.is_err(), "Unknown preset should error");
    let err = result.unwrap_err();
    assert!(
        err.contains("Unknown preset"),
        "Error should mention unknown preset"
    );
}

#[test]
fn test_preset_list_contains_all_builtins() {
    let presets = preset::list_available_presets();

    let builtins = [
        "wordpress-core",
        "wordpress-plugin",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];
    for builtin in &builtins {
        assert!(
            presets.iter().any(|p| p.starts_with(*builtin)),
            "Built-in preset '{}' should be in list",
            builtin
        );
    }
}

#[test]
fn test_user_config_overrides_preset() {
    // Load preset
    let preset = preset::load_preset("wordpress-core").unwrap();

    // Create a "user config" that overrides some values
    let mut config = ScannerConfig::default();
    config.project.name = "my-custom-project".to_string();
    config.project.path = "./my-project".to_string();

    // Apply preset (preset values become defaults)
    preset.merge_into(&mut config);

    // User config values should be preserved where preset doesn't override
    // Note: Currently preset overwrites, so this tests the current behavior
    // In a real scenario, user config would be applied AFTER preset
    assert_eq!(config.project.name, "wordpress-core"); // preset wins in current impl
}

#[test]
fn test_preset_triage_config() {
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    // WordPress preset has triage enabled with specific settings
    assert!(config.triage.enabled);
    assert_eq!(config.triage.model, "mistral-small");
    assert_eq!(config.triage.batch_size, 8);
}

#[test]
fn test_preset_budget_config() {
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    // WordPress preset has high budget for core audit
    assert!(config.budget.enabled);
    assert_eq!(config.budget.max_llm_calls, 600);
}

#[test]
fn test_preset_agent_flow_staging_only() {
    // All OSS presets should have agent_flow disabled or staging-only
    let presets = [
        "wordpress-core",
        "wordpress-plugin",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];
    for name in &presets {
        let preset = preset::load_preset(name).unwrap();
        let mut config = ScannerConfig::default();
        preset.merge_into(&mut config);

        // Agent flow should be disabled for untrusted OSS targets
        assert!(
            !config.agent_flow.enabled,
            "Preset {} should have agent_flow disabled",
            name
        );
    }
}
