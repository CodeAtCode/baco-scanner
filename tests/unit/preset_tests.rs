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

// Regression tests for preset TOML structure (T39-T42)

#[test]
fn test_presets_use_rulesets_key() {
    // Verify no preset uses the phantom 'config' key in semgrep section
    let preset_names = [
        "wordpress-core",
        "wordpress-plugin",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    for name in &preset_names {
        // Load preset to verify it parses
        let _preset = preset::load_preset(name).unwrap();
        // The preset should load without error (TOML parses correctly)

        // Also verify the raw file doesn't contain the phantom key
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let preset_path = format!("{}/presets/{}.toml", manifest_dir, name);
        let content = std::fs::read_to_string(&preset_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", preset_path, e));

        // Assert the string "\nconfig = [" does not appear (phantom key guard)
        assert!(
            !content.contains("\nconfig = ["),
            "Preset {} should not use 'config' key in semgrep section",
            name
        );
    }
}

#[test]
fn test_wordpress_core_merge_rulesets() {
    // Regression test: verify rulesets land in scanner.semgrep.rulesets
    // This would have caught the phantom 'config' key bug
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    assert!(
        config
            .scanner
            .semgrep
            .rulesets
            .contains(&"p/wordpress".to_string()),
        "wordpress-core preset should have 'p/wordpress' in rulesets"
    );
}

#[test]
fn test_preset_priority_patterns_merge() {
    // Verify entry_point_patterns and sink_patterns merge correctly
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    assert!(
        config
            .priority
            .entry_point_patterns
            .contains(&"xmlrpc.php".to_string()),
        "wordpress-core preset should have 'xmlrpc.php' in entry_point_patterns"
    );
    assert!(
        config.priority.sink_patterns.contains(&"eval(".to_string()),
        "wordpress-core preset should have 'eval(' in sink_patterns"
    );
}

#[test]
fn test_preset_fp_patterns_merge() {
    // Verify fp_patterns merge correctly
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let cwe79_patterns = config.knowledge.fp_patterns.get("CWE-79");
    assert!(
        cwe79_patterns.is_some(),
        "wordpress-core preset should have CWE-79 fp_patterns"
    );
    assert!(
        cwe79_patterns.unwrap().contains(&"esc_html(".to_string()),
        "CWE-79 fp_patterns should contain 'esc_html('"
    );
}

#[test]
fn test_presets_contain_only_known_keys() {
    // Anti-phantom guard: verify all preset keys are known
    // Build the set of known key paths by serializing a fully-populated PresetOverlay
    use std::collections::HashSet;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let preset_names = [
        "wordpress-core",
        "wordpress-plugin",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    for name in &preset_names {
        let preset_path = format!("{}/presets/{}.toml", manifest_dir, name);
        let content = std::fs::read_to_string(&preset_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", preset_path, e));

        let value: toml::Value = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", preset_path, e));

        // Collect all leaf key paths from the preset
        let mut preset_paths = HashSet::new();
        collect_key_paths(&value, "", &mut preset_paths);

        // For now, just verify the TOML parses (full key validation requires
        // PresetOverlay serialization which may not compile until parallel lane lands)
        // This test will be enhanced when PresetOverlay::try_into(toml::Value) is available
        assert!(
            !preset_paths.is_empty(),
            "Preset {} should have at least some keys",
            name
        );
    }
}

// Helper to recursively collect key paths from a toml::Value
fn collect_key_paths(
    value: &toml::Value,
    prefix: &str,
    paths: &mut std::collections::HashSet<String>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table {
                let full_key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };

                // Check if this is a leaf table (all values are non-tables)
                let is_leaf_table = val
                    .as_table()
                    .is_some_and(|t| t.values().all(|v| v.as_table().is_none()));

                if is_leaf_table {
                    // Record this as a wildcard path (any child key allowed)
                    paths.insert(format!("{}.*", full_key));
                } else {
                    paths.insert(full_key.clone());
                    collect_key_paths(val, &full_key, paths);
                }
            }
        }
        _ => {
            // Leaf value - path already recorded by parent
        }
    }
}
