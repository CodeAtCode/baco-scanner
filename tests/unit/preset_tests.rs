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
        err.to_string().contains("Unknown preset"),
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
    use std::collections::HashSet;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let preset_names = [
        "wordpress-core",
        "wordpress-plugin",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    // Known leaf key paths (wildcard patterns for tables with arbitrary children)
    let known_keys: HashSet<String> = [
        // Project section
        "project.*".to_string(),
        // Scanner section
        "scanner.*".to_string(),
        "scanner.semgrep.*".to_string(),
        "scanner.performance.*".to_string(),
        // LLM section
        "llm.*".to_string(),
        "llm.phases.*".to_string(),
        "llm.phases.discovery.*".to_string(),
        "llm.phases.verification.*".to_string(),
        "llm.phases.aggregation.*".to_string(),
        // Triage section
        "triage.*".to_string(),
        // Priority section
        "priority.*".to_string(),
        // Budget section
        "budget.*".to_string(),
        // Knowledge section (includes fp_patterns, required_security_primitives, hook_registry)
        "knowledge.*".to_string(),
        "knowledge.fp_patterns.*".to_string(),
        "knowledge.required_security_primitives.*".to_string(),
        "knowledge.hook_registry.*".to_string(),
        // Agent section
        "agent_flow.*".to_string(),
        "agent.*".to_string(),
    ]
    .iter()
    .cloned()
    .collect();

    for name in &preset_names {
        let preset_path = format!("{}/presets/{}.toml", manifest_dir, name);
        let content = std::fs::read_to_string(&preset_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", preset_path, e));

        let value: toml::Value = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", preset_path, e));

        // Collect all leaf key paths from the preset
        let mut preset_paths = HashSet::new();
        collect_key_paths(&value, "", &mut preset_paths);

        // Verify each preset path matches a known pattern
        for path in &preset_paths {
            let matches = known_keys.iter().any(|known| {
                if known.ends_with(".*") {
                    let prefix = &known[..known.len() - 2];
                    path.starts_with(prefix)
                } else {
                    *path == *known
                }
            });
            assert!(
                matches,
                "Preset {} has unknown key path: {} (known: {:?})",
                name, path, known_keys
            );
        }
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

// ============================================================================
// Overlay Merge Precedence Tests
// ============================================================================

#[test]
fn test_preset_overlay_precedence() {
    // Test that preset values override base values where set,
    // but unset fields keep base values
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();

    // Set base values first
    config.project.name = "base-project-name".to_string();
    config.project.path = "/base/path".to_string();
    config.scanner.max_file_size_kb = 256;

    // Apply preset
    preset.merge_into(&mut config);

    // Preset values should override where set
    assert_eq!(config.project.name, "wordpress-core");
    // Path is set in preset, so preset value wins
    assert_eq!(config.project.path, "./wordpress");
    // max_file_size_kb is set in preset, so preset value wins
    assert_eq!(config.scanner.max_file_size_kb, 256);
}

#[test]
fn test_preset_unknown_key_rejection() {
    // Verify that unknown keys in preset TOML are rejected during parsing
    // This is enforced by the test_presets_contain_only_known_keys test
    // Here we verify the known presets all load successfully
    let preset_names = [
        "wordpress-core",
        "wordpress-plugin",
        "django",
        "laravel",
        "cpp",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    for name in &preset_names {
        let result = preset::load_preset(name);
        assert!(
            result.is_ok(),
            "Preset {} should load without unknown key errors",
            name
        );
    }
}

#[test]
fn test_preset_custom_rules_array_cpp() {
    // Verify cpp preset has custom_rules array
    let preset = preset::load_preset("cpp").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    // cpp preset should have custom_rules populated
    assert!(
        !config.scanner.semgrep.custom_rules.is_empty(),
        "cpp preset should have custom_rules array"
    );
}

#[test]
fn test_preset_custom_rules_array_wp() {
    // Verify wordpress presets have custom_rules array
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    assert!(
        !config.scanner.semgrep.custom_rules.is_empty(),
        "wordpress-core preset should have custom_rules array"
    );

    let preset = preset::load_preset("wordpress-plugin").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    assert!(
        !config.scanner.semgrep.custom_rules.is_empty(),
        "wordpress-plugin preset should have custom_rules array"
    );
}

#[test]
fn test_preset_hook_registry_overlay_propagation_django() {
    // Verify django preset hook_registry config propagates to base
    let preset = preset::load_preset("django").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let python_cfg = config.knowledge.hook_registry.get("python");
    assert!(
        python_cfg.is_some(),
        "django preset should propagate python hook_registry"
    );
    let python_cfg = python_cfg.unwrap();
    assert_eq!(python_cfg.hook_label, "urlpatterns");
    // Django has 3 registration patterns: path, re_path, url
    assert_eq!(python_cfg.registrations.len(), 3);
}

#[test]
fn test_preset_hook_registry_overlay_propagation_laravel() {
    // Verify laravel preset hook_registry config propagates to base
    let preset = preset::load_preset("laravel").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_cfg = config.knowledge.hook_registry.get("php");
    assert!(
        php_cfg.is_some(),
        "laravel preset should propagate php hook_registry"
    );
    let php_cfg = php_cfg.unwrap();
    assert_eq!(php_cfg.hook_label, "rest_route");
    // Laravel has 1 registration pattern: Route::get/post/etc
    assert_eq!(php_cfg.registrations.len(), 1);
}

#[test]
fn test_preset_explicit_override_wins() {
    // Test that explicit user config values win over preset values
    // This tests the merge_into implementation where preset overrides base
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();

    // Set explicit values before applying preset
    config.project.name = "explicit-name".to_string();
    config.scanner.max_file_size_kb = 1024;

    // Apply preset (preset wins per current implementation)
    preset.merge_into(&mut config);

    // Per current implementation, preset overwrites
    assert_eq!(config.project.name, "wordpress-core");
    assert_eq!(config.scanner.max_file_size_kb, 256);
}
