//! Config-driven hook registry tests

use baco::config::knowledge::HookRegistryLanguageConfig;
use baco::hook_registry;
use std::collections::HashMap;
use tempfile::TempDir;

/// Helper to build a WordPress PHP hook config matching the preset
fn wp_php_config() -> HookRegistryLanguageConfig {
    HookRegistryLanguageConfig {
        hook_label: "rest_route".to_string(),
        registrations: vec![
            r"(?si)add_action\s*\(\s*[\x27\x22](?P<hook>(?:wp_ajax|wp_ajax_nopriv|admin_post|admin_post_nopriv)[^\x27\x22]*)[\x27\x22]\s*,\s*".to_string(),
            r"(?si)register_rest_route\s*\([^;]*?[\x27\x22]callback[\x27\x22]\s*=>\s*".to_string(),
        ],
        handler_patterns: None, // Use built-in PHP callable forms
    }
}

#[test]
fn test_extracts_wp_ajax_string_callable() {
    let content = r#"add_action('wp_ajax_save_settings', 'save_settings');"#;
    let cfg = wp_php_config();
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 1, "Expected one registration");
    assert_eq!(regs[0].hook, "wp_ajax_save_settings");
    assert_eq!(regs[0].handler, "save_settings");
}

#[test]
fn test_extracts_ajax_array_callable_method() {
    let content = r#"add_action( 'wp_ajax_nopriv_ping', [$this, 'ping_handler'] );"#;
    let cfg = wp_php_config();
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 1, "Expected one registration");
    assert_eq!(regs[0].hook, "wp_ajax_nopriv_ping");
    assert_eq!(regs[0].handler, "ping_handler");
}

#[test]
fn test_extracts_rest_route_callback_string_and_array() {
    let content = r#"
        register_rest_route('my-ns', '/v1', array(
            'methods' => 'GET',
            'callback' => 'my_handler'
        ));
        register_rest_route('another-ns', '/v2', array(
            'methods' => 'POST',
            'callback' => array($this, 'rest_method')
        ));
    "#;
    let cfg = wp_php_config();
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 2, "Expected two registrations");
    // First one: rest_route_my_handler
    assert!(regs[0].hook.starts_with("rest_route_"));
    assert_eq!(regs[0].handler, "my_handler");
    // Second one: rest_route_rest_method
    assert!(regs[1].hook.starts_with("rest_route_"));
    assert_eq!(regs[1].handler, "rest_method");
}

#[test]
fn test_ignores_non_entry_hooks() {
    let content = r#"
        add_action('save_post', 'x');
        add_filter('wp_ajax_x', 'y');
        add_action('wp_enqueue_scripts', 'z');
    "#;
    let cfg = wp_php_config();
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(
        regs.len(),
        0,
        "Expected zero registrations for non-entry hooks"
    );
}

#[test]
fn test_dedupes_repeated_registrations() {
    let content = r#"
        add_action('wp_ajax_test', 'test_handler');
        add_action('wp_ajax_test', 'test_handler');
    "#;
    let cfg = wp_php_config();
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 1, "Expected deduped registration");
    assert_eq!(regs[0].hook, "wp_ajax_test");
    assert_eq!(regs[0].handler, "test_handler");
}

#[test]
fn test_hook_map_round_trip_and_missing_file() {
    let tempdir = TempDir::new().expect("Failed to create temp dir");
    let path = tempdir.path().join("hook_map.json");

    let mut map = HashMap::new();
    map.insert("wp_ajax_test".to_string(), vec!["test_handler".to_string()]);

    // Save
    hook_registry::save_hook_map(&path, &map).expect("Failed to save hook map");

    // Load
    let loaded = hook_registry::load_hook_map(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded.get("wp_ajax_test").unwrap(),
        &vec!["test_handler".to_string()]
    );

    // Missing file → empty map
    let missing_path = tempdir.path().join("nonexistent.json");
    let empty = hook_registry::load_hook_map(&missing_path);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_extract_with_empty_registrations() {
    let content = r#"add_action('wp_ajax_test', 'test_handler');"#;
    let cfg = HookRegistryLanguageConfig {
        hook_label: "entry_point".to_string(),
        registrations: vec![],
        handler_patterns: None,
    };
    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(
        regs.len(),
        0,
        "Empty registrations should produce empty result"
    );
}

#[test]
fn test_priority_boost_for_hook_files() {
    use baco::config::PriorityConfig;
    use baco::indexer::FileInfo;
    use baco::scanner::phases::llm_phases::static_analysis::compute_file_priority_score;
    use std::path::PathBuf;

    let file = FileInfo {
        path: PathBuf::from("src/handler.php"),
        size: 5000,
        language: "php".to_string(),
        hash: None,
    };

    let priority = PriorityConfig::default();
    let hook_map_with_entry: HashMap<String, Vec<String>> = {
        let mut m = HashMap::new();
        m.insert("src/handler.php".to_string(), vec!["handler".to_string()]);
        m
    };
    let hook_map_empty: HashMap<String, Vec<String>> = HashMap::new();

    let score_with = compute_file_priority_score(&file, &priority, &hook_map_with_entry);
    let score_without = compute_file_priority_score(&file, &priority, &hook_map_empty);

    // With hook entry: base * entry_point_boost (1.5)
    // Without hook entry: base (no hook boost)
    let expected_with = score_without * priority.entry_point_boost;
    assert!(
        (score_with - expected_with).abs() < 1e-6,
        "Expected score_with ({}) to equal score_without ({}) * entry_point_boost ({})",
        score_with,
        score_without,
        priority.entry_point_boost
    );
}

#[test]
fn test_wp_presets_deserialize_with_hook_registry() {
    use baco::config::ScannerConfig;
    use baco::preset;

    // Test wordpress-core preset
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_cfg = config.knowledge.hook_registry.get("php");
    assert!(
        php_cfg.is_some(),
        "wordpress-core should have php hook_registry config"
    );
    let php_cfg = php_cfg.unwrap();
    assert_eq!(php_cfg.hook_label, "rest_route");
    assert_eq!(
        php_cfg.registrations.len(),
        2,
        "Should have 2 registration patterns"
    );

    // Test wordpress-plugin preset
    let preset = preset::load_preset("wordpress-plugin").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_cfg = config.knowledge.hook_registry.get("php");
    assert!(
        php_cfg.is_some(),
        "wordpress-plugin should have php hook_registry config"
    );
    let php_cfg = php_cfg.unwrap();
    assert_eq!(php_cfg.hook_label, "rest_route");
    assert_eq!(
        php_cfg.registrations.len(),
        2,
        "Should have 2 registration patterns"
    );
}

#[test]
fn test_django_laravel_presets_deserialize_with_hook_registry() {
    use baco::config::ScannerConfig;
    use baco::preset;

    // Test django preset
    let preset = preset::load_preset("django").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let python_cfg = config.knowledge.hook_registry.get("python");
    assert!(
        python_cfg.is_some(),
        "django should have python hook_registry config"
    );
    let python_cfg = python_cfg.unwrap();
    // Django has 3 registrations: path, re_path, url
    assert_eq!(
        python_cfg.registrations.len(),
        3,
        "django should have 3 registration patterns"
    );
    assert!(
        python_cfg.handler_patterns.is_some(),
        "django should have handler_patterns"
    );
    assert_eq!(
        python_cfg.handler_patterns.as_ref().unwrap().len(),
        1,
        "django should have 1 handler pattern"
    );

    // Test laravel preset
    let preset = preset::load_preset("laravel").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_cfg = config.knowledge.hook_registry.get("php");
    assert!(
        php_cfg.is_some(),
        "laravel should have php hook_registry config"
    );
    let php_cfg = php_cfg.unwrap();
    // Laravel has 1 registration: Route::get/post/etc
    assert_eq!(
        php_cfg.registrations.len(),
        1,
        "laravel should have 1 registration pattern"
    );
    assert!(
        php_cfg.handler_patterns.is_some(),
        "laravel should have handler_patterns"
    );
    assert_eq!(
        php_cfg.handler_patterns.as_ref().unwrap().len(),
        2,
        "laravel should have 2 handler patterns"
    );
}
