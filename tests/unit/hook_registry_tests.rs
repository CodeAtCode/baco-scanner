//! Config-driven hook registry tests

use baco::config::knowledge::HookRegistryLanguageConfig;
use baco::hook_registry::{self, HookRegistration, find_unprotected_hooks};
use std::collections::HashMap;
use tempfile::TempDir;

fn php_primitives() -> Vec<String> {
    [
        "wp_verify_nonce",
        "check_admin_referer",
        "check_ajax_referer",
        "current_user_can",
        "user_can",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn reg(hook: &str, handler: &str) -> HookRegistration {
    HookRegistration {
        hook: hook.to_string(),
        handler: handler.to_string(),
    }
}

#[test]
fn test_primitive_in_a_callee_protects_the_entry_point() {
    // The delegation shape: an entry point that does nothing itself and calls a
    // helper which authorises. Reading only the handler body reports this as
    // unprotected, which is the false positive this check exists to remove.
    let content = r#"<?php
function pay4payment_rated_ajax_handler() {
    do_something();
}

function do_something() {
    check_admin_referer('pay4payment');
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'paid' ) );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg(
            "wp_ajax_nopriv_pay4payment_rated",
            "pay4payment_rated_ajax_handler",
        )],
        &php_primitives(),
    );
    assert!(
        out.is_empty(),
        "a primitive reachable from a callee must protect the handler, got {:?}",
        out
    );

    // Control: the same delegation shape with the primitive removed must be
    // reported. Without this, the assertion above also passes when the whole
    // check is a no-op -- finding nothing is exactly what a broken check does.
    let control_source = r#"<?php
function pay4payment_rated_ajax_handler() {
    do_something();
}

function do_something() {
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'paid' ) );
}
"#;
    let control = find_unprotected_hooks(
        control_source,
        &[reg(
            "wp_ajax_nopriv_pay4payment_rated",
            "pay4payment_rated_ajax_handler",
        )],
        &php_primitives(),
    );
    assert_eq!(
        control.len(),
        1,
        "removing the primitive must make it reportable, got {:?}",
        control
    );
}

#[test]
fn test_primitive_two_callee_levels_deep_still_protects() {
    let content = r#"<?php
function handler_a() {
    check_permission();
}

function check_permission() {
    guard();
}

function guard() {
    current_user_can('manage_options');
}
"#;
    let out = find_unprotected_hooks(content, &[reg("wp_ajax_x", "handler_a")], &php_primitives());
    assert!(
        out.is_empty(),
        "depth 2 must reach the primitive, got {:?}",
        out
    );

    // Control: the same chain with no primitive anywhere must be reported, so
    // this test fails if the walk stops returning a verdict at all.
    let chain_without = r#"<?php
function handler_a() {
    check_permission();
}

function check_permission() {
    guard();
}

function guard() {
    $wpdb->insert( $wpdb->prefix . 'x', array() );
}
"#;
    let control = find_unprotected_hooks(
        chain_without,
        &[reg("wp_ajax_x", "handler_a")],
        &php_primitives(),
    );
    assert_eq!(control.len(), 1, "got {:?}", control);
}

#[test]
fn test_nopriv_entry_point_without_primitive_is_unauthenticated() {
    let content = r#"<?php
function save_item() {
    $wpdb->insert( $wpdb->prefix . 'items', array( 'name' => $_POST['name'] ) );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_nopriv_save_item", "save_item")],
        &php_primitives(),
    );
    assert_eq!(out.len(), 1, "expected one unprotected hook, got {:?}", out);
    assert!(
        out[0].unauthenticated,
        "wp_ajax_nopriv_ must be flagged unauthenticated"
    );
    assert_eq!(out[0].handler, "save_item");
}

#[test]
fn test_authenticated_entry_point_without_primitive_is_not_unauthenticated() {
    let content = r#"<?php
function save_item() {
    $wpdb->insert( $wpdb->prefix . 'items', array( 'name' => $_POST['name'] ) );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_save_item", "save_item")],
        &php_primitives(),
    );
    assert_eq!(out.len(), 1, "expected one unprotected hook, got {:?}", out);
    assert!(
        !out[0].unauthenticated,
        "wp_ajax_ requires a logged-in user, so this is a CSRF surface, not an unauthenticated one"
    );
}

#[test]
fn test_same_handler_on_two_hooks_yields_two_severities() {
    // One finding per handler, but severity comes from the hook. Two hooks on
    // the same function are two different risks, so they must not collapse.
    let content = r#"<?php
function save_item() {
    $wpdb->delete( $wpdb->prefix . 'items', array( 'id' => $_POST['id'] ) );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[
            reg("wp_ajax_save_item", "save_item"),
            reg("wp_ajax_nopriv_save_item", "save_item"),
        ],
        &php_primitives(),
    );
    assert_eq!(out.len(), 2, "expected one finding per hook, got {:?}", out);
    let unauth = out.iter().filter(|u| u.unauthenticated).count();
    assert_eq!(unauth, 1, "exactly one of the two is unauthenticated");
}

#[test]
fn test_primitive_in_the_handler_body_directly_protects() {
    let content = r#"<?php
function save_item() {
    check_ajax_referer( 'save_item', 'nonce' );
    $wpdb->insert( $wpdb->prefix . 'items', array() );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_nopriv_save_item", "save_item")],
        &php_primitives(),
    );
    assert!(
        out.is_empty(),
        "a primitive in the handler protects it, got {:?}",
        out
    );

    // Control: same handler shape with the primitive removed, must be reported.
    let stripped = r#"<?php
function save_item() {
    $wpdb->insert( $wpdb->prefix . 'items', array() );
}
"#;
    let control = find_unprotected_hooks(
        stripped,
        &[reg("wp_ajax_nopriv_save_item", "save_item")],
        &php_primitives(),
    );
    assert_eq!(control.len(), 1, "got {:?}", control);
}

#[test]
fn test_handler_not_declared_in_this_file_is_not_reported() {
    // The hook may point at a method or a function in another file. Reporting it
    // here would be a finding with no evidence behind it.
    let content = r#"<?php
function unrelated() {
    return 1;
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_nopriv_thing", "defined_elsewhere")],
        &php_primitives(),
    );
    assert!(
        out.is_empty(),
        "an unresolvable handler must not be reported"
    );
}

#[test]
fn test_brace_inside_a_string_does_not_end_the_function_body() {
    // The body has to be found by brace matching with lexical state, not by a
    // regex: a `}` inside a string would truncate it, and the check would then
    // look at a fragment and miss the primitive that follows.
    let content = r#"<?php
function save_item() {
    $msg = "a closing brace } is not the end";
    check_ajax_referer( 'save_item', 'nonce' );
    $wpdb->insert( $wpdb->prefix . 'items', array() );
}
"#;
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_nopriv_save_item", "save_item")],
        &php_primitives(),
    );
    assert!(
        out.is_empty(),
        "a `}}` inside a string literal must not truncate the body, got {:?}",
        out
    );
}

#[test]
fn test_handler_line_is_the_declaration_line() {
    let content = "<?php\n\nfunction save_item() {\n    do_something();\n}\n";
    let out = find_unprotected_hooks(
        content,
        &[reg("wp_ajax_nopriv_save_item", "save_item")],
        &php_primitives(),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].line, 3, "the finding must point at the declaration");
}

#[test]
fn test_no_primitives_configured_reports_nothing() {
    // With no primitives for the language there is nothing to be missing, and
    // reporting anyway would flood a scan that simply did not opt in.
    let content = "<?php\nfunction save_item() { $wpdb->insert('x'); }\n";
    let out = find_unprotected_hooks(content, &[reg("wp_ajax_nopriv_x", "save_item")], &[]);
    assert!(
        out.is_empty(),
        "no primitives configured must mean no findings"
    );
}

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

    // Keyed by file path, as in production: the value is the list of hook
    // registrations found in that file, each carrying its hook name.
    let mut map = HashMap::new();
    map.insert(
        "/wp-content/plugins/x.php".to_string(),
        vec![HookRegistration {
            hook: "wp_ajax_test".to_string(),
            handler: "test_handler".to_string(),
        }],
    );

    // Save
    hook_registry::save_hook_map(&path, &map).expect("Failed to save hook map");

    // Load
    let loaded = hook_registry::load_hook_map(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded.get("/wp-content/plugins/x.php").unwrap(),
        &vec![HookRegistration {
            hook: "wp_ajax_test".to_string(),
            handler: "test_handler".to_string(),
        }]
    );

    // The hook name has to survive the round trip: it is what separates an
    // authenticated entry point from an unauthenticated one, and the primitive
    // check sets severity from it.
    assert_eq!(
        loaded.get("/wp-content/plugins/x.php").unwrap()[0].hook,
        "wp_ajax_test"
    );

    // Missing file → empty map
    let missing_path = tempdir.path().join("nonexistent.json");
    let empty = hook_registry::load_hook_map(&missing_path);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_corrupt_hook_map_does_not_panic_and_leaves_no_temporary_behind() {
    let tempdir = TempDir::new().expect("Failed to create temp dir");
    let path = tempdir.path().join("hook_map.json");

    // A truncated file, which is what an interrupted plain `fs::write` leaves
    // behind. Loading it must not panic, and must not invent hooks either.
    std::fs::write(&path, "{\"wp_ajax_a\": [\"hand").expect("Failed to write corrupt file");
    let loaded = hook_registry::load_hook_map(&path);
    assert!(
        loaded.is_empty(),
        "a corrupt map must not yield partial hooks, got {:?}",
        loaded
    );

    // The atomic write must not leave its temporary next to the target.
    let mut map = HashMap::new();
    map.insert(
        "/b.php".to_string(),
        vec![HookRegistration {
            hook: "wp_ajax_b".to_string(),
            handler: "handler_b".to_string(),
        }],
    );
    hook_registry::save_hook_map(&path, &map).expect("Failed to save over a corrupt file");

    let reloaded = hook_registry::load_hook_map(&path);
    assert_eq!(
        reloaded.len(),
        1,
        "the corrupt file must be replaced wholesale"
    );

    let leftover: Vec<_> = std::fs::read_dir(tempdir.path())
        .expect("Failed to list temp dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftover.is_empty(),
        "atomic write left a temporary behind: {:?}",
        leftover
    );
}

#[test]
fn test_hook_map_save_replaces_a_populated_file() {
    let tempdir = TempDir::new().expect("Failed to create temp dir");
    let path = tempdir.path().join("hook_map.json");

    let mut first = HashMap::new();
    first.insert(
        "/old.php".to_string(),
        vec![HookRegistration {
            hook: "wp_ajax_old".to_string(),
            handler: "old_handler".to_string(),
        }],
    );
    hook_registry::save_hook_map(&path, &first).expect("Failed to save first map");

    let mut second = HashMap::new();
    second.insert(
        "/new.php".to_string(),
        vec![HookRegistration {
            hook: "wp_ajax_new".to_string(),
            handler: "new_handler".to_string(),
        }],
    );
    hook_registry::save_hook_map(&path, &second).expect("Failed to save second map");

    let loaded = hook_registry::load_hook_map(&path);
    assert_eq!(loaded.len(), 1, "the second save must replace, not merge");
    assert!(
        loaded.contains_key("/new.php"),
        "the new map must be what survives, got {:?}",
        loaded
    );
    assert!(!loaded.contains_key("wp_ajax_old"));
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
    let hook_map_with_entry: HashMap<String, Vec<HookRegistration>> = {
        let mut m = HashMap::new();
        m.insert(
            "src/handler.php".to_string(),
            vec![HookRegistration {
                hook: "wp_ajax_save".to_string(),
                handler: "handler".to_string(),
            }],
        );
        m
    };
    let hook_map_empty: HashMap<String, Vec<HookRegistration>> = HashMap::new();

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
