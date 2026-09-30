//! End-to-end behaviour of the hook primitive check as the indexing phase runs
//! it: hook registration and the missing-primitive check in one pass, producing
//! real findings.
//!
//! The unit level for the static check itself lives in `hook_registry_tests`.

use baco::config::knowledge::HookRegistryLanguageConfig;
use baco::scanner::phases::other_phases::indexing::register_hooks_and_check_primitives;
use std::collections::HashMap;
use std::path::Path;

fn wp_php_config() -> HookRegistryLanguageConfig {
    HookRegistryLanguageConfig {
        hook_label: "rest_route".to_string(),
        registrations: vec![
            r"(?si)add_action\s*\(\s*[\x27\x22](?P<hook>(?:wp_ajax|wp_ajax_nopriv|admin_post|admin_post_nopriv)[^\x27\x22]*)[\x27\x22]\s*,\s*".to_string(),
            r"(?si)register_rest_route\s*\([^;]*?[\x27\x22]callback[\x27\x22]\s*=>\s*".to_string(),
        ],
        handler_patterns: None,
    }
}

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

fn run(source: &str) -> Vec<baco::findings::VulnerabilityFinding> {
    let mut hook_map: HashMap<String, Vec<baco::hook_registry::HookRegistration>> = HashMap::new();
    let mut findings = Vec::new();
    register_hooks_and_check_primitives(
        Path::new("/wp-content/plugins/pay4payment/class-pay4pay.php"),
        source,
        &wp_php_config(),
        &php_primitives(),
        &mut hook_map,
        &mut findings,
    );
    findings
}

/// The real-world case: the entry point delegates and the authorisation lives in
/// the callee. This must not be reported.
#[test]
fn test_delegating_handler_with_primitive_in_callee_produces_no_finding() {
    let source = r#"<?php
add_action( 'wp_ajax_nopriv_pay4payment_rated', 'pay4payment_rated_ajax_handler' );

function pay4payment_rated_ajax_handler() {
    pay4payment_rated();
}

function pay4payment_rated() {
    check_admin_referer( 'pay4payment_rated' );
    global $wpdb;
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'paid' ) );
}
"#;
    let findings = run(source);
    assert!(
        findings.is_empty(),
        "a primitive in the callee protects the entry point, got {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

/// Same plugin, authorisation removed. This is the finding the check exists for.
#[test]
fn test_nopriv_entry_point_without_any_primitive_is_high() {
    let source = r#"<?php
add_action( 'wp_ajax_nopriv_pay4payment_rated', 'pay4payment_rated_ajax_handler' );

function pay4payment_rated_ajax_handler() {
    global $wpdb;
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => $_POST['status'] ) );
}
"#;
    let findings = run(source);
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding, got {}",
        findings.len()
    );

    let f = &findings[0];
    assert_eq!(
        f.severity,
        baco::findings::Severity::High,
        "an unauthenticated entry point with no primitive is high"
    );
    assert_eq!(
        f.cwe_id.as_deref(),
        Some("CWE-306"),
        "missing authentication on a critical function, not CSRF"
    );
    assert!(
        f.title.contains("wp_ajax_nopriv_pay4payment_rated"),
        "the finding must name the hook, got {}",
        f.title
    );
    assert!(
        f.description.contains("pay4payment_rated_ajax_handler"),
        "the finding must name the handler, got {}",
        f.description
    );
    assert_eq!(
        f.file_path,
        "/wp-content/plugins/pay4payment/class-pay4pay.php"
    );
    assert_eq!(f.sources, vec!["hook_primitive_check".to_string()]);
    assert!(
        f.llm_model.is_none(),
        "this check is static, so it must not claim an LLM produced it"
    );
}

#[test]
fn test_authenticated_entry_point_without_primitive_is_medium_and_csrf() {
    let source = r#"<?php
add_action( 'wp_ajax_pay4payment_rate', 'pay4payment_rate_ajax_handler' );

function pay4payment_rate_ajax_handler() {
    global $wpdb;
    $wpdb->update( $wpdb->prefix . 'orders', array( 'rate' => $_POST['rate'] ) );
}
"#;
    let findings = run(source);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(
        f.severity,
        baco::findings::Severity::Medium,
        "an authenticated entry point missing the nonce is a CSRF surface"
    );
    assert_eq!(f.cwe_id.as_deref(), Some("CWE-352"));
}

#[test]
fn test_primitive_directly_in_the_handler_produces_no_finding() {
    let source = r#"<?php
add_action( 'wp_ajax_nopriv_save_item', 'save_item' );

function save_item() {
    check_ajax_referer( 'save_item', 'nonce' );
    global $wpdb;
    $wpdb->insert( $wpdb->prefix . 'items', array( 'name' => $_POST['name'] ) );
}
"#;
    assert!(run(source).is_empty());
}

#[test]
fn test_registration_without_a_handler_in_this_file_produces_no_finding() {
    // The callback may be a method on a class defined elsewhere. Reporting it
    // from this file would be a finding with no evidence behind it.
    let source = r#"<?php
add_action( 'wp_ajax_nopriv_save_item', array( $this, 'save_item' ) );
"#;
    assert!(run(source).is_empty());
}

#[test]
fn test_registration_without_primitives_configured_produces_no_finding() {
    let source = r#"<?php
add_action( 'wp_ajax_nopriv_save_item', 'save_item' );

function save_item() {
    global $wpdb;
    $wpdb->insert( $wpdb->prefix . 'items', array() );
}
"#;
    let mut hook_map: HashMap<String, Vec<baco::hook_registry::HookRegistration>> = HashMap::new();
    let mut findings = Vec::new();
    register_hooks_and_check_primitives(
        Path::new("/x.php"),
        source,
        &wp_php_config(),
        &[],
        &mut hook_map,
        &mut findings,
    );
    assert!(
        findings.is_empty(),
        "no primitives configured means nothing can be missing, got {}",
        findings.len()
    );
    assert!(
        !hook_map.is_empty(),
        "the hook must still be registered even with no primitives configured"
    );
}
