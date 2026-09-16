//! Org-context profile tests and symlink containment tests.

use baco::config::OrgContextConfig;
use baco::indexer::FileIndex;
use baco::org_context::render;
use std::collections::HashMap;
use std::fs;

/// Test render returns None when disabled
#[test]
fn test_org_context_render_disabled() {
    let cfg = OrgContextConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(render(&cfg).is_none());
}

/// Test render returns None when enabled but all optional fields empty
#[test]
fn test_org_context_render_enabled_but_empty() {
    let cfg = OrgContextConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(render(&cfg).is_none());
}

/// Test pii data_sensitivity renders "at least High"
#[test]
fn test_org_context_render_pii() {
    let cfg = OrgContextConfig {
        enabled: true,
        data_sensitivity: Some("pii".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("at least High"));
}

/// Test vault secret_storage renders placeholder warning
#[test]
fn test_org_context_render_vault() {
    let cfg = OrgContextConfig {
        enabled: true,
        secret_storage: Some("vault".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("placeholders, NOT leaked secrets"));
}

/// Test risk_tolerance renders anti-misread note
#[test]
fn test_org_context_render_risk_tolerance() {
    let cfg = OrgContextConfig {
        enabled: true,
        risk_tolerance: Some("low".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("does NOT mean only report criticals"));
}

/// Test severity_rules renders as OVERRIDE lines
#[test]
fn test_org_context_render_severity_rules() {
    let mut rules = HashMap::new();
    rules.insert("XSS".to_string(), "Critical".to_string());
    rules.insert("SQLi".to_string(), "Critical".to_string());
    let cfg = OrgContextConfig {
        enabled: true,
        severity_rules: rules,
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("OVERRIDE: XSS → Critical"));
    assert!(result.contains("OVERRIDE: SQLi → Critical"));
}

/// Test stack and infra are rendered correctly
#[test]
fn test_org_context_render_stack() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["php".to_string(), "javascript".to_string()],
        infra: vec!["aws".to_string()],
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("The target is"));
    assert!(result.contains("php"));
    assert!(result.contains("javascript"));
    assert!(result.contains("aws"));
}

/// Symlink containment test: symlink escaping scan root should be skipped
#[test]
fn test_symlink_containment_escape() {
    use std::os::unix::fs::symlink;

    // Create temp directory structure
    let temp_root = std::env::temp_dir().join("baco_symlink_test");
    let _ = fs::remove_dir_all(&temp_root); // Clean up any prior run
    fs::create_dir_all(&temp_root).unwrap();

    // Create real file inside scan root
    let sub_dir = temp_root.join("sub");
    fs::create_dir_all(&sub_dir).unwrap();
    let real_file = sub_dir.join("real.py");
    fs::write(&real_file, "print('hello')").unwrap();

    // Create evil file outside scan root
    let outside_file = std::env::temp_dir().join("baco_evil_file.py");
    fs::write(&outside_file, "import evil").unwrap();

    // Create symlink inside scan root pointing outside
    let link_file = sub_dir.join("link.py");
    symlink(&outside_file, &link_file).unwrap();

    // Index the root using FileIndex API
    let index = FileIndex::index_project(
        temp_root.to_str().unwrap(),
        &["python".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    // Assert real.py is indexed
    let real_paths: Vec<_> = index
        .files
        .iter()
        .map(|f| f.path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert!(
        real_paths.contains(&"real.py"),
        "real.py should be indexed, got: {:?}",
        real_paths
    );

    // Assert link.py is NOT indexed (symlink escape)
    assert!(
        !real_paths.contains(&"link.py"),
        "link.py (escaping symlink) should be skipped"
    );

    // Cleanup
    let _ = fs::remove_file(&outside_file);
    let _ = fs::remove_dir_all(&temp_root);
}

/// Symlink containment test: symlinks within scan root are NOT followed
/// (WalkDir default behavior - symlinks are seen but not traversed)
#[test]
fn test_symlink_containment_within_root() {
    use std::os::unix::fs::symlink;

    // Create temp directory structure
    let temp_root = std::env::temp_dir().join("baco_symlink_internal_test");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    // Create real file inside scan root
    let real_file = temp_root.join("real.py");
    fs::write(&real_file, "print('hello')").unwrap();

    // Create symlink inside scan root pointing to another file inside
    let link_file = temp_root.join("link.py");
    symlink(&real_file, &link_file).unwrap();

    // Index the root
    let index = FileIndex::index_project(
        temp_root.to_str().unwrap(),
        &["python".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    // real.py should be indexed
    // link.py (symlink) is seen by WalkDir but symlink_metadata check filters it
    // because canonicalize on a symlink to a file returns the file's real path
    let real_paths: Vec<_> = index
        .files
        .iter()
        .map(|f| f.path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert!(real_paths.contains(&"real.py"), "real.py should be indexed");
    // Symlinks are not indexed - they're filtered by the symlink containment check
    // (the symlink itself resolves to a path that starts with root, but we skip symlinks)
    assert!(
        !real_paths.contains(&"link.py"),
        "link.py (symlink) should not be indexed - WalkDir doesn't follow symlinks"
    );

    // Cleanup
    let _ = fs::remove_dir_all(&temp_root);
}

// ============================================================================
// Migrated inline tests from src/org_context.rs (7 tests)
// ============================================================================

#[test]
fn test_render_disabled_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(render(&cfg).is_none());
}

#[test]
fn test_render_enabled_but_empty_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(render(&cfg).is_none());
}

#[test]
fn test_render_pii_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: true,
        data_sensitivity: Some("pii".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("at least High"));
}

#[test]
fn test_render_vault_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: true,
        secret_storage: Some("vault".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("placeholders, NOT leaked secrets"));
}

#[test]
fn test_render_risk_tolerance_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: true,
        risk_tolerance: Some("low".to_string()),
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("does NOT mean only report criticals"));
}

#[test]
fn test_render_severity_rules_inline_migrated() {
    let mut rules = HashMap::new();
    rules.insert("XSS".to_string(), "Critical".to_string());
    let cfg = OrgContextConfig {
        enabled: true,
        severity_rules: rules,
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("OVERRIDE: XSS → Critical"));
}

#[test]
fn test_render_stack_inline_migrated() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["php".to_string(), "javascript".to_string()],
        ..Default::default()
    };
    let result = render(&cfg).unwrap();
    assert!(result.contains("The target is"));
    assert!(result.contains("php"));
    assert!(result.contains("javascript"));
}
#[test]
fn test_org_context_render_all_fields_set() {
    let mut rules = HashMap::new();
    rules.insert("XSS".to_string(), "Critical".to_string());
    rules.insert("SQLi".to_string(), "High".to_string());

    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["rust".to_string(), "javascript".to_string()],
        infra: vec!["gcp".to_string(), "kubernetes".to_string()],
        data_sensitivity: Some("pii".to_string()),
        secret_storage: Some("vault".to_string()),
        risk_tolerance: Some("low".to_string()),
        severity_rules: rules,
    };

    let result = render(&cfg).unwrap();

    // All sections should be present
    assert!(result.contains("The target is"));
    assert!(result.contains("rust"));
    assert!(result.contains("javascript"));
    assert!(result.contains("gcp"));
    assert!(result.contains("kubernetes"));
    assert!(result.contains("at least High"));
    assert!(result.contains("placeholders, NOT leaked secrets"));
    assert!(result.contains("Risk tolerance:"));
    assert!(result.contains("does NOT mean only report criticals"));
    assert!(result.contains("OVERRIDE: XSS → Critical"));
    assert!(result.contains("OVERRIDE: SQLi → High"));
}

#[test]
fn test_org_context_render_default_when_disabled() {
    let cfg = OrgContextConfig::default();

    // Default should have enabled = false
    assert!(!cfg.enabled);
    assert!(render(&cfg).is_none());
}

#[test]
fn test_org_context_render_only_stack() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["python".to_string()],
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("The target is python"));
    assert!(result.contains("apply checks idiomatic to this stack"));
}

#[test]
fn test_org_context_render_only_infra() {
    let cfg = OrgContextConfig {
        enabled: true,
        infra: vec!["azure".to_string()],
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("The target is azure"));
}

#[test]
fn test_org_context_render_data_sensitivity_other() {
    let cfg = OrgContextConfig {
        enabled: true,
        data_sensitivity: Some("financial".to_string()),
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("Data sensitivity level: financial"));
    assert!(result.contains("Apply appropriate handling guidance"));
}

#[test]
fn test_org_context_render_secret_storage_other() {
    let cfg = OrgContextConfig {
        enabled: true,
        secret_storage: Some("aws-secrets-manager".to_string()),
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("Secret storage: aws-secrets-manager"));
}

#[test]
fn test_org_context_render_risk_tolerance_high() {
    let cfg = OrgContextConfig {
        enabled: true,
        risk_tolerance: Some("high".to_string()),
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("Risk tolerance: 'high'"));
    assert!(result.contains("does NOT mean only report criticals"));
}

#[test]
fn test_org_context_render_severity_rules_multiple() {
    let mut rules = HashMap::new();
    rules.insert("RCE".to_string(), "Critical".to_string());
    rules.insert("IDOR".to_string(), "High".to_string());
    rules.insert("SSRF".to_string(), "Critical".to_string());

    let cfg = OrgContextConfig {
        enabled: true,
        severity_rules: rules,
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("OVERRIDE: RCE → Critical"));
    assert!(result.contains("OVERRIDE: IDOR → High"));
    assert!(result.contains("OVERRIDE: SSRF → Critical"));
}

#[test]
fn test_org_context_render_empty_stack_and_infra() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec![],
        infra: vec![],
        ..Default::default()
    };

    // Should return None when all fields are empty
    assert!(render(&cfg).is_none());
}

#[test]
fn test_org_context_render_header_present() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["go".to_string()],
        ..Default::default()
    };

    let result = render(&cfg).unwrap();
    assert!(result.contains("=== ORG CONTEXT ==="));
    assert!(result.contains("Organizational policy profile"));
}

// ============================================================================
// ADDITIONAL ORG CONTEXT TESTS
// ============================================================================

/// Test stack rendering into discovery prompt prefix
#[test]
fn test_org_context_stack_discovery_prefix() {
    let cfg = OrgContextConfig {
        enabled: true,
        stack: vec!["rust".to_string(), "typescript".to_string()],
        ..Default::default()
    };

    let result = render(&cfg).unwrap();

    // Should include stack in discovery context
    assert!(result.contains("rust"));
    assert!(result.contains("typescript"));
    assert!(result.contains("apply checks idiomatic to this stack"));
}

/// Test data_sensitivity rendering into verification prompt prefix
#[test]
fn test_org_context_data_sensitivity_verification_prefix() {
    let cfg = OrgContextConfig {
        enabled: true,
        data_sensitivity: Some("medical".to_string()),
        ..Default::default()
    };

    let result = render(&cfg).unwrap();

    // Medical data should trigger high sensitivity handling
    assert!(result.contains("medical"));
    assert!(result.contains("Data sensitivity level: medical"));
}

/// Test risk_tolerance rendering affects severity reporting guidance
#[test]
fn test_org_context_risk_tolerance_reporting_guidance() {
    let cfg = OrgContextConfig {
        enabled: true,
        risk_tolerance: Some("medium".to_string()),
        ..Default::default()
    };

    let result = render(&cfg).unwrap();

    // Risk tolerance should be documented with clear guidance
    assert!(result.contains("Risk tolerance"));
    assert!(result.contains("medium"));
    assert!(result.contains("does NOT mean only report criticals"));
}
