//! Tests for Scanner initialization and basic operations

use tests::fixtures::{
    create_test_config, create_test_finding, create_test_findings, ensure_test_output_dir,
};
use baco::scanner::Scanner;

#[test]
fn test_scanner_new_creates_default_state() {
    ensure_test_output_dir();

    let config = create_test_config();
    let scanner = Scanner::new(config, "/tmp/test-project".into(), false);

    // Verify scanner was created
    // Path may not exist in tests
    let _ = scanner.target_path();

    // Verify state has default values
    let state = scanner.state.borrow();
    assert!(state.findings.is_empty());
    assert_eq!(state.files_scanned, 0);
    assert!(state.errors.is_empty());
    assert!(state.cve_entries.is_empty());
    assert!(state.project_stack.is_none());
}

#[test]
fn test_scanner_with_initial_findings() {
    ensure_test_output_dir();

    let config = create_test_config();
    let initial_findings = create_test_findings(3);
    let scanner = Scanner::with_initial_findings(
        config,
        "/tmp/test-project".into(),
        initial_findings.clone(),
        false,
    );

    // Verify initial findings are set
    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 3);
    assert_eq!(state.findings[0].id, "test-finding-0");
}

#[test]
fn test_scanner_force_flag() {
    ensure_test_output_dir();

    let config = create_test_config();
    let scanner = Scanner::new(config, "/tmp/test-project".into(), true);

    // Force flag is internal, just verify scanner created
    let _ = scanner.target_path();
}

#[test]
fn test_scanner_target_path() {
    ensure_test_output_dir();

    let config = create_test_config();
    let target = PathBuf::from("/some/target");
    let scanner = Scanner::new(config, target.clone(), false);

    assert_eq!(scanner.target_path(), &target);
}

#[test]
fn test_scanner_findings_method() {
    ensure_test_output_dir();

    let config = create_test_config();
    let findings = create_test_findings(2);
    let scanner =
        Scanner::with_initial_findings(config, "/tmp/test-project".into(), findings, false);

    let retrieved = scanner.findings();
    assert_eq!(retrieved.len(), 2);
}

#[test]
fn test_scanner_findings_mut_method() {
    ensure_test_output_dir();

    let config = create_test_config();
    let findings = create_test_findings(5);
    let scanner =
        Scanner::with_initial_findings(config, "/tmp/test-project".into(), findings, false);

    let retrieved = scanner.findings_mut();
    assert_eq!(retrieved.len(), 5);
}

#[test]
fn test_scanner_update_findings() {
    ensure_test_output_dir();

    let config = create_test_config();
    let scanner = Scanner::new(config, "/tmp/test-project".into(), false);

    // Add some findings
    let new_findings = create_test_findings(4);
    scanner.update_findings(new_findings);

    // Verify update
    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 4);
}

#[test]
fn test_scanner_add_finding() {
    ensure_test_output_dir();

    let config = create_test_config();
    let scanner = Scanner::new(config, "/tmp/test-project".into(), false);

    // Add findings one by one
    let finding1 = create_test_finding();
    let finding2 = create_test_finding();

    scanner.add_finding(finding1);
    scanner.add_finding(finding2);

    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 2);
}

#[test]
fn test_scanner_state_immutability() {
    ensure_test_output_dir();

    let config = create_test_config();
    let scanner = Scanner::new(config, "/tmp/test-project".into(), false);

    // Multiple borrows should work
    let state1 = scanner.state.borrow();
    let state2 = scanner.state.borrow();

    assert_eq!(state1.findings.len(), state2.findings.len());
}

use std::path::PathBuf;
