//! Tests for force_scan flag in SemgrepRunner
//!
//! These tests verify that the `--no-git-ignore` flag is correctly added
//! to the semgrep command when force_scan is enabled.

use baco::semgrep::SemgrepRunner;

#[test]
fn test_force_scan_default_false() {
    // Default construction should have force_scan = false
    let runner = SemgrepRunner::new(vec![], vec![]);
    assert!(!runner.force_scan, "force_scan should default to false");
}

#[test]
fn test_force_scan_builder_sets_flag() {
    // Builder should set force_scan to true
    let runner = SemgrepRunner::new(vec![], vec![]).with_force_scan(true);
    assert!(
        runner.force_scan,
        "force_scan should be true after with_force_scan(true)"
    );
}

#[test]
fn test_force_scan_builder_can_disable() {
    // Builder should be able to explicitly set force_scan to false
    let runner = SemgrepRunner::new(vec![], vec![]).with_force_scan(false);
    assert!(
        !runner.force_scan,
        "force_scan should be false after with_force_scan(false)"
    );
}

#[test]
fn test_force_scan_with_other_settings() {
    // force_scan should work alongside other settings
    let runner = SemgrepRunner::new(
        vec!["p/python".to_string()],
        vec!["python.lang".to_string()],
    )
    .with_languages(vec!["python".to_string()])
    .with_timeout(120)
    .with_max_target_bytes(2000000)
    .with_force_scan(true);

    assert!(runner.force_scan, "force_scan should be true");
    assert_eq!(runner.rulesets, vec!["p/python".to_string()]);
    assert_eq!(runner.exclude_rules, vec!["python.lang".to_string()]);
    assert_eq!(runner.timeout_secs, 120);
    assert_eq!(runner.max_target_bytes, Some(2000000));
}

#[test]
fn test_build_args_no_force_scan_flag_when_disabled() {
    // When force_scan is false, --no-git-ignore should NOT appear in args
    let runner = SemgrepRunner::new(vec![], vec![]).with_force_scan(false);
    let args = runner.build_args("/target/path", &[]);

    assert!(
        !args.contains(&"--no-git-ignore".to_string()),
        "--no-git-ignore should NOT be in args when force_scan=false"
    );
}

#[test]
fn test_build_args_includes_force_scan_flag_when_enabled() {
    // When force_scan is true, --no-git-ignore MUST appear in args
    let runner = SemgrepRunner::new(vec![], vec![]).with_force_scan(true);
    let args = runner.build_args("/target/path", &[]);

    assert!(
        args.contains(&"--no-git-ignore".to_string()),
        "--no-git-ignore MUST be in args when force_scan=true"
    );

    // Verify the flag appears before the target path
    let no_git_ignore_idx = args.iter().position(|a| a == "--no-git-ignore").unwrap();
    let target_idx = args.iter().position(|a| a == "/target/path").unwrap();
    assert!(
        no_git_ignore_idx < target_idx,
        "--no-git-ignore should appear before target path"
    );
}

#[test]
fn test_build_args_with_rulesets_and_force_scan() {
    // Verify force_scan flag works alongside rulesets
    let runner = SemgrepRunner::new(vec!["p/python".to_string()], vec![]).with_force_scan(true);

    let rulesets = runner.derive_default_rulesets();
    let args = runner.build_args("/target/path", &rulesets);

    assert!(args.contains(&"--no-git-ignore".to_string()));
    assert!(args.contains(&"--config".to_string()));
    assert!(args.contains(&"p/python".to_string()));
}
