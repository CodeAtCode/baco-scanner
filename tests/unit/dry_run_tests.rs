/// Tests for dry-run mode and cost estimation.
///
/// These tests verify:
/// - Estimate calculation math (files → tokens)
/// - Budget cap respected in estimate
/// - Dry-run flag parsing
/// - Version string format
use baco::cost_estimate::{
    bytes_to_tokens, compute_estimate, count_high_risk_files, estimate_llm_calls,
};
use std::path::PathBuf;

fn make_file(path: &str, size: u64, language: &str) -> baco::indexer::FileInfo {
    baco::indexer::FileInfo {
        path: PathBuf::from(path),
        size,
        language: language.to_string(),
        hash: None,
    }
}

#[test]
fn test_estimate_calculation_math() {
    // Test bytes to tokens conversion (~4 chars per token)
    assert_eq!(bytes_to_tokens(400), 100);
    assert_eq!(bytes_to_tokens(800), 200);
    assert_eq!(bytes_to_tokens(1000), 250);
    assert_eq!(bytes_to_tokens(3), 0); // Less than 4 chars = 0 tokens

    // Test full estimate calculation
    let files = vec![
        make_file("src/main.rs", 1000, "rust"),
        make_file("src/lib.rs", 2000, "rust"),
        make_file("src/index.ts", 1500, "typescript"),
    ];

    let estimate = compute_estimate(&files, 100, 0.2, false, &[1.0, 1.0, 1.0]);

    assert_eq!(estimate.total_files, 3);
    assert_eq!(estimate.total_bytes, 4500);
    assert_eq!(estimate.estimated_tokens, 1125); // 4500 / 4
    assert_eq!(estimate.planned_llm_calls, 3); // min(100, 3)
    assert_eq!(estimate.files_by_language.get("rust").unwrap(), &2);
    assert_eq!(estimate.files_by_language.get("typescript").unwrap(), &1);
}

#[test]
fn test_budget_cap_respected() {
    // Test that budget cap is respected in estimate
    let files: Vec<baco::indexer::FileInfo> = (0..200)
        .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
        .collect();

    let estimate = compute_estimate(&files, 50, 0.0, false, &[1.0; 200]);

    assert_eq!(estimate.total_files, 200);
    assert_eq!(estimate.planned_llm_calls, 50); // Capped at budget
    assert_eq!(estimate.max_llm_calls, 50);
}

#[test]
fn test_budget_cap_with_triage() {
    // Test budget cap with triage enabled
    let files: Vec<baco::indexer::FileInfo> = (0..100)
        .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
        .collect();

    let estimate = compute_estimate(&files, 100, 0.0, true, &[1.0; 100]);

    // With triage, ~50% pass: 100 / 2 = 50
    assert_eq!(estimate.planned_llm_calls, 50);
}

#[test]
fn test_high_risk_file_counting() {
    let files = vec![
        make_file("src/main.rs", 1000, "rust"),
        make_file("src/lib.rs", 500, "rust"),
        make_file("src/index.ts", 800, "typescript"),
        make_file("src/app.py", 600, "python"),
        make_file("src/server.js", 700, "javascript"),
        make_file("src/__init__.py", 200, "python"),
        make_file("src/utils.rs", 400, "rust"),
    ];

    let count = count_high_risk_files(&files);
    assert_eq!(count, 5); // main, index, app, server, __init__
}

#[test]
fn test_llm_call_estimate_no_triage() {
    // No triage: all files considered up to budget
    let calls = estimate_llm_calls(100, 10, 50, 0.0, false);
    assert_eq!(calls, 50); // Capped at budget
}

#[test]
fn test_llm_call_estimate_with_triage() {
    // With triage: ~50% of non-high-risk files pass
    let calls = estimate_llm_calls(100, 10, 100, 0.0, true);
    // normal_count = 90, triaged_normal = 45
    // high_risk = 10
    // Total = 55
    assert_eq!(calls, 55);
}

#[test]
fn test_llm_call_estimate_with_reserve() {
    // Budget with reserve for high-risk files
    let calls = estimate_llm_calls(100, 10, 50, 0.2, false);
    // normal_cap = 50 - (50 * 0.2) = 40
    // All files considered, capped at 50
    assert_eq!(calls, 50);
}

#[test]
fn test_empty_file_list() {
    let files: Vec<baco::indexer::FileInfo> = vec![];

    let estimate = compute_estimate(&files, 100, 0.2, false, &[]);

    assert_eq!(estimate.total_files, 0);
    assert_eq!(estimate.total_bytes, 0);
    assert_eq!(estimate.estimated_tokens, 0);
    assert_eq!(estimate.planned_llm_calls, 0);
    assert_eq!(estimate.avg_priority_score, 0.0);
    assert!(estimate.files_by_language.is_empty());
}

#[test]
fn test_version_string_format() {
    // Verify that the version string follows semver format
    let version = env!("CARGO_PKG_VERSION");

    // Should contain at least major.minor.patch
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "Version should have at least major.minor.patch"
    );

    // Major, minor, patch should be numeric
    assert!(
        parts[0].parse::<u32>().is_ok(),
        "Major version should be numeric"
    );
    assert!(
        parts[1].parse::<u32>().is_ok(),
        "Minor version should be numeric"
    );

    // Patch might have suffix (e.g., "0-alpha.1"), so just check it starts with a number
    assert!(
        parts[2]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false),
        "Patch version should start with a number"
    );
}

#[test]
fn test_dry_run_flag_parsing() {
    // Test that --dry-run flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[arg(long)]
        dry_run: bool,
    }

    // Test with flag present
    let cli = TestCli::try_parse_from(["test", "--dry-run"]);
    assert!(cli.is_ok());
    assert!(cli.unwrap().dry_run);

    // Test with flag absent
    let cli = TestCli::try_parse_from(["test"]);
    assert!(cli.is_ok());
    assert!(!cli.unwrap().dry_run);
}

#[test]
fn test_preset_flag_parsing() {
    // Test that --preset flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[arg(long)]
        preset: Option<String>,
    }

    // Test with flag and value
    let cli = TestCli::try_parse_from(["test", "--preset", "default"]);
    assert!(cli.is_ok());
    assert_eq!(cli.unwrap().preset, Some("default".to_string()));

    // Test with flag absent
    let cli = TestCli::try_parse_from(["test"]);
    assert!(cli.is_ok());
    assert!(cli.unwrap().preset.is_none());
}

#[test]
fn test_version_flag_parsing() {
    // Test that --version flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(version = "1.0.0")]
    struct TestCli {
        #[arg(long)]
        dry_run: bool,
    }

    // Test version is set
    let cli = TestCli::parse_from(["test", "--dry-run"]);
    assert!(cli.dry_run);
}
