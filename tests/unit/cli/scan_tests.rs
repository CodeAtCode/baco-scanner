//! Unit tests for `baco::cli::scan` helper functions.

use baco::checkpoint::ScanPhase;
use baco::cli::scan::{format_phase, print_scan_summary, run_dry_run};
use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use tempfile::TempDir;

/// Test `format_phase` with various ScanPhase variants.
#[test]
fn test_format_phase() {
    // Test a few representative phases
    let indexing = format_phase(&ScanPhase::Indexing);
    assert!(!indexing.is_empty());
    assert!(indexing.contains("Indexing"));

    let semgrep = format_phase(&ScanPhase::Semgrep);
    assert!(!semgrep.is_empty());
    assert!(semgrep.contains("Semgrep"));

    let reporting = format_phase(&ScanPhase::Reporting);
    eprintln!("DEBUG: reporting = '{}'", reporting);
    assert!(!reporting.is_empty());
    assert!(reporting.contains("Reporting"));

    // Format should be "N/24 Name"
    assert!(indexing.contains('/'));
    assert!(indexing.contains(' '));
}

/// Test `print_scan_summary` creates findings.json and findings.md.
#[test]
fn test_print_scan_summary() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path();

    // Create test findings with different severities
    let findings = vec![
        VulnerabilityFinding {
            id: "test-finding-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "SQL injection vulnerability".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.9,
            file_path: "src/main.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("execute(query)".to_string()),
            ..Default::default()
        },
        VulnerabilityFinding {
            id: "test-finding-2".to_string(),
            title: "XSS".to_string(),
            description: "Cross-site scripting".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            file_path: "src/handler.rs".to_string(),
            line_number: Some(100),
            code_snippet: Some("render(user_input)".to_string()),
            ..Default::default()
        },
        VulnerabilityFinding {
            id: "test-finding-3".to_string(),
            title: "Info Leak".to_string(),
            description: "Information disclosure".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.7,
            file_path: "src/api.rs".to_string(),
            line_number: Some(55),
            code_snippet: Some("dump_debug(data)".to_string()),
            ..Default::default()
        },
    ];

    // Call print_scan_summary with quiet=false to see output
    let result = print_scan_summary(
        &findings,
        output_dir,
        "test-project",
        false, // evidence_gate_enabled
        true,  // quiet
    );

    assert!(result.is_ok(), "print_scan_summary should succeed");

    // Verify findings.json was created
    let findings_path = output_dir.join("findings.json");
    assert!(findings_path.exists(), "findings.json should be created");

    // Verify findings.md was created
    let markdown_path = output_dir.join("findings.md");
    assert!(markdown_path.exists(), "findings.md should be created");

    // Verify findings.json contains the findings
    let json_content = std::fs::read_to_string(&findings_path).unwrap();
    assert!(json_content.contains("test-finding-1"));
    assert!(json_content.contains("test-finding-2"));
    assert!(json_content.contains("test-finding-3"));
}

/// Test `run_dry_run` with a minimal project.
#[test]
fn test_run_dry_run() {
    // Create a temp target directory with a small source file
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let target_path = temp_dir.path();

    // Create a simple Rust file
    let source_file = target_path.join("main.rs");
    std::fs::write(&source_file, "fn main() { println!(\"Hello\"); }").unwrap();

    // Create output directory for config
    let output_dir = TempDir::new().expect("Failed to create output temp dir");

    // Create a minimal config
    let mut config = ScannerConfig::default();
    config.project.path = target_path.to_string_lossy().to_string();
    config.project.languages = vec!["rust".to_string()];
    config.output.dir = output_dir.path().to_string_lossy().to_string();
    config.scanner.max_file_size_kb = 512;
    config.scanner.exclude_paths = vec![];
    config.scanner.performance.enable_file_filtering = false;

    // Call run_dry_run with quiet=true
    let result = run_dry_run(&config, target_path, true);

    assert!(result.is_ok(), "run_dry_run should succeed");
}
