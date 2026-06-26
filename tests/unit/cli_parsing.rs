//! CLI parsing unit tests

use baco::cli::{Cli, Commands};
use baco::validation;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_cli_parsing_scan() {
    let cli = Cli::parse_from(["baco", "scan", "--config", "/tmp/config.toml"]);
    match cli.command {
        Commands::Scan { config, .. } => assert_eq!(config, PathBuf::from("/tmp/config.toml")),
        _ => panic!("Expected Scan command"),
    }
    // Test quiet flag parsing
    let cli_quiet =
        Cli::parse_from(["baco", "scan", "--config", "/tmp/config.toml", "--quiet"]);
    match cli_quiet.command {
        Commands::Scan { config, .. } => {
            assert_eq!(config, PathBuf::from("/tmp/config.toml"));
            assert!(cli_quiet.quiet);
        }
        _ => panic!("Expected Scan command"),
    }
}

#[test]
fn test_cli_parsing_resume() {
    let cli = Cli::parse_from(["baco", "resume", "--checkpoint", "/tmp/checkpoint.json"]);
    match cli.command {
        Commands::Resume { checkpoint } => {
            assert_eq!(checkpoint, PathBuf::from("/tmp/checkpoint.json"))
        }
        _ => panic!("Expected Resume command"),
    }
}

#[test]
fn test_cli_parsing_report() {
    let cli = Cli::parse_from([
        "baco",
        "report",
        "--input",
        "/tmp/findings.json",
        "--format",
        "html",
    ]);
    match cli.command {
        Commands::Report { input, format } => {
            assert_eq!(input, PathBuf::from("/tmp/findings.json"));
            assert_eq!(format, "html");
        }
        _ => panic!("Expected Report command"),
    }
}

#[test]
fn test_cli_parsing_verify() {
    let cli = Cli::parse_from(["baco", "verify", "--input", "/tmp/findings.json"]);
    match cli.command {
        Commands::Verify { input } => assert_eq!(input, PathBuf::from("/tmp/findings.json")),
        _ => panic!("Expected Verify command"),
    }
}

#[test]
fn test_validate_file_exists_nonexistent() {
    let result = validation::validate_file_exists(Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not exist"));
}

#[test]
fn test_validate_findings_valid_json() {
    let temp_dir = TempDir::new().unwrap();
    let findings_path = temp_dir.path().join("findings.json");
    let findings_json = r#"[{"id":"test-1","title":"Test","description":"Desc","severity":"high","confidence_score":0.8,"cwe_id":"CWE-79","file_path":"src/test.rs","line_number":10,"code_snippet":"code","recommendation":"fix","already_reported":false,"sources":[]}]"#;
    fs::write(&findings_path, findings_json).unwrap();

    let result = validation::validate_findings(&findings_path);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}
