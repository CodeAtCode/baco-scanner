use baco::checkpoint::Checkpoint;
use baco::config::ConfigError;
use baco::validation::{validate_checkpoint, validate_config};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_validate_config_success_returns_config() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let config_toml = "[project]\nname = \"test\"\npath = \"/tmp\"\n";
    temp_file.write_all(config_toml.as_bytes()).unwrap();

    let result = validate_config(temp_file.path());
    match &result {
        Ok(config) => {
            assert_eq!(config.project.path, "/tmp");
        }
        Err(ConfigError::MissingDependency { tool, .. }) => {
            // Semgrep not installed in test env — config parsed and path validated successfully
            assert_eq!(tool, "Semgrep");
        }
        Err(e) => panic!("Expected Ok or MissingDependency, got: {:?}", e),
    }
}

#[test]
fn test_validate_checkpoint_success_returns_checkpoint() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let checkpoint_json = r#"{"scan_id":"scan-1","project_path":"/tmp","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0}"#;
    temp_file.write_all(checkpoint_json.as_bytes()).unwrap();

    let result = validate_checkpoint(temp_file.path());
    assert!(result.is_ok(), "Error: {:?}", result.err());
    let checkpoint: Checkpoint = result.unwrap();
    assert_eq!(checkpoint.scan_id, "scan-1");
    assert_eq!(checkpoint.project_path, "/tmp");
}
