//! Test helper functions for integration tests

use crate::config::ScannerConfig;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to set up a test environment with project and output directories
pub fn setup_test_env(temp_dir: &TempDir, project_name: &str) -> (PathBuf, PathBuf) {
    let project_path = temp_dir.path().join(project_name);
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();
    fs::create_dir_all(&project_path).unwrap();
    (project_path, output_dir)
}

/// Helper to create a scanner config for testing
pub fn create_test_config(
    project_path: PathBuf,
    output_dir: PathBuf,
    project_name: &str,
) -> ScannerConfig {
    let mut config = ScannerConfig::default();
    config.output.dir = output_dir.to_string_lossy().to_string();
    config.project.path = project_path.to_string_lossy().to_string();
    config.project.name = project_name.to_string();
    config
}
