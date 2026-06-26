//! Shared test utilities for the baco scanner.
//!
//! This module consolidates duplicated test helper functions to reduce code duplication.

use crate::config::ScannerConfig;
use crate::scanner::Scanner;
use tempfile::TempDir;
use std::path::PathBuf;

/// Creates a test scanner with a temporary directory.
///
/// # Arguments
/// * `temp_dir` - Optional temporary directory. If None, a new one is created.
/// * `config` - Optional configuration. If None, default config is used.
///
/// # Returns
/// A tuple of (Scanner, TempDir) where TempDir is Some if a new temp dir was created.
pub fn create_test_scanner(
    temp_dir: Option<TempDir>,
    config: Option<ScannerConfig>,
) -> (Scanner, Option<TempDir>) {
    let temp_dir = temp_dir.unwrap_or_else(|| TempDir::new().unwrap());
    let config = config.unwrap_or_else(ScannerConfig::default);
    
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, Some(temp_dir))
}

/// Creates a test scanner with default settings.
pub fn create_default_test_scanner() -> (Scanner, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, temp_dir)
}
