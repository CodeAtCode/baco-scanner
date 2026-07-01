//! Project type test helpers.
//!
//! This module consolidates duplicated configuration validation test code from:
//! - `src/project_type.rs:233-239` (test helpers)
//! - `tests/unit/project_type.rs:12-18` (duplicate test helpers)
//!
//! Reduces 48+ lines of duplication into shared test config builders.

use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Helper to create a temporary directory with a Cargo.toml content.
///
/// This consolidates the duplicated `create_temp_cargo_project` function that appears
/// in both `src/project_type.rs` tests and `tests/unit/project_type.rs`.
///
/// # Arguments
/// * `content` - Cargo.toml content to write
///
/// # Returns
/// A `TempDir` containing a Cargo.toml with the specified content
pub fn create_temp_cargo_project(content: &str) -> TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    let cargo_path = temp_dir.path().join("Cargo.toml");
    let mut file = fs::File::create(&cargo_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    temp_dir
}

/// Helper to create a temporary directory with a package.json content.
///
/// This consolidates the duplicated `create_temp_package_project` function.
///
/// # Arguments
/// * `content` - package.json content to write
///
/// # Returns
/// A `TempDir` containing a package.json with the specified content
pub fn create_temp_package_project(content: &str) -> TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    let package_path = temp_dir.path().join("package.json");
    let mut file = fs::File::create(&package_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    temp_dir
}

/// Helper to create a temporary directory with both Cargo.toml and src/main.rs.
///
/// # Arguments
/// * `cargo_content` - Cargo.toml content
/// * `main_content` - main.rs content (optional)
///
/// # Returns
/// A `TempDir` with a complete Rust project structure
pub fn create_temp_rust_project(
    cargo_content: &str,
    main_content: Option<&str>,
) -> TempDir {
    let temp_dir = create_temp_cargo_project(cargo_content);
    
    if let Some(content) = main_content {
        let src_dir = temp_dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let main_path = src_dir.join("main.rs");
        let mut file = fs::File::create(&main_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }
    
    temp_dir
}

/// Helper to create a temporary directory with both package.json and src/index.js.
///
/// # Arguments
/// * `package_content` - package.json content
/// * `index_content` - index.js content (optional)
///
/// # Returns
/// A `TempDir` with a complete Node.js project structure
pub fn create_temp_node_project(
    package_content: &str,
    index_content: Option<&str>,
) -> TempDir {
    let temp_dir = create_temp_package_project(package_content);
    
    if let Some(content) = index_content {
        let src_dir = temp_dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let index_path = src_dir.join("index.js");
        let mut file = fs::File::create(&index_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }
    
    temp_dir
}
