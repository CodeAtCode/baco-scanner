//! General project type detection tests
//!
//! These tests verify basic project type detection from Cargo.toml and package.json.

use baco::project_type::{detect_project_type, ProjectType};
use std::fs;
use std::io::Write;

/// Helper to create a temporary directory with a given Cargo.toml content
fn create_temp_cargo_project(content: &str) -> tempfile::TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    let cargo_path = temp_dir.path().join("Cargo.toml");
    let mut file = fs::File::create(&cargo_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    temp_dir
}

/// Helper to create a temporary directory with a given package.json content
fn create_temp_package_project(content: &str) -> tempfile::TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    let package_path = temp_dir.path().join("package.json");
    let mut file = fs::File::create(&package_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    temp_dir
}

// ============================================================================
// test_project_type_cli()
// ============================================================================

#[test]
fn test_project_type_cli() {
    // Test Rust CLI with clap
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4", features = ["derive"] }
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
    drop(temp_dir);

    // Test Rust CLI with structopt
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
structopt = "0.3"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
    drop(temp_dir);

    // Test Node.js CLI with commander
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-cli",
  "version": "1.0.0",
  "description": "A CLI tool",
  "bin": {
    "my-cli": "./bin/cli.js"
  },
  "dependencies": {
    "commander": "^9.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_web()
// ============================================================================

#[test]
fn test_project_type_web() {
    // Test Rust web with actix
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-web"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
    drop(temp_dir);

    // Test Rust web with axum
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-web"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
    drop(temp_dir);

    // Test Node.js web with Express
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
    drop(temp_dir);

    // Test Node.js web with React
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_library()
// ============================================================================

#[test]
fn test_project_type_library() {
    // Test Rust library with [lib] section
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-lib"
version = "0.1.0"
edition = "2021"

[lib]
name = "mylib"
path = "src/lib.rs"

[dependencies]
serde = "1.0"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Library);
    drop(temp_dir);

    // Test Node.js library with no bin
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-lib",
  "version": "1.0.0",
  "description": "A library",
  "main": "dist/index.js",
  "types": "dist/index.d.ts"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Library);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_unknown()
// ============================================================================

#[test]
fn test_project_type_unknown() {
    // Test project with no recognizable patterns
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-project"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1.0"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Unknown);
    drop(temp_dir);

    // Test Node.js project with no recognizable patterns
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-project",
  "version": "1.0.0",
  "description": "Just a project"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Unknown);
    drop(temp_dir);

    // Test non-existent path
    let project_type = detect_project_type(std::path::Path::new("/non/existent/path"));
    assert_eq!(project_type, ProjectType::Unknown);
}

// ============================================================================
// test_project_type_embedded()
// ============================================================================

#[test]
fn test_project_type_embedded() {
    // Test Rust embedded with no_std
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "embedded-app"
version = "0.1.0"
edition = "2021"

[dependencies]
cortex-m = "0.7"
cortex-m-rt = "0.7"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Embedded);
    drop(temp_dir);

    // Test Rust embedded with no_std flag
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "embedded-app"
version = "0.1.0"
edition = "2021"

[dependencies]
rtic = "1.1"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Embedded);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_firmware()
// ============================================================================

#[test]
fn test_project_type_firmware() {
    // Test Rust firmware with ESP32
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "esp32-firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
esp-idf-sys = "0.1"
panic-halt = "0.1"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
    drop(temp_dir);

    // Test Rust firmware with STM32
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "stm32-firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
stm32 = "0.2"
embedded-hal = "1.0"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_desktop()
// ============================================================================

#[test]
fn test_project_type_desktop() {
    // Test Rust desktop with Electron
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "desktop-app"
version = "0.1.0"
edition = "2021"

[dependencies]
electron-builder = "23"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Desktop);
    drop(temp_dir);

    // Test Rust desktop with Tauri
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "tauri-app"
version = "0.1.0"
edition = "2021"

[dependencies]
tauri = { version = "1", features = ["api-all"] }
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Desktop);
    drop(temp_dir);
}

// ============================================================================
// test_project_type_game()
// ============================================================================

#[test]
fn test_project_type_game() {
    // Test Rust game with Bevy
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-game"
version = "0.1.0"
edition = "2021"

[dependencies]
bevy = "0.13"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
    drop(temp_dir);

    // Test Node.js game with Three.js
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-game",
  "version": "1.0.0",
  "dependencies": {
    "three": "^0.150.0",
    "cannon": "^0.6.2"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
    drop(temp_dir);
}
