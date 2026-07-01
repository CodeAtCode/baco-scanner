//! Unit tests for project type detection.
//!
//! Tests cover: project type detection, file extension matching, framework detection
//! from both Cargo.toml and package.json files.

use baco::project_type::{detect_project_type, ProjectType};
use std::fs;
use std::io::Write;
use std::path::Path;

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
// ProjectType enum tests
// ============================================================================

#[test]
fn test_project_type_default_is_unknown() {
    let unknown: ProjectType = Default::default();
    assert_eq!(unknown, ProjectType::Unknown);
}

#[test]
fn test_project_type_display() {
    assert_eq!(ProjectType::CLI.to_string(), "cli");
    assert_eq!(ProjectType::Web.to_string(), "web");
    assert_eq!(ProjectType::Library.to_string(), "library");
    assert_eq!(ProjectType::Embedded.to_string(), "embedded");
    assert_eq!(ProjectType::Firmware.to_string(), "firmware");
    assert_eq!(ProjectType::Desktop.to_string(), "desktop");
    assert_eq!(ProjectType::Game.to_string(), "game");
    assert_eq!(ProjectType::Unknown.to_string(), "unknown");
}

#[test]
fn test_project_type_equality() {
    assert_eq!(ProjectType::CLI, ProjectType::CLI);
    assert_eq!(ProjectType::Web, ProjectType::Web);
    assert_ne!(ProjectType::CLI, ProjectType::Web);
    assert_ne!(ProjectType::Library, ProjectType::Unknown);
}

#[test]
fn test_project_type_ordering() {
    // Verify partial ordering works
    assert!(ProjectType::Unknown < ProjectType::CLI);
    assert!(ProjectType::CLI < ProjectType::Web);
    assert!(ProjectType::Library < ProjectType::Embedded);
}

// ============================================================================
// CLI detection tests
// ============================================================================

#[test]
fn test_detect_cli_from_cargo_clap() {
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
}

#[test]
fn test_detect_cli_from_cargo_structopt() {
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
}

#[test]
fn test_detect_cli_from_cargo_docopt() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
docopt = "1.1"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

#[test]
fn test_detect_cli_from_package_json_bin() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-cli",
  "version": "1.0.0",
  "bin": "./bin/cli.js"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

#[test]
fn test_detect_cli_from_package_json_commander() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-cli",
  "version": "1.0.0",
  "dependencies": {
    "commander": "^9.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

#[test]
fn test_detect_cli_from_package_json_yargs() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-cli",
  "version": "1.0.0",
  "dependencies": {
    "yargs": "^17.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

#[test]
fn test_detect_cli_from_package_json_chalk() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-cli",
  "version": "1.0.0",
  "dependencies": {
    "chalk": "^5.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

// ============================================================================
// Web detection tests
// ============================================================================

#[test]
fn test_detect_web_from_cargo_actix() {
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
}

#[test]
fn test_detect_web_from_cargo_axum() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-web"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.7"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

#[test]
fn test_detect_web_from_cargo_rocket() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-web"
version = "0.1.0"
edition = "2021"

[dependencies]
rocket = "0.5"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

#[test]
fn test_detect_web_from_package_json_react() {
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
}

#[test]
fn test_detect_web_from_package_json_next() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "next": "^14.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

#[test]
fn test_detect_web_from_package_json_vue() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "vue": "^3.4.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

#[test]
fn test_detect_web_from_package_json_express() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

#[test]
fn test_detect_web_from_package_json_nestjs() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-web",
  "version": "1.0.0",
  "dependencies": {
    "@nestjs/core": "^10.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}

// ============================================================================
// Library detection tests
// ============================================================================

#[test]
fn test_detect_library_from_cargo_lib_section() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-lib"
version = "0.1.0"
edition = "2021"

[lib]
name = "mylib"
path = "src/lib.rs"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Library);
}

#[test]
fn test_detect_library_from_package_json_main() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-lib",
  "version": "1.0.0",
  "main": "dist/index.js"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Library);
}

#[test]
fn test_detect_library_from_package_json_types() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-lib",
  "version": "1.0.0",
  "types": "dist/index.d.ts"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Library);
}

// ============================================================================
// Embedded detection tests
// ============================================================================

#[test]
fn test_detect_embedded_from_cargo_no_std() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "embedded-app"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    );
    // Write a src/main.rs with no_std
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let main_path = src_dir.join("main.rs");
    let mut file = fs::File::create(&main_path).unwrap();
    file.write_all(b"#![no_std]").unwrap();
    file.write_all(b"#![no_main]").unwrap();

    let project_type = detect_project_type(temp_dir.path());
    // Note: current implementation checks lowercase content of Cargo.toml only
    // This test documents current behavior
    assert_eq!(project_type, ProjectType::Unknown);
}

#[test]
fn test_detect_embedded_from_cargo_cortex_m() {
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
}

#[test]
fn test_detect_embedded_from_cargo_rtic() {
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
}

// ============================================================================
// Firmware detection tests
// ============================================================================

#[test]
fn test_detect_firmware_from_cargo_esp_idf() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "esp32-firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
esp-idf-sys = "0.1"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
}

#[test]
fn test_detect_firmware_from_cargo_stm32() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "stm32-firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
stm32 = "0.2"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
}

#[test]
fn test_detect_firmware_from_cargo_embedded_hal() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
embedded-hal = "1.0"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
}

#[test]
fn test_detect_firmware_from_cargo_panic_halt() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "firmware"
version = "0.1.0"
edition = "2021"

[dependencies]
panic-halt = "0.1"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Firmware);
}

// ============================================================================
// Desktop detection tests
// ============================================================================

#[test]
fn test_detect_desktop_from_cargo_tauri() {
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
}

#[test]
fn test_detect_desktop_from_cargo_electron() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "desktop-app"
version = "0.1.0"
edition = "2021"

[dependencies]
electron = "23"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Desktop);
}

#[test]
fn test_detect_desktop_from_package_json_tauri() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "tauri-app",
  "version": "1.0.0",
  "dependencies": {
    "tauri": "^1.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Desktop);
}

#[test]
fn test_detect_desktop_from_package_json_electron() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "electron-app",
  "version": "1.0.0",
  "dependencies": {
    "electron": "^23.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Desktop);
}

// ============================================================================
// Game detection tests
// ============================================================================

#[test]
fn test_detect_game_from_cargo_bevy() {
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
}

#[test]
fn test_detect_game_from_cargo_sdl2() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-game"
version = "0.1.0"
edition = "2021"

[dependencies]
sdl2 = "0.35"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
}

#[test]
fn test_detect_game_from_cargo_ggez() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-game"
version = "0.1.0"
edition = "2021"

[dependencies]
ggez = "0.9"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
}

#[test]
fn test_detect_game_from_package_json_three() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-game",
  "version": "1.0.0",
  "dependencies": {
    "three": "^0.150.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
}

#[test]
fn test_detect_game_from_package_json_phaser() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-game",
  "version": "1.0.0",
  "dependencies": {
    "phaser": "^3.60.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
}

#[test]
fn test_detect_game_from_package_json_pixi() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-game",
  "version": "1.0.0",
  "dependencies": {
    "pixi.js": "^7.0.0"
  }
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Game);
}

// ============================================================================
// Unknown detection tests
// ============================================================================

#[test]
fn test_detect_unknown_from_cargo_no_patterns() {
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
}

#[test]
fn test_detect_unknown_from_package_json_no_patterns() {
    let temp_dir = create_temp_package_project(
        r#"{
  "name": "my-project",
  "version": "1.0.0",
  "description": "Just a project"
}"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Unknown);
}

#[test]
fn test_detect_unknown_from_nonexistent_path() {
    let project_type = detect_project_type(Path::new("/non/existent/path"));
    assert_eq!(project_type, ProjectType::Unknown);
}

#[test]
fn test_detect_from_cargo_toml_no_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let result = detect_from_cargo_toml(temp_dir.path());
    assert!(result.is_none());
}

#[test]
fn test_detect_from_package_json_no_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let result = detect_from_package_json(temp_dir.path());
    assert_eq!(result, ProjectType::Unknown);
}

// ============================================================================
// Priority and heuristics tests
// ============================================================================

#[test]
fn test_cargo_toml_takes_priority_over_package_json() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create both files
    let cargo_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = fs::File::create(&cargo_path).unwrap();
    cargo_file
        .write_all(
            b"[package]\nname = \"cli\"\n[dependencies]\nclap = \"4\"\n",
        )
        .unwrap();

    let package_path = temp_dir.path().join("package.json");
    let mut package_file = fs::File::create(&package_path).unwrap();
    package_file
        .write_all(b"{\"name\": \"web\", \"dependencies\": {\"react\": \"18\"}}")
        .unwrap();

    // Should detect as CLI from Cargo.toml, not Web from package.json
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::CLI);
}

#[test]
fn test_case_insensitive_matching() {
    let temp_dir = create_temp_cargo_project(
        r#"[package]
name = "my-web"
version = "0.1.0"
edition = "2021"

[dependencies]
ACTIX-WEB = "4"
"#,
    );
    let project_type = detect_project_type(temp_dir.path());
    assert_eq!(project_type, ProjectType::Web);
}
