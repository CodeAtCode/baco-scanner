//! Project type detection module.
//!
//! Detects project type from Cargo.toml/package.json using dependency heuristics.
//! Supports: CLI, Web, Library, Embedded, Firmware, Desktop, Game, Unknown.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// All project type categories
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum ProjectType {
    #[default]
    Unknown,
    CLI,
    Web,
    Library,
    Embedded,
    Firmware,
    Desktop,
    Game,
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectType::CLI => write!(f, "cli"),
            ProjectType::Web => write!(f, "web"),
            ProjectType::Library => write!(f, "library"),
            ProjectType::Embedded => write!(f, "embedded"),
            ProjectType::Firmware => write!(f, "firmware"),
            ProjectType::Desktop => write!(f, "desktop"),
            ProjectType::Game => write!(f, "game"),
            ProjectType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Detect project type from a given path.
///
/// Uses dependency heuristics from Cargo.toml or package.json.
/// Returns Unknown gracefully when detection fails.
pub fn detect_project_type(path: &Path) -> ProjectType {
    // Try Cargo.toml first (Rust projects)
    if let Some(project_type) = detect_from_cargo_toml(path) {
        return project_type;
    }

    // Fall back to package.json (Node.js projects)
    detect_from_package_json(path)
}

/// Detect project type from Cargo.toml
pub fn detect_from_cargo_toml(path: &Path) -> Option<ProjectType> {
    let cargo_path = path.join("Cargo.toml");
    if !cargo_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&cargo_path).ok()?;
    let lowercase = content.to_lowercase();

    // Check for CLI frameworks: clap, structopt, docopt, atty
    if lowercase.contains("clap")
        || lowercase.contains("structopt")
        || lowercase.contains("docopt")
        || lowercase.contains("atty")
    {
        return Some(ProjectType::CLI);
    }

    // Check for web frameworks: actix, axum, rocket, warp, express, next, react
    if lowercase.contains("actix")
        || lowercase.contains("axum")
        || lowercase.contains("rocket")
        || lowercase.contains("warp")
        || lowercase.contains("express")
        || lowercase.contains("next")
        || lowercase.contains("react")
        || lowercase.contains("koa")
        || lowercase.contains("hono")
    {
        return Some(ProjectType::Web);
    }

    // Check for embedded: no_std, cortex-m, xtensa, thumbv
    if lowercase.contains("no_std")
        || lowercase.contains("cortex-m")
        || lowercase.contains("xtensa")
        || lowercase.contains("thumbv")
        || lowercase.contains("rtic")
    {
        return Some(ProjectType::Embedded);
    }

    // Check for firmware: esp32, stm32, teensy, embedded-hal
    if lowercase.contains("esp32")
        || lowercase.contains("esp-idf")
        || lowercase.contains("stm32")
        || lowercase.contains("teensy")
        || lowercase.contains("embedded-hal")
        || lowercase.contains("panic-halt")
    {
        return Some(ProjectType::Firmware);
    }

    // Check for desktop: electron, tauri, iced, egui
    if lowercase.contains("electron")
        || lowercase.contains("tauri")
        || lowercase.contains("iced")
        || lowercase.contains("egui")
        || lowercase.contains("rustdesk")
    {
        return Some(ProjectType::Desktop);
    }

    // Check for game: bevy, gloo, pygame, sdl2, krom
    if lowercase.contains("bevy")
        || lowercase.contains("gloo")
        || lowercase.contains("pygame")
        || lowercase.contains("sdl2")
        || lowercase.contains("krom")
        || lowercase.contains("kiss3d")
        || lowercase.contains("rodio")
        || lowercase.contains("ggez")
    {
        return Some(ProjectType::Game);
    }

    // Default to library if it's a Rust project with explicit lib section
    // Look for [lib] section specifically, not just the word "lib"
    if lowercase.contains("[lib]") {
        return Some(ProjectType::Library);
    }

    // If it's a minimal Rust project without specific patterns, return Unknown
    None
}

/// Detect project type from package.json
pub fn detect_from_package_json(path: &Path) -> ProjectType {
    let package_path = path.join("package.json");
    if !package_path.exists() {
        return ProjectType::Unknown;
    }

    let content = match std::fs::read_to_string(&package_path) {
        Ok(c) => c,
        Err(_) => return ProjectType::Unknown,
    };

    // Check for CLI: bin field, commander, yargs,/cli, meow, inquirer
    if content.contains("\"bin\"")
        || content.contains("\"commander\"")
        || content.contains("\"yargs\"")
        || content.contains("\"/cli\"")
        || content.contains("\"meow\"")
        || content.contains("\"inquirer\"")
        || content.contains("chalk")
        || content.contains("figlet")
    {
        return ProjectType::CLI;
    }

    // Check for web: react, next, vue, svelte, express, nest, nestjs
    if content.contains("\"react\"")
        || content.contains("\"next\"")
        || content.contains("\"vue\"")
        || content.contains("\"svelte\"")
        || content.contains("\"nuxt\"")
        || content.contains("\"sugarss\"")
        || content.contains("express")
        || content.contains("nest")
        || content.contains("nestjs")
        || content.contains("angular")
        || content.contains("remix")
    {
        return ProjectType::Web;
    }

    // Check for embedded: nikoajs, esim, native-audio
    if content.contains("\"nikoajs\"")
        || content.contains("\"esim\"")
        || content.contains("\"native-audio\"")
    {
        return ProjectType::Embedded;
    }

    // Check for firmware: esp-idf, arduino, platformio
    if content.contains("\"esp-idf\"")
        || content.contains("\"arduino\"")
        || content.contains("\"platformio\"")
    {
        return ProjectType::Firmware;
    }

    // Check for desktop: electron, tauri, nativefier
    if content.contains("\"electron\"")
        || content.contains("\"tauri\"")
        || content.contains("\"nativefier\"")
    {
        return ProjectType::Desktop;
    }

    // Check for game: three, babylonjs, phaser, playcanvas, cannon, pixi
    if content.contains("\"three\"")
        || content.contains("\"babylonjs\"")
        || content.contains("\"phaser\"")
        || content.contains("\"playcanvas\"")
        || content.contains("\"cannon\"")
        || content.contains("\"pixi\"")
        || content.contains("pixi.js")
        || content.contains("pixijs")
    {
        return ProjectType::Game;
    }

    // Check for library: has "main" or "types" but no "bin"
    if content.contains("\"main\"") || content.contains("\"types\"") {
        return ProjectType::Library;
    }

    // Return Unknown for projects with no recognizable patterns
    ProjectType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let project_type = detect_project_type(Path::new("/non/existent/path"));
        assert_eq!(project_type, ProjectType::Unknown);
    }

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
}
