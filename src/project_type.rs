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
