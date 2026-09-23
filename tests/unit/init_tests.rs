//! Unit tests for the `baco init` scaffolding: language detection,
//! preset suggestion, config generation, and overwrite protection.

use baco::config::ScannerConfig;
use baco::init::{
    InitCommand, detect_languages_in_dir, detect_project_markers, generate_config_content,
    run_init, suggest_preset,
};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_detect_languages_cpp() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("main.cpp"), "int main() {}").unwrap();
    fs::write(temp_dir.path().join("utils.h"), "#ifndef UTILS_H").unwrap();

    let languages = detect_languages_in_dir(temp_dir.path());
    assert!(languages.contains("cpp"));
    assert_eq!(languages.len(), 1);
}

#[test]
fn test_detect_languages_mixed() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("app.py"), "print('hello')").unwrap();
    fs::write(temp_dir.path().join("server.js"), "console.log('hi')").unwrap();
    fs::write(temp_dir.path().join("config.rs"), "fn main() {}").unwrap();

    let languages = detect_languages_in_dir(temp_dir.path());
    assert!(languages.contains("python"));
    assert!(languages.contains("javascript"));
    assert!(languages.contains("rust"));
    assert_eq!(languages.len(), 3);
}

#[test]
fn test_detect_project_markers_wordpress() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("wp-content")).unwrap();
    fs::write(temp_dir.path().join("wp-config.php"), "<?php").unwrap();

    let markers = detect_project_markers(temp_dir.path());
    assert!(markers.contains(&"wordpress".to_string()));
}

#[test]
fn test_suggest_preset_wordpress_plugin() {
    let mut languages = HashSet::new();
    languages.insert("php".to_string());
    let markers = vec!["wordpress".to_string()];

    let preset = suggest_preset(&languages, &markers);
    assert_eq!(preset, Some("wordpress-plugin".to_string()));
}

#[test]
fn test_suggest_preset_django() {
    let mut languages = HashSet::new();
    languages.insert("python".to_string());
    let markers = vec!["django".to_string()];

    let preset = suggest_preset(&languages, &markers);
    assert_eq!(preset, Some("django".to_string()));
}

#[test]
fn test_suggest_preset_laravel() {
    let mut languages = HashSet::new();
    languages.insert("php".to_string());
    let markers = vec!["laravel".to_string()];

    let preset = suggest_preset(&languages, &markers);
    assert_eq!(preset, Some("laravel".to_string()));
}

#[test]
fn test_suggest_preset_cpp() {
    let mut languages = HashSet::new();
    languages.insert("cpp".to_string());
    let markers: Vec<String> = vec![];

    let preset = suggest_preset(&languages, &markers);
    assert_eq!(preset, Some("cpp".to_string()));
}

#[test]
fn test_generate_config_content() {
    let languages = vec!["rust".to_string()];
    let content = generate_config_content("test-project", ".", &languages, Some("cpp"));

    assert!(content.contains("[project]"));
    assert!(content.contains("name = \"test-project\""));
    assert!(content.contains("path = \".\""));
    assert!(content.contains("\"rust\""));
    assert!(content.contains("[llm.phases.discovery]"));
    assert!(content.contains("[llm.phases.verification]"));
    assert!(content.contains("[llm.phases.aggregation]"));
    assert!(content.contains("[llm.phases.static_analysis]"));
    assert!(content.contains("[llm.phases.security_agent_verification]"));
    assert!(content.contains("[llm.phases.threat_modeling]"));
    assert!(content.contains("profile = \"core\""));
    assert!(content.contains("Suggested preset: cpp"));
}

#[test]
fn test_run_init_creates_config() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.cpp"), "int main() {}").unwrap();

    let cmd = InitCommand {
        path: temp_dir.path().to_path_buf(),
        force: false,
    };

    let result = run_init(&cmd, true);
    assert!(result.is_ok());

    let config_path = temp_dir.path().join("baco.toml");
    assert!(config_path.exists());

    let content = fs::read_to_string(&config_path).unwrap();
    let config: Result<ScannerConfig, _> = toml::from_str(&content);
    assert!(config.is_ok(), "Generated config should be parseable");

    let config = config.unwrap();
    assert!(config.project.languages.contains(&"cpp".to_string()));
}

#[test]
fn test_run_init_refuses_existing_config() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("baco.toml"), "existing").unwrap();

    let cmd = InitCommand {
        path: temp_dir.path().to_path_buf(),
        force: false,
    };

    let result = run_init(&cmd, true);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("already exists"));
}

#[test]
fn test_run_init_force_overwrites() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("baco.toml"), "existing content").unwrap();
    fs::write(temp_dir.path().join("test.cpp"), "int main() {}").unwrap();

    let cmd = InitCommand {
        path: temp_dir.path().to_path_buf(),
        force: true,
    };

    let result = run_init(&cmd, true);
    assert!(result.is_ok());

    let content = fs::read_to_string(temp_dir.path().join("baco.toml")).unwrap();
    assert!(content.contains("[project]"));
    assert!(!content.contains("existing content"));
}

#[test]
fn test_run_init_nonexistent_dir() {
    let cmd = InitCommand {
        path: PathBuf::from("/nonexistent/path/12345"),
        force: false,
    };

    let result = run_init(&cmd, true);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}
