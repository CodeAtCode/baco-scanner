//! Integration tests for the `baco init` subcommand.

use std::process::Command;
use tempfile::TempDir;

fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Create a temp dir with .cpp files
fn create_cpp_project(temp_dir: &TempDir) {
    std::fs::write(temp_dir.path().join("main.cpp"), "int main() { return 0; }").unwrap();
    std::fs::write(
        temp_dir.path().join("utils.h"),
        "#ifndef UTILS_H\n#define UTILS_H\n#endif",
    )
    .unwrap();
}

/// Create a temp dir with WordPress markers
fn create_wordpress_project(temp_dir: &TempDir) {
    std::fs::create_dir(temp_dir.path().join("wp-content")).unwrap();
    std::fs::write(
        temp_dir.path().join("wp-config.php"),
        "<?php\n// WordPress config\n",
    )
    .unwrap();
    std::fs::write(
        temp_dir.path().join("plugin.php"),
        "<?php\n// WordPress plugin\n",
    )
    .unwrap();
}

/// Create a temp dir with Django markers
fn create_django_project(temp_dir: &TempDir) {
    std::fs::write(
        temp_dir.path().join("manage.py"),
        "#!/usr/bin/env python\nprint('hello')",
    )
    .unwrap();
    std::fs::write(temp_dir.path().join("requirements.txt"), "django>=4.0\n").unwrap();
}

/// Create a temp dir with Laravel markers
fn create_laravel_project(temp_dir: &TempDir) {
    std::fs::write(
        temp_dir.path().join("artisan"),
        "#!/usr/bin/env php\n<?php\n",
    )
    .unwrap();
    std::fs::create_dir(temp_dir.path().join("config")).unwrap();
    std::fs::write(
        temp_dir.path().join("config/app.php"),
        "<?php\nreturn [];\n",
    )
    .unwrap();
}

#[test]
fn test_init_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "init", "--help"])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(output.status.success(), "Init help should succeed");
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(help_text.contains("--force"), "Help should mention --force");
    assert!(
        help_text.contains("PATH"),
        "Help should mention PATH argument"
    );
}

#[test]
fn test_init_cpp_project() {
    let temp_dir = TempDir::new().unwrap();
    create_cpp_project(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Init should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = temp_dir.path().join("baco.toml");
    assert!(config_path.exists(), "baco.toml should be created");

    // Read and parse the config
    let content = std::fs::read_to_string(&config_path).unwrap();

    // Verify it's valid TOML that parses against ScannerConfig
    let config: baco::config::ScannerConfig = toml::from_str(&content)
        .expect("Generated config should be valid TOML parseable by ScannerConfig");

    // Verify languages include cpp
    assert!(
        config.project.languages.contains(&"cpp".to_string()),
        "Config should include cpp language, got: {:?}",
        config.project.languages
    );

    // Verify output mentions cpp preset suggestion
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cpp") && (stdout.contains("preset") || stdout.contains("Preset")),
        "Output should suggest cpp preset: {}",
        stdout
    );
}

#[test]
fn test_init_existing_config_refuses_without_force() {
    let temp_dir = TempDir::new().unwrap();
    create_cpp_project(&temp_dir);

    // Create existing baco.toml
    std::fs::write(temp_dir.path().join("baco.toml"), "existing content").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    // Should fail
    assert!(
        !output.status.success(),
        "Init should fail when config exists without --force"
    );

    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_text.contains("already exists") || output_text.contains("Use --force"),
        "Error should mention existing file and --force: {}",
        output_text
    );

    // File should be unchanged
    let content = std::fs::read_to_string(temp_dir.path().join("baco.toml")).unwrap();
    assert_eq!(content, "existing content");
}

#[test]
fn test_init_force_overwrites() {
    let temp_dir = TempDir::new().unwrap();
    create_cpp_project(&temp_dir);

    // Create existing baco.toml
    std::fs::write(temp_dir.path().join("baco.toml"), "existing content").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            "--force",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(output.status.success(), "Init with --force should succeed");

    let content = std::fs::read_to_string(temp_dir.path().join("baco.toml")).unwrap();
    assert!(
        content.contains("[project]"),
        "Config should be overwritten with new content"
    );
    assert!(!content.contains("existing content"));
}

#[test]
fn test_init_wordpress_suggests_wordpress_plugin_preset() {
    let temp_dir = TempDir::new().unwrap();
    create_wordpress_project(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Init should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wordpress-plugin"),
        "Output should suggest wordpress-plugin preset: {}",
        stdout
    );

    // Verify config is valid
    let config_path = temp_dir.path().join("baco.toml");
    let content = std::fs::read_to_string(&config_path).unwrap();
    let config: baco::config::ScannerConfig =
        toml::from_str(&content).expect("Generated config should be valid TOML");

    assert!(
        config.project.languages.contains(&"php".to_string()),
        "Config should include php language"
    );
}

#[test]
fn test_init_django_suggests_django_preset() {
    let temp_dir = TempDir::new().unwrap();
    create_django_project(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Init should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("django"),
        "Output should suggest django preset: {}",
        stdout
    );
}

#[test]
fn test_init_laravel_suggests_laravel_preset() {
    let temp_dir = TempDir::new().unwrap();
    create_laravel_project(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Init should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("laravel"),
        "Output should suggest laravel preset: {}",
        stdout
    );
}

#[test]
fn test_init_nonexistent_directory_fails() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            "/nonexistent/path/12345",
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "Init should fail for nonexistent directory"
    );

    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_text.contains("does not exist"),
        "Error should mention directory does not exist: {}",
        output_text
    );
}

#[test]
fn test_init_generated_config_has_all_phases() {
    let temp_dir = TempDir::new().unwrap();
    create_cpp_project(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "init",
            temp_dir.path().to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(output.status.success());

    let config_path = temp_dir.path().join("baco.toml");
    let content = std::fs::read_to_string(&config_path).unwrap();

    // Verify all six phase slots are present
    assert!(content.contains("[llm.phases.discovery]"));
    assert!(content.contains("[llm.phases.verification]"));
    assert!(content.contains("[llm.phases.aggregation]"));
    assert!(content.contains("[llm.phases.static_analysis]"));
    assert!(content.contains("[llm.phases.security_agent_verification]"));
    assert!(content.contains("[llm.phases.threat_modeling]"));

    // Verify each phase has commented base_url/models/api_key lines
    assert!(content.contains("base_url"));
    assert!(content.contains("api_key"));
    assert!(content.contains("models"));
}
