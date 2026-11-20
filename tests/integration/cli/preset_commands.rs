//! Integration tests for `baco preset` CLI commands
//!
//! These tests verify:
//! - `baco preset list` shows all available presets with exact count
//! - `baco preset show <name>` displays preset TOML content
//! - `baco preset show <missing>` returns non-zero exit code with error message

use std::process::Command;

#[test]
fn test_preset_list_shows_all_bundled_presets() {
    // Run `baco preset list`
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "preset", "list"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute preset list command");

    // Verify success
    assert!(
        output.status.success(),
        "preset list should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Expected bundled presets from BUILTIN_PRESETS in src/preset.rs
    let expected_presets = [
        "wordpress-core",
        "wordpress-plugin",
        "django",
        "laravel",
        "cpp",
        "php",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    // Verify header is present
    assert!(
        stdout.contains("Available presets:"),
        "Output should contain 'Available presets:' header. Got: {}",
        stdout
    );

    // Verify each preset appears with exact formatting "  - <name>"
    for preset in &expected_presets {
        let expected_line = format!("  - {}", preset);
        assert!(
            stdout.contains(&expected_line),
            "Output should contain '{}'. Got: {}",
            expected_line,
            stdout
        );
    }

    // Verify exact count (9 bundled presets)
    let mut count = 0;
    for preset in &expected_presets {
        let expected_line = format!("  - {}", preset);
        if stdout.contains(&expected_line) {
            count += 1;
        }
    }
    assert_eq!(
        count, 9,
        "Should show exactly 9 bundled presets, found: {}",
        count
    );
}

#[test]
fn test_preset_show_displays_toml_content() {
    // Run `baco preset show php`
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "preset", "show", "php"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute preset show command");

    // Verify success
    assert!(
        output.status.success(),
        "preset show should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify the output contains actual TOML sections from the php preset
    // Read the actual preset file to get the section headers
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let preset_path = format!("{}/presets/php.toml", manifest_dir);
    let preset_content =
        std::fs::read_to_string(&preset_path).expect("Failed to read php.toml preset file");

    // Extract section headers from the preset file (lines starting with [)
    for line in preset_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.starts_with("[#") {
            // This is a section header, verify it appears in output
            assert!(
                stdout.contains(trimmed),
                "Output should contain section '{}'. Got: {}",
                trimmed,
                stdout
            );
        }
    }

    // Verify specific php preset values
    assert!(
        stdout.contains("name = \"php\""),
        "Output should contain preset name. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("languages"),
        "Output should contain languages key. Got: {}",
        stdout
    );
}

#[test]
fn test_preset_show_missing_preset_returns_error() {
    // Run `baco preset show definitely-missing-name-xyz`
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "preset",
            "show",
            "definitely-missing-name-xyz",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute preset show command");

    // Verify NON-ZERO exit code
    let exit_code = output.status.code();
    assert!(
        exit_code.is_some_and(|c| c != 0),
        "preset show with missing name should return non-zero exit code, got: {:?}",
        exit_code
    );

    // Verify error message names the missing preset
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("definitely-missing-name-xyz"),
        "Error message should name the missing preset 'definitely-missing-name-xyz'. Got stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Verify it mentions it's not found/unknown
    assert!(
        combined.contains("not found") || combined.contains("Unknown preset"),
        "Error message should indicate preset not found. Got: {}",
        combined
    );
}

#[test]
fn test_preset_list_count_matches_bundled_presets() {
    // Verify the preset list shows exactly the bundled presets from BUILTIN_PRESETS
    // Note: Not all files in presets/ are bundled (e.g., javascript.toml exists but isn't in BUILTIN_PRESETS)
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "preset", "list"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute preset list command");

    assert!(
        output.status.success(),
        "preset list should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Expected bundled presets from BUILTIN_PRESETS in src/preset.rs
    let bundled_presets = [
        "wordpress-core",
        "wordpress-plugin",
        "django",
        "laravel",
        "cpp",
        "php",
        "litellm",
        "oss-python",
        "oss-monorepo",
    ];

    // Verify each bundled preset appears in the output
    for preset in &bundled_presets {
        let expected_line = format!("  - {}", preset);
        assert!(
            stdout.contains(&expected_line),
            "Bundled preset '{}' should appear in list. Got: {}",
            preset,
            stdout
        );
    }

    // Verify count matches bundled presets (not all files in presets/)
    let mut listed_count = 0;
    for line in stdout.lines() {
        if line.trim().starts_with("- ") {
            listed_count += 1;
        }
    }

    assert_eq!(
        listed_count,
        bundled_presets.len(),
        "Listed preset count ({}) should match bundled presets count ({})",
        listed_count,
        bundled_presets.len()
    );
}
