//! Every configuration file shipped in this repository must deserialize.
//!
//! A phantom key in a shipped config is invisible until someone runs the tool,
//! and the preset suite only guards `presets/`. See the module tests for the
//! exact set and the teeth check.

use std::fs;
use std::path::PathBuf;

/// Test that all shipped config files parse through the production loader.
#[test]
fn test_shipped_configs_deserialize() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut checked_files: Vec<PathBuf> = Vec::new();

    // Canonical root files that MUST exist
    let root_files = vec![
        PathBuf::from(manifest_dir).join("config.example.toml"),
        PathBuf::from(manifest_dir).join("config_test.toml"),
    ];

    for path in &root_files {
        assert!(
            path.exists(),
            "Canonical shipped config missing: {}",
            path.display()
        );
        checked_files.push(path.clone());
    }

    // Optional root file (untracked scratch)
    let libyaml_path = PathBuf::from(manifest_dir).join("config_libyaml.toml");
    if libyaml_path.exists() {
        checked_files.push(libyaml_path);
    }

    // All TOMLs under tests/fixtures/
    let fixtures_dir = PathBuf::from(manifest_dir).join("tests/fixtures");
    if fixtures_dir.exists() {
        let entries = fs::read_dir(&fixtures_dir).expect("Cannot read fixtures dir");
        for entry in entries {
            let entry = entry.expect("Cannot read fixture entry");
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                checked_files.push(path);
            }
        }
    }

    // Assert we have at least the canonical files
    assert!(
        checked_files.len() >= 3,
        "Expected at least 3 shipped configs (2 canonical + optional), found {}",
        checked_files.len()
    );

    // Verify each file through the production loader
    for config_path in &checked_files {
        let result = baco::config::ScannerConfig::from_file(
            config_path.to_str().expect("Config path not valid UTF-8"),
        );

        assert!(
            result.is_ok(),
            "Failed to parse shipped config: {}\nLoader error: {:?}",
            config_path.display(),
            result.unwrap_err()
        );
    }

    println!("Checked {} shipped config file(s)", checked_files.len());
}

/// Teeth test: prove the loader actually rejects phantom keys.
///
/// Note: config_test.toml itself failed this check before it was fixed
/// (it had six phantom keys plus enable_hunt_prompts in the wrong section).
#[test]
fn test_phantom_key_rejection() {
    use std::io::Write;

    // Create a temp directory and a TOML with a known phantom key
    let temp_dir = tempfile::tempdir().expect("Cannot create temp dir");
    let phantom_config_path = temp_dir.path().join("phantom.toml");

    let phantom_toml = r#"
[scanner]
format = "json"  # phantom key - not a valid ScannerConfig field

[engine]
enabled = true
"#;

    let mut file = fs::File::create(&phantom_config_path).expect("Cannot create temp file");
    file.write_all(phantom_toml.as_bytes())
        .expect("Cannot write temp file");

    // Assert that from_file returns an Err
    let result = baco::config::ScannerConfig::from_file(
        phantom_config_path.to_str().expect("Path not valid UTF-8"),
    );

    assert!(
        result.is_err(),
        "Loader should reject config with phantom key 'format' in [scanner] section",
    );

    let err = result.unwrap_err();
    println!("Phantom key correctly rejected with error: {:?}", err);
}
