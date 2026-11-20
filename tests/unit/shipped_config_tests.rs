//! Every configuration file shipped in this repository must deserialize.
//!
//! A phantom key in a shipped config is invisible until someone runs the tool,
//! and the preset suite only guards `presets/`. See the module tests for the
//! exact set and the teeth check.

use std::fs;
use std::path::PathBuf;

/// Test that every shipped config file parses through the production loader.
///
/// "Shipped" means part of the repository: `config.example.toml` and the
/// fixtures the suite reads. A local scratch config belongs to one machine, is
/// not in the repository, and is validated only when present — requiring it made
/// the suite fail on a clean checkout.
#[test]
fn test_shipped_configs_deserialize() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Ships with the repository, so a clean checkout must have it.
    let mut required: Vec<PathBuf> = vec![root.join("config.example.toml")];

    // Local scratch configs: validated when present, never required.
    let optional: Vec<PathBuf> = vec![
        root.join("config_test.toml"),
        root.join("config_libyaml.toml"),
    ];

    // Every config the test suite reads ships with the suite.
    let fixtures_dir = root.join("tests/fixtures");
    let entries = fs::read_dir(&fixtures_dir).expect("Cannot read tests/fixtures");
    for entry in entries {
        let path = entry.expect("Cannot read fixture entry").path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            required.push(path);
        }
    }

    for path in &required {
        assert!(path.exists(), "Shipped config missing: {}", path.display());
    }

    // The walk must actually have found the fixtures, or this test proves nothing.
    let fixture_count = required
        .iter()
        .filter(|path| path.starts_with(&fixtures_dir))
        .count();
    assert!(
        fixture_count >= 1,
        "No fixture TOMLs found under {}",
        fixtures_dir.display()
    );

    let mut checked = required;
    checked.extend(optional.into_iter().filter(|path| path.exists()));

    for config_path in &checked {
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

    println!("Checked {} config file(s)", checked.len());
}

/// Teeth test: prove the loader actually rejects phantom keys.
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
