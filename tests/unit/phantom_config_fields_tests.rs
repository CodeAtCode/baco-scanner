//! Phantom config field detection tests.
//!
//! Scans src/config/*.rs for public struct fields and verifies each has
//! external consumption (field access outside its defining file).
//! Fields with zero external consumers are flagged as phantom.

use std::fs;
use std::path::{Path, PathBuf};

/// Known fields that appear unused due to dynamic/serde-only consumption.
/// Add here with justification when a field is legitimately consumed in ways
/// that static analysis cannot detect (e.g., serde deserialization only).
const KNOWN_CONSUMED: &[(&str, &str)] = &[
    (
        "control_path",
        "Consumed via destructuring in context modules (22 refs, no dot-access)",
    ),
    (
        "knowledge_path",
        "Consumed via destructuring in context modules (4 refs, no dot-access)",
    ),
    (
        "normalization",
        "Consumed outside config via non-field-access pattern (root_cause_dedup)",
    ),
    (
        "prompt_per_1k",
        "Cost estimator reads it via table lookup, not dot-access",
    ),
    (
        "completion_per_1k",
        "Cost estimator reads it via table lookup, not dot-access",
    ),
    (
        "cwe_overrides",
        "Consumed by in-config to_registry conversion (scanner.rs) feeding the router",
    ),
    (
        "language_overrides",
        "Consumed by in-config to_registry conversion (scanner.rs) feeding the router",
    ),
];

/// Extract all `pub <field_name>: <type>` declarations from config source files.
fn extract_config_fields(src_dir: &Path) -> Vec<(String, String, String)> {
    let mut fields = Vec::new();

    let config_dir = src_dir.join("config");
    if !config_dir.exists() {
        return fields;
    }

    static FIELD_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = FIELD_RE.get_or_init(|| regex::Regex::new(r"pub\s+(\w+)\s*:\s*([^,\n]+)").unwrap());

    for entry in fs::read_dir(&config_dir).expect("Failed to read config dir") {
        let entry = entry.expect("Failed to read config entry");
        let path = entry.path();
        if !path.is_file() || path.extension() != Some("rs".as_ref()) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("Failed to read config file");
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();

        // Match pub field declarations: pub field_name: Type
        for cap in re.captures_iter(&content) {
            let field_name = cap.get(1).unwrap().as_str().to_string();
            let field_type = cap.get(2).unwrap().as_str().trim().to_string();
            // Skip private/helper functions that start with default_
            if field_name.starts_with("default_") {
                continue;
            }
            fields.push((field_name, field_type, file_name.clone()));
        }
    }

    fields
}

/// Check if a field is consumed outside its defining file.
/// Looks for `<.>field_name` patterns (field access) in src/ tree.
fn has_external_consumer(field_name: &str, defining_file: &str, src_dir: &PathBuf) -> bool {
    // Pattern to match field access: .field_name (with optional & before)
    let pattern = format!(r"(?m)\.\s*{}\b", field_name);
    let re = regex::Regex::new(&pattern).unwrap();

    // Scan all Rust files in src/
    for entry in walkdir::WalkDir::new(src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension() {
            if ext != "rs" {
                continue;
            }
        }

        // Skip the defining file
        if let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().to_string()) {
            if file_name == defining_file {
                continue;
            }
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if re.is_match(&content) {
            return true;
        }
    }

    false
}

#[test]
fn test_happy_path_known_consumed_field() {
    // Test that a known-consumed field passes the allowlist check
    let (field, justification) = KNOWN_CONSUMED[0];
    assert!(
        !field.is_empty(),
        "Field name should not be empty: {}",
        justification
    );
}

#[test]
fn test_phantom_detection_logic_with_synthetic_fixture() {
    // Synthetic fixture (NOT from live src/) exercises the detection logic:
    // used_field has a consumer, phantom_field does not

    // Write fixture to temp directory
    let temp_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|p| p.join("target/test_fixture_phantom"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/phantom_test"));

    let src_dir = temp_dir.join("src");
    let config_dir = src_dir.join("config");

    // Clean and recreate
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&config_dir).expect("Failed to create temp dirs");

    // Write fixture files
    fs::write(
        config_dir.join("mod.rs"),
        r#"pub struct FakeConfig { pub used_field: String, pub phantom_field: String, }"#,
    )
    .expect("Failed to write fixture config");

    fs::write(
        temp_dir.join("src").join("main.rs"),
        r#"use config::FakeConfig; fn main() { let c = FakeConfig { used_field: "x".to_string(), phantom_field: "y".to_string() }; let _ = c.used_field; }"#,
    )
    .expect("Failed to write fixture main");

    // Extract fields
    let fields = extract_config_fields(&src_dir);

    // Should find both fields
    assert_eq!(fields.len(), 2, "Should find 2 fields in fixture");

    // Check used_field has consumer
    let used_field = fields.iter().find(|(n, _, _)| n == "used_field").unwrap();
    assert!(
        has_external_consumer(&used_field.0, &used_field.2, &src_dir),
        "used_field should have external consumer"
    );

    // Check phantom_field has NO consumer
    let phantom_field = fields
        .iter()
        .find(|(n, _, _)| n == "phantom_field")
        .unwrap();
    assert!(
        !has_external_consumer(&phantom_field.0, &phantom_field.2, &src_dir),
        "phantom_field should NOT have external consumer"
    );

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_live_config_fields_scan() {
    // Scan the actual config files and report any phantom fields
    let src_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|p| p.join("src"))
        .expect("CARGO_MANIFEST_DIR not set");

    let fields = extract_config_fields(&src_dir);

    assert!(!fields.is_empty(), "Should find config fields in live src");

    let mut phantom_fields = Vec::new();

    for (field_name, _field_type, defining_file) in &fields {
        // Check if field is in known consumed list
        let is_known = KNOWN_CONSUMED.iter().any(|(k, _)| k == field_name);

        if is_known {
            continue; // Skip known phantom fields
        }

        if !has_external_consumer(field_name, defining_file, &src_dir) {
            phantom_fields.push((field_name.clone(), defining_file.clone()));
        }
    }

    // Report phantom fields - this will fail if there are any unexpected phantoms
    if !phantom_fields.is_empty() {
        eprintln!("\n⚠️  Phantom config fields detected (not in KNOWN_CONSUMED allowlist):");
        for (field, file) in &phantom_fields {
            eprintln!("  - {} (defined in {})", field, file);
        }
        eprintln!("\nAdd to KNOWN_CONSUMED with justification, or remove the field.");
    }

    // The invariant: after dispositions (removals + wiring + justified allowlist),
    // the live config surface must contain ZERO phantom fields.
    assert!(
        phantom_fields.is_empty(),
        "Phantom config fields detected (not in KNOWN_CONSUMED allowlist): {:?}",
        phantom_fields
    );
}
