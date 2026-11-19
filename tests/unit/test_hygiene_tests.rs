//! Test hygiene: detect destructive filesystem calls with relative path literals.
//!
//! This prevents regressions like the incident where tests deleted developers'
//! real scan output by calling `remove_dir_all("baco-output")` with CWD = crate root.

use std::fs;
use std::path::Path;

/// Detector for destructive or creating filesystem calls with relative path literals.
///
/// Returns offending lines (line number 1-indexed) where a call like
/// `remove_dir_all("relative/path")` appears with a relative string literal argument.
///
/// Allowed patterns (not flagged):
/// - Absolute path literals (`/tmp/...`, `C:\\...`)
/// - Variables (not string literals)
/// - `temp_dir.path()` or `TempDir` expressions
/// - `env!("CARGO_MANIFEST_DIR")` or `env!("CARGO_PKG_NAME")` etc.
pub fn detect_relative_fs_calls(source: &str) -> Vec<(usize, String)> {
    // Only the form `name("<literal>", ...)` counts: a string literal passed
    // directly as the first argument. A variable (`&subdir`), a temp path, or an
    // absolute literal is not a CWD-relative literal and must not be reported.
    // Each callee appears once, so a single call cannot be counted twice.
    let callees = [
        "remove_dir_all",
        "remove_file",
        "create_dir_all",
        "write",
        "File::create",
    ];

    let mut offenders: Vec<(usize, String)> = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }

        let mut flagged = false;
        for callee in callees {
            let needle = format!("{callee}(\"");
            let mut from = 0;
            while let Some(pos) = line[from..].find(&needle) {
                let call_start = from + pos;
                from = call_start + needle.len();

                // `write("` must not be the tail of a longer identifier such as
                // `overwrite("`.
                let preceded_by_ident = line[..call_start]
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if preceded_by_ident {
                    continue;
                }

                let rest = &line[from..];
                let literal = &rest[..rest.find('"').unwrap_or(rest.len())];
                let is_absolute = literal.starts_with('/') || literal.contains(":\\");
                if !literal.is_empty() && !is_absolute {
                    offenders.push((idx + 1, line.to_string()));
                    flagged = true;
                    break;
                }
            }
            if flagged {
                break;
            }
        }
    }

    offenders
}

/// Walk all .rs files under tests/ and run the detector.
/// Returns (files_scanned, offenders) where offenders is a Vec of (file_path, line_num, line).
fn scan_all_test_files() -> (usize, Vec<(String, usize, String)>) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let tests_dir = Path::new(manifest_dir).join("tests");

    let mut files_scanned = 0;
    let mut all_offenders = Vec::new();

    // Allowlist: files with legitimate relative path usage
    let allowlist: &[&str] = &[
        // doctor_tests.rs: test_check_output_dir_writable_none_uses_default intentionally
        // touches CWD to exercise the None default, guarded by pre_existing check.
        "tests/unit/doctor_tests.rs",
        // This file holds the offending patterns as string fixtures for the
        // detector's own teeth tests.
        "tests/unit/test_hygiene_tests.rs",
    ];

    fn walk_dir(
        dir: &Path,
        files_scanned: &mut usize,
        all_offenders: &mut Vec<(String, usize, String)>,
        allowlist: &[&str],
    ) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_dir(&path, files_scanned, all_offenders, allowlist);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // Check allowlist
                let relative_path = path
                    .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                    .unwrap_or(&path);
                let relative_str = relative_path.to_string_lossy();

                if allowlist.contains(&relative_str.as_ref()) {
                    continue;
                }

                *files_scanned += 1;

                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let offenders = detect_relative_fs_calls(&content);
                for (line_num, line) in offenders {
                    all_offenders.push((relative_str.to_string(), line_num, line));
                }
            }
        }
    }

    walk_dir(
        &tests_dir,
        &mut files_scanned,
        &mut all_offenders,
        allowlist,
    );
    (files_scanned, all_offenders)
}

#[test]
fn test_hygiene_no_relative_paths_in_tests() {
    let (files_scanned, offenders) = scan_all_test_files();

    // Must scan at least 30 files to ensure the walk is not broken
    assert!(
        files_scanned >= 30,
        "Expected at least 30 test files, scanned {}",
        files_scanned
    );

    // Assert no unguarded offenders found
    assert!(
        offenders.is_empty(),
        "Found {} relative path filesystem calls in test files:\n{}",
        offenders.len(),
        offenders
            .iter()
            .map(|(file, line_num, line)| format!("  {}: {}: {}", file, line_num, line.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ============================================================================
// Teeth: unit tests for the detector itself
// ============================================================================

#[test]
fn test_detector_flags_relative_remove_dir_all() {
    let source = r#"
fn test_something() {
    std::fs::remove_dir_all("baco-output");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 1, "Should flag relative remove_dir_all");
    assert!(offenders[0].1.contains("remove_dir_all"));
}

#[test]
fn test_detector_allows_absolute_path() {
    let source = r#"
fn test_something() {
    std::fs::remove_dir_all("/tmp/baco-output");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 0, "Should not flag absolute path");
}

#[test]
fn test_detector_allows_tempdir_path() {
    let source = r#"
fn test_something() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::remove_dir_all(temp_dir.path());
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 0, "Should not flag temp_dir.path()");
}

#[test]
fn test_detector_allows_variable() {
    let source = r#"
fn test_something() {
    let output_path = "baco-output";
    std::fs::remove_dir_all(&output_path);
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 0, "Should not flag variable reference");
}

#[test]
fn test_detector_flags_relative_remove_file() {
    let source = r#"
fn test_something() {
    std::fs::remove_file("temp_file.txt");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 1, "Should flag relative remove_file");
}

#[test]
fn test_detector_flags_relative_create_dir_all() {
    let source = r#"
fn test_something() {
    std::fs::create_dir_all("output/dir");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 1, "Should flag relative create_dir_all");
}

#[test]
fn test_detector_flags_relative_fs_write() {
    let source = r#"
fn test_something() {
    std::fs::write("output.txt", "content");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 1, "Should flag relative fs::write");
}

#[test]
fn test_detector_flags_relative_file_create() {
    let source = r#"
fn test_something() {
    use std::fs::File;
    let _ = File::create("output.txt");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 1, "Should flag relative File::create");
}

#[test]
fn test_detector_allows_env_manifest_dir() {
    let source = r#"
fn test_something() {
    let path = env!("CARGO_MANIFEST_DIR");
    std::fs::write(&path, "content");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(
        offenders.len(),
        0,
        "Should not flag env!(CARGO_MANIFEST_DIR)"
    );
}

#[test]
fn test_detector_allows_short_absolute() {
    let source = r#"
fn test_something() {
    std::fs::remove_dir_all("/tmp/test");
}
"#;
    let offenders = detect_relative_fs_calls(source);
    assert_eq!(offenders.len(), 0, "Should not flag Unix absolute path");
}
