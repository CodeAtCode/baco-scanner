//! The coverage gate is a shipped Python script invoked from ci.yml, so it gets
//! the same treatment as production code: these tests run the real script
//! against synthetic lcov data and assert on its exit status and messages.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/coverage_gate.py")
}

struct Output {
    success: bool,
    text: String,
}

fn run_gate(args: &[&str]) -> Output {
    let out = Command::new("python3")
        .arg(script_path())
        .args(args)
        .output()
        .expect("python3 must be installed: the shipped coverage gate needs it");
    Output {
        success: out.status.success(),
        text: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// DA lines 1..=10 hit, 11..=20 missed: 10 of 20 instrumented lines covered.
const DOCTOR_LCOV: &str = "\
TN:
SF:src/doctor.rs
DA:1,1
DA:2,1
DA:3,1
DA:4,1
DA:5,1
DA:6,1
DA:7,1
DA:8,1
DA:9,1
DA:10,1
DA:11,0
DA:12,0
DA:13,0
DA:14,0
DA:15,0
DA:16,0
DA:17,0
DA:18,0
DA:19,0
DA:20,0
end_of_record
";

/// An absolute SF path must canonicalise to the workspace-relative key.
const SCAN_HEALTH_LCOV_ABS: &str = "\
TN:
SF:/tmp/checkout/baco/src/scan_health.rs
DA:1,1
DA:2,1
DA:3,1
DA:4,0
DA:5,0
end_of_record
";

/// A file outside the hot set: never part of a generated baseline.
const COLD_LCOV: &str = "\
TN:
SF:src/main.rs
DA:1,1
DA:2,1
end_of_record
";

fn write_lcov(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("lcov.info");
    fs::write(&path, body).expect("write synthetic lcov");
    path
}

fn write_baseline(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("baseline.json");
    fs::write(&path, body).expect("write synthetic baseline");
    path
}

const BASELINE_AT_FLOOR: &str = r#"{
  "files": {
    "src/doctor.rs": {"lines_hit": 10, "lines_found": 20}
  }
}"#;

/// DA lines 1..=2 hit, 3..=5 missed: exactly at a 2-of-5 floor.
const SCAN_HEALTH_AT_FLOOR_LCOV: &str = "\
TN:
SF:src/scan_health.rs
DA:1,1
DA:2,1
DA:3,0
DA:4,0
DA:5,0
end_of_record
";

#[test]
fn gate_passes_when_coverage_meets_or_exceeds_the_baseline() {
    let dir = TempDir::new().unwrap();
    // doctor.rs sits at its floor (10/20), scan_health.rs at its floor (2/5).
    let lcov = write_lcov(&dir, &format!("{DOCTOR_LCOV}{SCAN_HEALTH_AT_FLOOR_LCOV}"));
    let baseline = write_baseline(
        &dir,
        r#"{
  "files": {
    "src/doctor.rs": {"lines_hit": 10, "lines_found": 20},
    "src/scan_health.rs": {"lines_hit": 2, "lines_found": 5}
  }
}"#,
    );
    let out = run_gate(&[lcov.to_str().unwrap(), baseline.to_str().unwrap()]);
    assert!(
        out.success,
        "each file at its own floor must pass; got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("2 hot files at or above the baseline"),
        "unexpected summary: {}",
        out.text
    );
}

#[test]
fn gate_fails_naming_the_file_when_coverage_drops() {
    let dir = TempDir::new().unwrap();
    let lcov = write_lcov(&dir, DOCTOR_LCOV);
    let baseline = write_baseline(
        &dir,
        r#"{
  "files": {
    "src/doctor.rs": {"lines_hit": 15, "lines_found": 20}
  }
}"#,
    );
    let out = run_gate(&[lcov.to_str().unwrap(), baseline.to_str().unwrap()]);
    assert!(!out.success, "10/20 against a 15/20 floor must fail");
    assert!(
        out.text.contains("src/doctor.rs") && out.text.contains("line coverage fell: 10/20"),
        "the failure must name the file and the numbers; got:\n{}",
        out.text
    );
}

#[test]
fn gate_fails_when_a_baseline_file_is_absent_from_the_report() {
    let dir = TempDir::new().unwrap();
    let lcov = write_lcov(&dir, DOCTOR_LCOV);
    let baseline = write_baseline(
        &dir,
        r#"{
  "files": {
    "src/doctor.rs": {"lines_hit": 10, "lines_found": 20},
    "src/gone.rs": {"lines_hit": 3, "lines_found": 4}
  }
}"#,
    );
    let out = run_gate(&[lcov.to_str().unwrap(), baseline.to_str().unwrap()]);
    assert!(
        !out.success,
        "a renamed or deleted baseline file must fail the gate"
    );
    assert!(
        out.text.contains("src/gone.rs") && out.text.contains("absent from the coverage report"),
        "the failure must say the file is gone; got:\n{}",
        out.text
    );
}

#[test]
fn gate_counts_a_line_hit_in_any_test_binary() {
    let dir = TempDir::new().unwrap();
    // Two records for the same file, as one-record-per-test-binary: lines 1..=10
    // hit in the first, 11..=20 uncovered in the second. The union is 10/20; a
    // non-merging parser would keep only the last record (0/10) and fail.
    let separate = "\
TN:
SF:src/doctor.rs
DA:1,1
DA:2,1
DA:3,1
DA:4,1
DA:5,1
DA:6,1
DA:7,1
DA:8,1
DA:9,1
DA:10,1
end_of_record
TN:
SF:src/doctor.rs
DA:11,0
DA:12,0
DA:13,0
DA:14,0
DA:15,0
DA:16,0
DA:17,0
DA:18,0
DA:19,0
DA:20,0
end_of_record
";
    let lcov = write_lcov(&dir, separate);
    let baseline = write_baseline(&dir, BASELINE_AT_FLOOR);
    let out = run_gate(&[lcov.to_str().unwrap(), baseline.to_str().unwrap()]);
    assert!(
        out.success,
        "a line hit in either binary counts as hit; got:\n{}",
        out.text
    );
}

#[test]
fn write_baseline_records_only_the_hot_files_and_canonical_paths() {
    let dir = TempDir::new().unwrap();
    let lcov = write_lcov(
        &dir,
        &format!("{DOCTOR_LCOV}{SCAN_HEALTH_LCOV_ABS}{COLD_LCOV}"),
    );
    let baseline = dir.path().join("baseline.json");
    let out = run_gate(&[
        "--write-baseline",
        lcov.to_str().unwrap(),
        baseline.to_str().unwrap(),
    ]);
    assert!(
        out.success,
        "write-baseline must succeed; got:\n{}",
        out.text
    );

    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&baseline).unwrap()).unwrap();
    let files = written["files"].as_object().unwrap();
    assert!(
        files.contains_key("src/doctor.rs"),
        "hot files must be recorded: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    assert!(
        files.contains_key("src/scan_health.rs"),
        "an absolute SF path must canonicalise to its workspace-relative key"
    );
    assert!(
        !files.contains_key("/tmp/checkout/baco/src/scan_health.rs"),
        "the raw absolute path must not appear as a key"
    );
    assert!(
        !files.contains_key("src/main.rs"),
        "files outside the hot set must not enter the baseline"
    );
    assert_eq!(files["src/doctor.rs"]["lines_hit"].as_i64(), Some(10));
    assert_eq!(files["src/doctor.rs"]["lines_found"].as_i64(), Some(20));
}
