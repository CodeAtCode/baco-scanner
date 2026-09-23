//! Tests for doctor.rs - pre-flight health check suite.

use baco::doctor::{
    CheckResult, CheckStatus, DoctorResults, check_disk_space, check_output_dir_writable,
};
use tempfile::TempDir;

#[test]
fn test_check_status_serialization() {
    assert_eq!(serde_json::to_string(&CheckStatus::Ok).unwrap(), "\"ok\"");
    assert_eq!(
        serde_json::to_string(&CheckStatus::Warn).unwrap(),
        "\"warn\""
    );
    assert_eq!(
        serde_json::to_string(&CheckStatus::Fail).unwrap(),
        "\"fail\""
    );
}

#[test]
fn test_doctor_results_exit_code() {
    let mut results = DoctorResults::new();
    assert_eq!(results.exit_code(), 0);

    results.add(CheckResult {
        name: "test".to_string(),
        status: CheckStatus::Warn,
        detail: "warning".to_string(),
    });
    assert_eq!(results.exit_code(), 0); // Warn doesn't cause non-zero

    results.add(CheckResult {
        name: "test2".to_string(),
        status: CheckStatus::Fail,
        detail: "failure".to_string(),
    });
    assert_eq!(results.exit_code(), 1); // Fail causes non-zero
}

#[test]
fn test_output_dir_writable_tempdir() {
    let temp_dir = TempDir::new().unwrap();
    let result = check_output_dir_writable(Some(temp_dir.path()));
    assert_eq!(result.status, CheckStatus::Ok);
    assert!(result.detail.contains("writable"));
}

#[test]
fn test_output_dir_create_if_missing() {
    let temp_dir = TempDir::new().unwrap();
    let new_dir = temp_dir.path().join("new_output");
    assert!(!new_dir.exists());

    let result = check_output_dir_writable(Some(&new_dir));
    assert_eq!(result.status, CheckStatus::Ok);
    assert!(new_dir.exists());
}

#[test]
fn test_run_doctor_checks_minimal_valid_config() {
    // Create a minimal valid config file
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let output_dir = temp_dir.path().join("output");
    let results =
        baco::doctor::run_doctor_checks(Some(config_path.as_path()), Some(output_dir.as_path()));

    // Verify we got check results
    assert!(!results.checks.is_empty());

    // Config parse should succeed
    let config_check = results.checks.iter().find(|c| c.name == "config_parse");
    assert!(config_check.is_some());
    assert_eq!(config_check.unwrap().status, CheckStatus::Ok);
}

#[test]
fn test_run_doctor_checks_missing_api_key() {
    // Create a config with missing api_key in a phase slot
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
# Missing api_key intentionally
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let output_dir = temp_dir.path().join("output");
    let results =
        baco::doctor::run_doctor_checks(Some(config_path.as_path()), Some(output_dir.as_path()));

    // LLM phases check should warn about missing config
    let llm_check = results.checks.iter().find(|c| c.name == "llm_phases");
    assert!(llm_check.is_some());
    let llm_result = llm_check.unwrap();
    assert!(llm_result.detail.contains("discovery"));
}

#[test]
fn test_run_doctor_checks_semgrep_check() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().join("output");

    let results = baco::doctor::run_doctor_checks(None, Some(output_dir.as_path()));

    // Semgrep check should be present
    let semgrep_check = results.checks.iter().find(|c| c.name == "semgrep");
    assert!(semgrep_check.is_some());

    // Result should be either Ok (if semgrep installed) or Fail (if not)
    let semgrep_result = semgrep_check.unwrap();
    assert!(
        semgrep_result.status == CheckStatus::Ok || semgrep_result.status == CheckStatus::Fail,
        "Semgrep check should be Ok or Fail, got {:?}",
        semgrep_result.status
    );
}

#[test]
fn test_run_doctor_checks_python3_check() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().join("output");

    let results = baco::doctor::run_doctor_checks(None, Some(output_dir.as_path()));

    // Python3 check should be present
    let python_check = results.checks.iter().find(|c| c.name == "python3");
    assert!(python_check.is_some());

    // Result should be either Ok (if python3 installed) or Fail (if not)
    let python_result = python_check.unwrap();
    assert!(
        python_result.status == CheckStatus::Ok || python_result.status == CheckStatus::Fail,
        "Python3 check should be Ok or Fail, got {:?}",
        python_result.status
    );
}

#[test]
fn test_run_doctor_checks_output_dir_with_tempdir() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    // Create minimal valid config
    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let output_dir = temp_dir.path().join("output");
    let results =
        baco::doctor::run_doctor_checks(Some(config_path.as_path()), Some(output_dir.as_path()));

    // Output dir check should be present and Ok
    let output_dir_check = results.checks.iter().find(|c| c.name == "output_dir");
    assert!(output_dir_check.is_some());
    assert_eq!(output_dir_check.unwrap().status, CheckStatus::Ok);
}

#[test]
fn test_run_doctor_checks_disk_space_with_tempdir() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    // Create minimal valid config
    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let output_dir = temp_dir.path().join("output");
    let results =
        baco::doctor::run_doctor_checks(Some(config_path.as_path()), Some(output_dir.as_path()));

    // Disk space check should be present
    let disk_check = results.checks.iter().find(|c| c.name == "disk_space");
    assert!(disk_check.is_some());

    // On Unix, should be Ok or Warn; on non-Unix, should be Ok (skipped)
    #[cfg(unix)]
    {
        let disk_result = disk_check.unwrap();
        assert!(
            disk_result.status == CheckStatus::Ok || disk_result.status == CheckStatus::Warn,
            "Disk space check should be Ok or Warn on Unix, got {:?}",
            disk_result.status
        );
    }

    #[cfg(not(unix))]
    {
        assert_eq!(disk_check.unwrap().status, CheckStatus::Ok);
    }
}

#[test]
fn test_check_result_structure() {
    let result = CheckResult {
        name: "test_check".to_string(),
        status: CheckStatus::Ok,
        detail: "Everything looks good".to_string(),
    };

    assert_eq!(result.name, "test_check");
    assert_eq!(result.status, CheckStatus::Ok);
    assert_eq!(result.detail, "Everything looks good");
}
#[tokio::test]
async fn test_llm_reachability_mock_server_ok() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .create();

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");
    let config_content = format!("[llm]\nbase_url = \"{}\"\n", server.url());
    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);
    let check = results
        .checks
        .iter()
        .find(|c| c.name == "llm_reachability")
        .expect("llm_reachability check must run");
    assert_eq!(check.status, baco::doctor::CheckStatus::Ok);
}

#[tokio::test]
async fn test_llm_reachability_refused_warns() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");
    let config_content = "[llm]\nbase_url = \"http://127.0.0.1:1\"\n";
    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);
    let check = results
        .checks
        .iter()
        .find(|c| c.name == "llm_reachability")
        .expect("llm_reachability check must run");
    assert_eq!(check.status, baco::doctor::CheckStatus::Warn);
}
#[test]
fn preset_resolve_unreadable_path_warns() {
    let temp_dir = TempDir::new().unwrap();
    let results = baco::doctor::run_doctor_checks(Some(temp_dir.path()), None);
    let check = results
        .checks
        .iter()
        .find(|c| c.name == "preset_resolve")
        .expect("preset_resolve check must run");
    assert_eq!(check.status, baco::doctor::CheckStatus::Warn);
}

#[test]
fn preset_resolve_unknown_preset_fails() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");
    std::fs::write(
        &config_path,
        "[scanner]\nprofile = \"core\"\npreset = \"nonexistent-preset-xyz-123\"\n",
    )
    .unwrap();
    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);
    let check = results
        .checks
        .iter()
        .find(|c| c.name == "preset_resolve")
        .expect("preset_resolve check must run");
    assert_eq!(check.status, baco::doctor::CheckStatus::Fail);
    assert!(check.detail.contains("nonexistent-preset-xyz-123"));
}
#[test]
fn doctor_checks_without_config_path_skip_ok() {
    let results = baco::doctor::run_doctor_checks(None, None);
    assert!(!results.checks.is_empty());
    for check in &results.checks {
        if check.name == "preset_resolve"
            || check.name == "llm_phases"
            || check.name == "llm_reachability"
        {
            assert_eq!(
                check.status,
                baco::doctor::CheckStatus::Ok,
                "check {} should skip-Ok without config",
                check.name
            );
        }
    }
    // config_parse instead does CWD discovery (baco.toml/config.toml) and
    // fails when nothing is found.
    let config_check = results
        .checks
        .iter()
        .find(|c| c.name == "config_parse")
        .expect("config_parse check must run");
    assert_eq!(config_check.status, baco::doctor::CheckStatus::Fail);
}

// ============================================================================
// Target 1: DoctorResults::all_ok() + Default
// ============================================================================

#[test]
fn test_doctor_results_all_ok_true() {
    let results = DoctorResults::new();
    assert!(results.all_ok());
}

#[test]
fn test_doctor_results_all_ok_false_after_warn() {
    let mut results = DoctorResults::new();
    results.add(CheckResult {
        name: "test".to_string(),
        status: CheckStatus::Warn,
        detail: "warning".to_string(),
    });
    assert!(!results.all_ok());
}

#[test]
fn test_doctor_results_all_ok_false_after_fail() {
    let mut results = DoctorResults::new();
    results.add(CheckResult {
        name: "test".to_string(),
        status: CheckStatus::Fail,
        detail: "failure".to_string(),
    });
    assert!(!results.all_ok());
}

#[test]
fn test_doctor_results_default_all_ok() {
    let results = DoctorResults::default();
    assert!(results.all_ok());
}

#[test]
fn test_doctor_results_default_exit_code_zero() {
    let results = DoctorResults::default();
    assert_eq!(results.exit_code(), 0);
}

// ============================================================================
// Target 2: check_output_dir_writable error branches
// ============================================================================

#[test]
fn test_check_output_dir_writable_parent_is_file() {
    // Create a temp file, then try to create a subdir under it
    let temp_dir = TempDir::new().unwrap();
    let temp_file = temp_dir.path().join("temp_file");
    std::fs::write(&temp_file, "").unwrap();

    let result = check_output_dir_writable(Some(temp_file.join("sub").as_path()));
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains("Failed to create"));
}

#[test]
fn test_check_output_dir_writable_path_is_file() {
    // Create a temp file and pass its path directly
    let temp_dir = TempDir::new().unwrap();
    let temp_file = temp_dir.path().join("temp_file");
    std::fs::write(&temp_file, "").unwrap();

    let result = check_output_dir_writable(Some(temp_file.as_path()));
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains("not a directory"));
}

#[test]
fn test_check_output_dir_writable_none_uses_default() {
    // Call with None - should use "baco-output" in CWD
    let result = check_output_dir_writable(None);
    assert_eq!(result.status, CheckStatus::Ok);

    // Clean up the created directory
    let _ = std::fs::remove_dir_all("baco-output");
}

// ============================================================================
// Target 3: check_disk_space branches
// ============================================================================

#[test]
fn test_check_disk_space_none_uses_current_dir() {
    let result = check_disk_space(None);
    // On Unix, this uses df on "." - should be Ok or Warn depending on disk space
    assert!(
        result.status == CheckStatus::Ok || result.status == CheckStatus::Warn,
        "Disk space check on current dir should be Ok or Warn, got {:?}",
        result.status
    );
}

#[test]
fn test_check_disk_space_nonexistent_path_fallback() {
    let result = check_disk_space(Some(std::path::Path::new("/nonexistent-xyz-abc-123")));
    // On Unix, df fails → fallback arm (Ok + "skipped")
    assert_eq!(result.status, CheckStatus::Ok);
    assert!(result.detail.contains("skipped"));
}

#[test]
fn test_check_disk_space_real_temp_dir() {
    let temp_dir = TempDir::new().unwrap();
    let result = check_disk_space(Some(temp_dir.path()));
    assert_eq!(result.status, CheckStatus::Ok);
}

// ============================================================================
// Target 4: check_preset_references Ok branch
// ============================================================================

#[test]
fn test_check_preset_references_django_ok() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"
preset = "django"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);

    let preset_check = results
        .checks
        .iter()
        .find(|c| c.name == "preset_resolve")
        .expect("preset_resolve check must run");

    assert_eq!(preset_check.status, CheckStatus::Ok);
    assert!(preset_check.detail.contains("resolved successfully"));
}

// ============================================================================
// Target 5: check_llm_phases / check_phase_config missing config
// ============================================================================

#[test]
fn test_check_llm_phases_missing_base_url_and_model() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "x"
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);

    let llm_check = results
        .checks
        .iter()
        .find(|c| c.name == "llm_phases")
        .expect("llm_phases check must run");

    assert_eq!(llm_check.status, CheckStatus::Warn);
    assert!(llm_check.detail.contains("Missing LLM config"));
    assert!(llm_check.detail.contains("discovery"));
}

#[test]
fn test_check_llm_phases_missing_model_only() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "x"
base_url = "http://x"
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);

    let llm_check = results
        .checks
        .iter()
        .find(|c| c.name == "llm_phases")
        .expect("llm_phases check must run");

    assert_eq!(llm_check.status, CheckStatus::Warn);
    assert!(llm_check.detail.contains("model"));
}

// ============================================================================
// Target 6: check_joern cpg-disabled
// ============================================================================

#[test]
fn test_check_joern_cpg_disabled_skipped() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("baco.toml");

    let config_content = r#"
[scanner]
profile = "core"

[llm]
[llm.phases]
[llm.phases.discovery]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.aggregation]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.static_analysis]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.security_agent_verification]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[llm.phases.threat_modeling]
api_key = "test-key"
base_url = "https://test.api/v1"
model = "test-model"

[cpg]
enabled = false
"#;

    std::fs::write(&config_path, config_content).unwrap();

    let results = baco::doctor::run_doctor_checks(Some(config_path.as_path()), None);

    let joern_check = results
        .checks
        .iter()
        .find(|c| c.name == "joern")
        .expect("joern check must run");

    assert_eq!(joern_check.status, CheckStatus::Ok);
    assert!(joern_check.detail.contains("skipped"));
}

#[test]
fn doctor_checks_missing_config_file_skip_ok() {
    let missing = std::path::PathBuf::from("/nonexistent-baco-probe-xyz.toml");
    let results = baco::doctor::run_doctor_checks(Some(missing.as_path()), None);
    let names: Vec<&str> = results.checks.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"config_parse"));
    assert!(names.contains(&"preset_resolve"));
    assert!(names.contains(&"llm_phases"));
}
