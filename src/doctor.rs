//! Pre-flight check suite for baco scanner.
//!
//! Validates configuration, dependencies, and environment before running a scan.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of a single health check
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Name of the check
    pub name: String,
    /// Status of the check
    pub status: CheckStatus,
    /// Detailed message about the check result
    pub detail: String,
}

/// Status of a health check
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Check passed
    Ok,
    /// Check passed with warnings
    Warn,
    /// Check failed (hard failure)
    Fail,
}

/// Results from the full doctor check suite
#[derive(Debug, Clone, Serialize)]
pub struct DoctorResults {
    /// Individual check results
    pub checks: Vec<CheckResult>,
    /// Overall health status
    pub overall_status: CheckStatus,
}

impl DoctorResults {
    /// Create new empty results
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            overall_status: CheckStatus::Ok,
        }
    }

    /// Add a check result and update overall status
    pub fn add(&mut self, result: CheckResult) {
        // Update overall status based on this check
        match (&self.overall_status, &result.status) {
            (_, CheckStatus::Fail) => self.overall_status = CheckStatus::Fail,
            (CheckStatus::Ok, CheckStatus::Warn) => self.overall_status = CheckStatus::Warn,
            _ => {} // Keep existing status if it's already worse
        }
        self.checks.push(result);
    }

    /// Return true if all checks passed
    pub fn all_ok(&self) -> bool {
        self.overall_status == CheckStatus::Ok
    }

    /// Return exit code for this result
    pub fn exit_code(&self) -> i32 {
        match self.overall_status {
            CheckStatus::Ok => 0,
            CheckStatus::Warn => 0, // Warnings don't cause non-zero exit
            CheckStatus::Fail => 1,
        }
    }
}

impl Default for DoctorResults {
    fn default() -> Self {
        Self::new()
    }
}

/// Run all health checks
pub fn run_doctor_checks(config_path: Option<&Path>, output_dir: Option<&Path>) -> DoctorResults {
    let mut results = DoctorResults::new();

    // Check 1: Config file parsing
    results.add(check_config_parsing(config_path));

    // Check 2: Preset references resolve
    results.add(check_preset_references(config_path));

    // Check 3: Per-phase LLM slot completeness
    results.add(check_llm_phases(config_path));

    // Check 4: Semgrep on PATH
    results.add(check_semgrep());

    // Check 5: Python3 on PATH
    results.add(check_python3());

    // Check 6: Joern (only if CPG enabled in config)
    results.add(check_joern(config_path));

    // Check 7: Output directory writable
    let output_path = output_dir
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from("baco-output")));
    results.add(check_output_dir_writable(output_path.as_deref()));

    // Check 8: Disk space
    results.add(check_disk_space(output_path.as_deref()));

    results
}

/// Check if config file parses correctly
fn check_config_parsing(config_path: Option<&Path>) -> CheckResult {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            // Default path discovery: check baco.toml first, then config.toml
            let baco_toml = PathBuf::from("baco.toml");
            let config_toml = PathBuf::from("config.toml");

            if baco_toml.exists() {
                baco_toml
            } else if config_toml.exists() {
                config_toml
            } else {
                return CheckResult {
                    name: "config_parse".to_string(),
                    status: CheckStatus::Fail,
                    detail: "No config file found (tried baco.toml, config.toml)".to_string(),
                };
            }
        }
    };

    if !path.exists() {
        return CheckResult {
            name: "config_parse".to_string(),
            status: CheckStatus::Fail,
            detail: format!("Config file not found: {}", path.display()),
        };
    }

    match crate::config::ScannerConfig::from_file(path.to_str().unwrap_or("")) {
        Ok(_) => CheckResult {
            name: "config_parse".to_string(),
            status: CheckStatus::Ok,
            detail: format!("Config file parses successfully: {}", path.display()),
        },
        Err(e) => CheckResult {
            name: "config_parse".to_string(),
            status: CheckStatus::Fail,
            detail: format!("Config parse error: {}", e),
        },
    }
}

/// Check if preset references in config resolve
fn check_preset_references(config_path: Option<&Path>) -> CheckResult {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            return CheckResult {
                name: "preset_resolve".to_string(),
                status: CheckStatus::Ok,
                detail: "No config path provided, skipping preset check".to_string(),
            }
        }
    };

    if !path.exists() {
        return CheckResult {
            name: "preset_resolve".to_string(),
            status: CheckStatus::Ok,
            detail: "Config file not found, skipping preset check".to_string(),
        };
    }

    // Read the config as raw TOML to check for preset references
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return CheckResult {
                name: "preset_resolve".to_string(),
                status: CheckStatus::Warn,
                detail: format!("Could not read config for preset check: {}", e),
            }
        }
    };

    // Look for preset = "..." patterns in the TOML
    let preset_pattern = regex::Regex::new(r#"preset\s*=\s*["']([^"']+)["']"#).unwrap();

    let mut found_presets = Vec::new();
    for cap in preset_pattern.captures_iter(&content) {
        if let Some(preset_name) = cap.get(1) {
            found_presets.push(preset_name.as_str().to_string());
        }
    }

    if found_presets.is_empty() {
        return CheckResult {
            name: "preset_resolve".to_string(),
            status: CheckStatus::Ok,
            detail: "No preset references found in config".to_string(),
        };
    }

    // Check if each referenced preset exists
    let mut invalid_presets = Vec::new();
    for preset_name in &found_presets {
        // Check bundled presets
        let bundled_path = std::env::var("CARGO_MANIFEST_DIR")
            .map(|m| {
                PathBuf::from(m)
                    .join("presets")
                    .join(format!("{}.toml", preset_name))
            })
            .unwrap_or_else(|_| PathBuf::from(format!("presets/{}.toml", preset_name)));

        let user_path = dirs::config_dir()
            .map(|d| {
                d.join("baco")
                    .join("presets")
                    .join(format!("{}.toml", preset_name))
            })
            .unwrap_or_else(|| {
                PathBuf::from(format!("~/.config/baco/presets/{}.toml", preset_name))
            });

        if !bundled_path.exists() && !user_path.exists() {
            invalid_presets.push(preset_name.clone());
        }
    }

    if invalid_presets.is_empty() {
        CheckResult {
            name: "preset_resolve".to_string(),
            status: CheckStatus::Ok,
            detail: format!(
                "All {} preset(s) resolved successfully",
                found_presets.len()
            ),
        }
    } else {
        CheckResult {
            name: "preset_resolve".to_string(),
            status: CheckStatus::Fail,
            detail: format!("Missing preset(s): {}", invalid_presets.join(", ")),
        }
    }
}

/// Check per-phase LLM slot completeness
fn check_llm_phases(config_path: Option<&Path>) -> CheckResult {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            return CheckResult {
                name: "llm_phases".to_string(),
                status: CheckStatus::Ok,
                detail: "No config path provided, skipping LLM phase check".to_string(),
            }
        }
    };

    if !path.exists() {
        return CheckResult {
            name: "llm_phases".to_string(),
            status: CheckStatus::Ok,
            detail: "Config file not found, skipping LLM phase check".to_string(),
        };
    }

    let config = match crate::config::ScannerConfig::from_file(path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => {
            return CheckResult {
                name: "llm_phases".to_string(),
                status: CheckStatus::Ok,
                detail: "Config could not be parsed, skipping LLM phase check".to_string(),
            }
        }
    };

    let phases = &config.llm.phases;
    let mut missing_config = Vec::new();

    // Check each phase by name
    check_phase_config("discovery", &phases.discovery, &mut missing_config);
    check_phase_config("verification", &phases.verification, &mut missing_config);
    check_phase_config("aggregation", &phases.aggregation, &mut missing_config);
    check_phase_config(
        "static_analysis",
        &phases.static_analysis,
        &mut missing_config,
    );
    check_phase_config(
        "security_agent_verification",
        &phases.security_agent_verification,
        &mut missing_config,
    );
    check_phase_config(
        "threat_modeling",
        &phases.threat_modeling,
        &mut missing_config,
    );

    if missing_config.is_empty() {
        CheckResult {
            name: "llm_phases".to_string(),
            status: CheckStatus::Ok,
            detail: "All enabled LLM phases have complete configuration".to_string(),
        }
    } else {
        CheckResult {
            name: "llm_phases".to_string(),
            status: CheckStatus::Warn,
            detail: format!(
                "Missing LLM config for phase(s): {}",
                missing_config.join(", ")
            ),
        }
    }
}

fn check_phase_config(
    name: &str,
    phase: &crate::config::LlmPhaseConfig,
    missing: &mut Vec<String>,
) {
    // If api_key is set, the phase is enabled and needs full config
    if phase.api_key.as_ref().is_some_and(|k| !k.is_empty()) {
        let mut needs = Vec::new();
        if phase.base_url.is_empty() {
            needs.push("base_url");
        }
        if phase.get_models().is_empty() {
            needs.push("model/models");
        }
        if !needs.is_empty() {
            missing.push(format!("{} (missing: {})", name, needs.join(", ")));
        }
    }
}

/// Check if semgrep is on PATH
fn check_semgrep() -> CheckResult {
    match which::which("semgrep") {
        Ok(path) => {
            // Get version
            let version = Command::new(&path)
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            CheckResult {
                name: "semgrep".to_string(),
                status: CheckStatus::Ok,
                detail: format!("semgrep found at {} (version: {})", path.display(), version),
            }
        }
        Err(_) => CheckResult {
            name: "semgrep".to_string(),
            status: CheckStatus::Fail,
            detail: "semgrep not found on PATH. Install with: pip install semgrep OR brew install semgrep".to_string(),
        },
    }
}

/// Check if python3 is on PATH
fn check_python3() -> CheckResult {
    match which::which("python3") {
        Ok(path) => {
            let version = Command::new(&path)
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            CheckResult {
                name: "python3".to_string(),
                status: CheckStatus::Ok,
                detail: format!("python3 found at {} ({})", path.display(), version),
            }
        }
        Err(_) => CheckResult {
            name: "python3".to_string(),
            status: CheckStatus::Fail,
            detail: "python3 not found on PATH. Install from https://www.python.org/downloads/"
                .to_string(),
        },
    }
}

/// Check if Joern is available (only if CPG is enabled in config)
fn check_joern(config_path: Option<&Path>) -> CheckResult {
    // First check if CPG is enabled in config
    let cpg_enabled = config_path
        .and_then(|p| {
            crate::config::ScannerConfig::from_file(p.to_str().unwrap_or(""))
                .ok()
                .map(|c| c.cpg.enabled)
        })
        .unwrap_or(false);

    if !cpg_enabled {
        return CheckResult {
            name: "joern".to_string(),
            status: CheckStatus::Ok,
            detail: "Joern check skipped (CPG not enabled in config)".to_string(),
        };
    }

    // CPG is enabled, check for Joern
    match which::which("joern") {
        Ok(path) => CheckResult {
            name: "joern".to_string(),
            status: CheckStatus::Ok,
            detail: format!("joern found at {}", path.display()),
        },
        Err(_) => CheckResult {
            name: "joern".to_string(),
            status: CheckStatus::Warn,
            detail: "Joern not found on PATH (required for CPG analysis). Install from https://github.com/joernio/joern".to_string(),
        },
    }
}

/// Check if output directory is writable
fn check_output_dir_writable(output_dir: Option<&Path>) -> CheckResult {
    let path = match output_dir {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("baco-output"),
    };

    // Create if doesn't exist
    if !path.exists() {
        match std::fs::create_dir_all(&path) {
            Ok(_) => CheckResult {
                name: "output_dir".to_string(),
                status: CheckStatus::Ok,
                detail: format!("Output directory created: {}", path.display()),
            },
            Err(e) => CheckResult {
                name: "output_dir".to_string(),
                status: CheckStatus::Fail,
                detail: format!(
                    "Failed to create output directory {}: {}",
                    path.display(),
                    e
                ),
            },
        }
    } else if !path.is_dir() {
        CheckResult {
            name: "output_dir".to_string(),
            status: CheckStatus::Fail,
            detail: format!("{} exists but is not a directory", path.display()),
        }
    } else {
        // Test write permission
        let test_file = path.join(".write_test");
        match std::fs::write(&test_file, "") {
            Ok(_) => {
                let _ = std::fs::remove_file(&test_file);
                CheckResult {
                    name: "output_dir".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!("Output directory writable: {}", path.display()),
                }
            }
            Err(e) => CheckResult {
                name: "output_dir".to_string(),
                status: CheckStatus::Fail,
                detail: format!("Output directory not writable {}: {}", path.display(), e),
            },
        }
    }
}

/// Check disk space on output filesystem
fn check_disk_space(output_dir: Option<&Path>) -> CheckResult {
    use std::fs;

    let path = match output_dir {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("."),
    };

    // Get available space
    let _available_bytes: Option<u64> = match fs::metadata(&path) {
        Ok(_) => {
            // Try to get disk space using df on Unix or similar
            #[cfg(unix)]
            {
                // For a more accurate check, we could use the "disk" crate or call df
                // For now, let's just report success and note the limitation
                None // Skip the actual check on Unix without external deps
            }
            #[cfg(not(unix))]
            {
                None
            }
        }
        Err(_) => None,
    };

    // For now, we'll do a simple check using df on Unix
    #[cfg(unix)]
    {
        match Command::new("df").arg("-k").arg(&path).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = stdout.lines().collect();
                if lines.len() >= 2 {
                    // Parse the df output
                    // Format: Filesystem 1K-blocks Used Available Use% Mounted
                    let parts: Vec<&str> = lines[1].split_whitespace().collect();
                    if parts.len() > 3 {
                        if let Ok(available_kb) = parts[3].parse::<u64>() {
                            let available_gb = available_kb as f64 / 1024.0 / 1024.0;
                            if available_gb < 1.0 {
                                return CheckResult {
                                    name: "disk_space".to_string(),
                                    status: CheckStatus::Warn,
                                    detail: format!(
                                        "Low disk space: {:.2} GB available on {}",
                                        available_gb,
                                        path.display()
                                    ),
                                };
                            }
                        }
                    }
                }
                CheckResult {
                    name: "disk_space".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!("Disk space check passed for {}", path.display()),
                }
            }
            _ => CheckResult {
                name: "disk_space".to_string(),
                status: CheckStatus::Ok,
                detail: "Disk space check skipped (df not available)".to_string(),
            },
        }
    }

    #[cfg(not(unix))]
    {
        CheckResult {
            name: "disk_space".to_string(),
            status: CheckStatus::Ok,
            detail: format!("Disk space check skipped (non-Unix platform)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
