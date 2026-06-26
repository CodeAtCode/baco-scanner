//! Auto-Patcher Module
//!
//! Generates and validates unified diff patches for vulnerability fixes.
//! Uses StagingArea for safe validation in isolated git worktrees.

use crate::scanner_types::PatchCandidate;
use crate::staging::{PatchValidationResult, StagingArea};
use std::path::PathBuf;
use std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AutoPatchError {
    #[error("Failed to generate patch: {0}")]
    Generation(String),
    #[error("Failed to apply patch: {0}")]
    Apply(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Staging error: {0}")]
    Staging(String),
    #[error("No LLM client configured")]
    NoLlmClient,
}

pub type Result<T> = std::result::Result<T, AutoPatchError>;

pub struct AutoPatcher {
    repo_path: PathBuf,
}

impl AutoPatcher {
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }

    /// Generate a patch for fixing a vulnerability
    ///
    /// In production, this would call the LLM to generate the fix.
    /// The prompt guides the LLM to produce a unified diff.
    pub fn generate_patch(
        &self,
        _vulnerability_description: &str,
        _vulnerable_code: &str,
        file_path: &str,
    ) -> Result<PatchCandidate> {
        // In production, this would call the LLM with a prompt like:
        // let prompt = format!(
        //     "Generate a unified diff to fix the following vulnerability:\n\
        //      Description: {}\n\
        //      File: {}\n\
        //      Vulnerable code:\n\
        //      ```\n\
        //      {}\n\
        //      ```\n\
        //      Provide only the unified diff as output.",
        //     vulnerability_description, file_path, vulnerable_code
        // );

        // For now, generate a placeholder that indicates where the fix would go
        // In production, this would be replaced by actual LLM-generated diff
        let diff = format!(
            "--- a/{}\n\
             +++ b/{}\n\
             @@ -1,10 +1,10 @@\n\
             \n",
            file_path, file_path
        );

        Ok(PatchCandidate::new(&diff, file_path))
    }

    /// Validate a patch by applying it in a staging worktree and running checks
    pub fn validate_patch(&self, candidate: &PatchCandidate) -> Result<PatchValidationResult> {
        let mut staging = StagingArea::create(&self.repo_path)
            .map_err(|e| AutoPatchError::Staging(e.to_string()))?;

        // Apply the patch
        if let Err(e) = staging.apply_patch(&candidate.diff) {
            let _ = staging.rollback();
            return Ok(PatchValidationResult::failure(&format!(
                "Patch application failed: {}",
                e
            )));
        }

        // Validate in staging worktree
        let result = staging.validate();

        // Always cleanup
        let mut staging = staging;
        let _ = staging.cleanup();

        match result {
            Ok(validation) => Ok(validation),
            Err(e) => Ok(PatchValidationResult::failure(&format!(
                "Validation failed: {}",
                e
            ))),
        }
    }

    /// Format a patch report with validation results
    pub fn format_patch_report(
        &self,
        candidate: &PatchCandidate,
        validation: &PatchValidationResult,
    ) -> String {
        let status = if validation.compiles && validation.tests_pass {
            "✅ VALIDATED"
        } else if validation.compiles {
            "⚠️ COMPILES BUT TESTS FAILED"
        } else {
            "❌ FAILED"
        };

        let mut report = format!(
            "Patch Report\n\
             ============\n\
             File: {}\n\
             Status: {}\n\
             \n\
             Diff:\n\
             {}\n",
            candidate.file_path, status, candidate.diff
        );

        if !validation.compiles {
            report.push_str(&format!(
                "Build Errors:\n{}\n",
                validation
                    .error_message
                    .as_deref()
                    .unwrap_or("Unknown error")
            ));
        }

        if validation.warnings > 0 {
            report.push_str(&format!("Warnings: {}\n", validation.warnings));
        }

        if !validation.tests_pass && validation.error_message.is_some() {
            report.push_str(&format!(
                "Test Errors:\n{}\n",
                validation.error_message.as_ref().unwrap_or(&String::new())
            ));
        }

        report
    }

    /// Apply and validate a patch in one step
    pub fn apply_and_validate(
        &self,
        candidate: &mut PatchCandidate,
    ) -> Result<PatchValidationResult> {
        let staging = StagingArea::create(&self.repo_path)
            .map_err(|e| AutoPatchError::Staging(e.to_string()))?;

        if let Err(e) = staging.apply_patch(&candidate.diff) {
            let mut staging = staging;
            let _ = staging.rollback();
            let validation = PatchValidationResult::failure(&format!("Apply failed: {}", e));
            candidate.validation_result = Some(validation.clone().into());
            return Ok(validation);
        }

        let validation = staging
            .validate()
            .map_err(|e| AutoPatchError::Validation(e.to_string()))?;

        let mut staging = staging;
        if validation.compiles && validation.tests_pass {
            staging
                .cleanup()
                .map_err(|e| AutoPatchError::Staging(e.to_string()))?;
            candidate.applied = true;
        } else {
            let _ = staging.rollback();
        }

        candidate.validation_result = Some(validation.clone().into());
        Ok(validation)
    }

    /// Execute batch auto-patching on multiple findings
    pub fn execute_batch(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
        config: &PatchingConfig,
    ) -> Result<Vec<crate::findings::VulnerabilityFinding>> {
        let mut patched_findings = Vec::new();
        let mut patch_count = 0;

        for finding in findings {
            if patch_count >= config.max_auto_patches {
                tracing::info!(
                    "Reached max auto-patches ({}), stopping",
                    config.max_auto_patches
                );
                break;
            }

            // Skip findings without code snippet
            let Some(code_snippet) = &finding.code_snippet else {
                continue;
            };

            // Generate patch
            let patch = self.generate_patch(&finding.title, code_snippet, &finding.file_path)?;

            // Validate patch
            let validation = self.validate_patch(&patch)?;

            if validation.compiles && validation.tests_pass {
                tracing::info!(
                    "Auto-patch validated for finding {} (file: {})",
                    finding.id,
                    finding.file_path
                );
                patched_findings.push(finding.clone());
                patch_count += 1;
            } else {
                tracing::warn!(
                    "Auto-patch validation failed for finding {}: {}",
                    finding.id,
                    validation
                        .error_message
                        .as_deref()
                        .unwrap_or("unknown error")
                );
                // Keep the finding even if patch failed - manual review needed
                patched_findings.push(finding.clone());
            }
        }

        Ok(patched_findings)
    }
}

/// Configuration for auto-patching
#[derive(Debug, Clone)]
pub struct PatchingConfig {
    pub dry_run: bool,
    pub allow_network_access: bool,
    pub max_auto_patches: usize,
    pub staging_prefix: Option<String>,
}

impl Default for PatchingConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            allow_network_access: false,
            max_auto_patches: 5,
            staging_prefix: Some("baco-auto-".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    /// Create a simple temp directory with basic Rust project structure (no git)
    fn create_temp_dir_with_project() -> PathBuf {
        let temp_dir = std::env::temp_dir().join(format!(
            "baco-patch-test-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a sample Cargo.toml
        fs::write(
            temp_dir.join("Cargo.toml"),
            r#"[package]
name = "test-repo"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();

        // Create src/main.rs with valid Rust code
        let src_dir = temp_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            r#"fn main() {
    let x = 42;
    println!("Value: {}", x);
}
"#,
        )
        .unwrap();

        temp_dir
    }

    #[test]
    fn test_patch_candidate_creation() {
        let diff = r#"--- a/src/main.rs
+++ b/src/main.rs
@@ -1,4 +1,4 @@
 fn main() {
-    let x = 42;
+    let x = 100;
     println!("Value: {}", x);
 }
"#;

        let candidate = PatchCandidate::new(diff, "src/main.rs");
        assert_eq!(candidate.file_path, "src/main.rs");
        assert!(!candidate.applied);
        assert!(!candidate.diff.is_empty());
    }

    #[test]
    fn test_apply_patch_to_file() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        let original = fs::read_to_string(&main_rs).unwrap();
        assert!(original.contains("let x = 42;"));

        // Simulate patch application
        let patched = original.replace("let x = 42;", "let x = 100;");
        fs::write(&main_rs, &patched).unwrap();

        let new_content = fs::read_to_string(&main_rs).unwrap();
        assert!(new_content.contains("let x = 100;"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_invalid_patch_fails() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        // Write invalid Rust syntax
        fs::write(
            &main_rs,
            r#"fn main() {
    let x = ; // Invalid
}
"#,
        )
        .unwrap();

        // cargo check should fail
        let check_output = Command::new("cargo")
            .current_dir(&temp_dir)
            .args(["check"])
            .output()
            .unwrap();

        assert!(!check_output.status.success());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
