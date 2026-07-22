//! PoC compilation and auto-patching logic

use crate::scanner_types::patch::PatchCandidate;
use crate::staging::core::StagingArea;
use crate::staging::error::{AutoPatchError, AutoPatchResult, PatchValidationResult};
use std::path::PathBuf;

/// Auto-Patcher for generating and validating patches
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
    ) -> AutoPatchResult<PatchCandidate> {
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
    pub fn validate_patch(
        &self,
        candidate: &PatchCandidate,
    ) -> AutoPatchResult<PatchValidationResult> {
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
    ) -> AutoPatchResult<PatchValidationResult> {
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
    ) -> AutoPatchResult<Vec<crate::findings::VulnerabilityFinding>> {
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

    // ============================================================================
    // AutoPatcher Tests
    // ============================================================================

    #[test]
    fn test_auto_patcher_creation() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));
        assert_eq!(patcher.repo_path, PathBuf::from("/tmp/test-repo"));
    }

    #[test]
    fn test_generate_patch_placeholder() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let result =
            patcher.generate_patch("test vulnerability", "unsafe code here", "src/test.rs");

        assert!(result.is_ok());
        let patch = result.unwrap();

        // Verify the patch contains expected unified diff format
        assert!(patch.diff.contains("--- a/src/test.rs"));
        assert!(patch.diff.contains("+++ b/src/test.rs"));
        assert!(patch.diff.contains("@@ -1,10 +1,10 @@"));
    }

    #[test]
    fn test_generate_patch_file_path() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let result = patcher.generate_patch("desc", "code", "lib/utils.rs");
        assert!(result.is_ok());
        let patch = result.unwrap();

        assert_eq!(patch.file_path, "lib/utils.rs");
    }

    #[test]
    fn test_format_patch_report_validated() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let candidate = PatchCandidate::new("test diff", "src/test.rs");
        let validation = PatchValidationResult {
            compiles: true,
            tests_pass: true,
            warnings: 0,
            error_message: None,
        };

        let report = patcher.format_patch_report(&candidate, &validation);

        assert!(report.contains("Patch Report"));
        assert!(report.contains("src/test.rs"));
        assert!(report.contains("✅ VALIDATED"));
        assert!(report.contains("test diff"));
    }

    #[test]
    fn test_format_patch_report_compiles_but_tests_failed() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let candidate = PatchCandidate::new("test diff", "src/test.rs");
        let validation = PatchValidationResult {
            compiles: true,
            tests_pass: false,
            warnings: 0,
            error_message: Some("test failed".to_string()),
        };

        let report = patcher.format_patch_report(&candidate, &validation);

        assert!(report.contains("⚠️ COMPILES BUT TESTS FAILED"));
    }

    #[test]
    fn test_format_patch_report_failed() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let candidate = PatchCandidate::new("test diff", "src/test.rs");
        let validation = PatchValidationResult {
            compiles: false,
            tests_pass: false,
            warnings: 0,
            error_message: Some("build failed".to_string()),
        };

        let report = patcher.format_patch_report(&candidate, &validation);

        assert!(report.contains("❌ FAILED"));
        assert!(report.contains("Build Errors:"));
        assert!(report.contains("build failed"));
    }

    #[test]
    fn test_format_patch_report_with_warnings() {
        let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

        let candidate = PatchCandidate::new("test diff", "src/test.rs");
        let validation = PatchValidationResult {
            compiles: true,
            tests_pass: true,
            warnings: 5,
            error_message: None,
        };

        let report = patcher.format_patch_report(&candidate, &validation);

        assert!(report.contains("Warnings: 5"));
    }

    // ============================================================================
    // PatchingConfig Tests
    // ============================================================================

    #[test]
    fn test_patching_config_default() {
        let config = PatchingConfig::default();

        assert!(!config.dry_run);
        assert!(!config.allow_network_access);
        assert_eq!(config.max_auto_patches, 5);
        assert_eq!(config.staging_prefix, Some("baco-auto-".to_string()));
    }

    #[test]
    fn test_patching_config_clone() {
        let config1 = PatchingConfig {
            dry_run: true,
            allow_network_access: true,
            max_auto_patches: 10,
            staging_prefix: Some("custom-".to_string()),
        };

        let config2 = config1.clone();

        assert_eq!(config1.dry_run, config2.dry_run);
        assert_eq!(config1.allow_network_access, config2.allow_network_access);
        assert_eq!(config1.max_auto_patches, config2.max_auto_patches);
        assert_eq!(config1.staging_prefix, config2.staging_prefix);
    }

    #[test]
    fn test_patching_config_debug() {
        let config = PatchingConfig::default();
        let debug_output = format!("{:?}", config);

        assert!(debug_output.contains("dry_run"));
        assert!(debug_output.contains("allow_network_access"));
        assert!(debug_output.contains("max_auto_patches"));
        assert!(debug_output.contains("staging_prefix"));
    }
}
