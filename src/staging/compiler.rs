//! PoC compilation and auto-patching logic

use crate::llm::{ChatMessage, LlmClient};
use crate::scanner_types::patch::PatchCandidate;
use crate::staging::PatchValidationResult;
use crate::staging::core::StagingArea;
use crate::staging::error::{AutoPatchError, AutoPatchResult};
use std::path::PathBuf;
use std::sync::Arc;

/// Auto-Patcher for generating and validating patches
pub struct AutoPatcher {
    /// Repository path for patch operations
    pub repo_path: PathBuf,
    /// Model asked to produce the diff. Without one, generation cannot happen and
    /// `generate_patch` reports that rather than inventing a patch.
    llm_client: Option<Arc<LlmClient>>,
}

impl AutoPatcher {
    /// A patcher with no model. `generate_patch` will report `NoLlmClient`.
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            llm_client: None,
        }
    }

    /// A patcher that asks `llm_client` to produce the diff.
    pub fn with_llm(repo_path: PathBuf, llm_client: Arc<LlmClient>) -> Self {
        Self {
            repo_path,
            llm_client: Some(llm_client),
        }
    }

    /// Generate a patch for fixing a vulnerability
    ///
    /// Calls the model with a prompt that describes the vulnerability and asks for
    /// a unified diff. The response must be a diff for `file_path`; anything else is
    /// rejected rather than passed on to `validate_patch`.
    pub async fn generate_patch(
        &self,
        vulnerability_description: &str,
        vulnerable_code: &str,
        file_path: &str,
    ) -> AutoPatchResult<PatchCandidate> {
        let Some(client) = self.llm_client.as_ref() else {
            return Err(AutoPatchError::NoLlmClient);
        };

        let user = format!(
            "Vulnerability:\n{vulnerability_description}\n\n\
             Vulnerable code in {file_path}:\n```\n{vulnerable_code}\n```\n\n\
             Reply with a unified diff against {file_path} that fixes it. \
             The diff must begin with a line starting \"--- a/{file_path}\". \
             Output only the diff."
        );
        let response = client
            .chat(&[
                ChatMessage::system(
                    "You write minimal, correct unified diffs that fix a single \
                     reported vulnerability. You output nothing but the diff.",
                ),
                ChatMessage::user(&user),
            ])
            .await
            .map_err(|e| AutoPatchError::Generation(e.to_string()))?;

        let diff = extract_unified_diff(&response.content, file_path)?;
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
    pub async fn execute_batch(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
        config: &PatchingConfig,
    ) -> AutoPatchResult<Vec<crate::findings::VulnerabilityFinding>> {
        self.execute_batch_with_vuln_spec(findings, config, None)
            .await
    }

    /// Execute batch auto-patching with optional vuln_spec config for auto-extraction
    pub async fn execute_batch_with_vuln_spec(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
        config: &PatchingConfig,
        vuln_spec_config: Option<&crate::vuln_spec::VulnSpecConfig>,
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
            let patch = self
                .generate_patch(&finding.title, code_snippet, &finding.file_path)
                .await?;

            // Auto-extract specs from patch if enabled
            if let Some(vs_config) = vuln_spec_config {
                if vs_config.enabled && vs_config.auto_extract_from_patches {
                    let specs = crate::vuln_spec::extractor::extract_from_patch(&patch.diff);
                    if !specs.is_empty() {
                        // Set domain category if not general
                        let domain =
                            crate::vuln_spec::extractor::extract_domain_from_patch(&patch.diff);
                        let mut specs_with_domain = specs;
                        for spec in &mut specs_with_domain {
                            if domain != "general" {
                                spec.category =
                                    crate::vuln_spec::schema::DomainCategory::DomainSpecific(
                                        domain.clone(),
                                    );
                            }
                        }

                        if let Ok(count) =
                            crate::vuln_spec::retriever::add_specs_to_index(&specs_with_domain)
                        {
                            tracing::debug!(
                                "Added {} specs from auto-generated patch (domain: {})",
                                count,
                                domain
                            );
                        }
                    }
                }
            }

            // Validate patch (skipped in dry-run: no repo mutation, no
            // worktree compilation)
            let validation = if config.dry_run {
                crate::staging::error::PatchValidationResult::default()
            } else {
                self.validate_patch(&patch)?
            };

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

/// Pull a unified diff for `file_path` out of a model response.
///
/// Models routinely wrap a diff in prose or a fenced block, so the diff is located
/// rather than assumed to be the whole reply. A reply with no diff for this file is
/// an error: `validate_patch` would otherwise be handed prose, and its failure would
/// read as a patch that did not apply.
fn extract_unified_diff(response: &str, file_path: &str) -> AutoPatchResult<String> {
    let expected_header = format!("--- a/{file_path}");

    let start = response
        .lines()
        .position(|l| l.trim_start().starts_with(&expected_header))
        .ok_or_else(|| {
            AutoPatchError::Generation(format!(
                "model returned no unified diff for {file_path}; \
                 expected a line starting '{expected_header}'"
            ))
        })?;

    let diff: String = response
        .lines()
        .skip(start)
        .take_while(|l| !l.starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n");

    if !diff.contains("@@") {
        return Err(AutoPatchError::Generation(format!(
            "model returned a diff for {file_path} with no hunk header"
        )));
    }

    Ok(diff)
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
