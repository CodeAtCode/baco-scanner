use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use async_trait::async_trait;
use std::process::Command;

pub struct GitAnalysisPhase;

#[async_trait]
impl ScanPhase for GitAnalysisPhase {
    fn name(&self) -> &'static str {
        "GitAnalysis"
    }

    fn order(&self) -> u8 {
        7
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running Git Analysis phase...");

        let target_path = ctx.scanner.target_path().to_str().unwrap_or(".");
        let mut updated_findings = Vec::new();

        let cve_patterns = ["CVE-", "security", "vulnerability", "fix", "patch", "fixes"];

        for mut finding in ctx.scanner.findings().clone() {
            let file_path = &finding.file_path;

            for pattern in cve_patterns {
                let output = Command::new("git")
                    .args([
                        "log",
                        "--oneline",
                        "--all",
                        "-20",
                        "--grep",
                        pattern,
                        "--",
                        file_path,
                    ])
                    .current_dir(target_path)
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let commit_output = String::from_utf8_lossy(&output.stdout);
                        if !commit_output.trim().is_empty() {
                            let first_commit = commit_output
                                .lines()
                                .next()
                                .and_then(|line| line.split_whitespace().next())
                                .map(|s| s.to_string());

                            if first_commit.is_some() {
                                finding.commit_reference = first_commit;
                                tracing::debug!(
                                    "Found git commit for {}: {:?}",
                                    file_path,
                                    finding.commit_reference
                                );
                                break;
                            }
                        }
                    }
                }
            }

            // If no commit found via grep, try git log on the file directly
            if finding.commit_reference.is_none() {
                let output = Command::new("git")
                    .args(["log", "--oneline", "-5", "--", file_path])
                    .current_dir(target_path)
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let log_output = String::from_utf8_lossy(&output.stdout);
                        if !log_output.trim().is_empty() {
                            let security_keywords = ["fix", "CVE", "security", "vuln", "patch"];
                            for line in log_output.lines() {
                                let line_lower = line.to_lowercase();
                                if security_keywords.iter().any(|k| line_lower.contains(k)) {
                                    let commit =
                                        line.split_whitespace().next().map(|s| s.to_string());
                                    if commit.is_some() {
                                        finding.commit_reference = commit;
                                        tracing::debug!(
                                            "Found security-related commit for {}: {:?}",
                                            file_path,
                                            finding.commit_reference
                                        );
                                        break;
                                    }
                                }
                            }

                            if finding.commit_reference.is_none() {
                                let commit = log_output
                                    .lines()
                                    .next()
                                    .and_then(|line| line.split_whitespace().next())
                                    .map(|s| s.to_string());
                                finding.commit_reference = commit;
                            }
                        }
                    }
                }
            }

            updated_findings.push(finding);
        }

        tracing::info!(
            "Git Analysis complete - {} findings processed, {} with commit references",
            updated_findings.len(),
            updated_findings
                .iter()
                .filter(|f| f.commit_reference.is_some())
                .count()
        );

        Ok(updated_findings)
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}
