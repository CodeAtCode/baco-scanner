use super::parser::parse_json_output;
use super::rules::SemgrepRunner;
use crate::findings::VulnerabilityFinding;
use std::process::Command;
use tempfile::NamedTempFile;

impl SemgrepRunner {
    /// Write each inline `custom_rules` YAML document to a temp .yml file so
    /// `semgrep --config` can consume it. Handles must stay alive until the
    /// semgrep process has exited (NamedTempFile deletes on drop).
    pub fn materialize_custom_rules(&self) -> Result<Vec<NamedTempFile>, String> {
        use std::io::Write;

        let mut files = Vec::with_capacity(self.custom_rules.len());
        for (i, yaml) in self.custom_rules.iter().enumerate() {
            let mut f = tempfile::Builder::new()
                .prefix("baco-rules-")
                .suffix(&format!("-{i}.yml"))
                .tempfile()
                .map_err(|e| format!("Failed to create temp rules file: {e}"))?;
            f.write_all(yaml.as_bytes())
                .map_err(|e| format!("Failed to write custom rules #{i}: {e}"))?;
            files.push(f);
        }
        Ok(files)
    }

    pub async fn run(
        &self,
        target_path: &str,
        _output_path: &str,
    ) -> Result<Vec<VulnerabilityFinding>, String> {
        // Use spawn_blocking to avoid blocking the async runtime
        let self_clone = self.clone();
        let target_path_clone = target_path.to_string();

        tokio::task::spawn_blocking(move || {
            // Note: cache functionality removed for Semgrep v2+ compatibility
            // The --cache-path and --no-cache flags are no longer supported

            // Inline preset rules become temp files; keep them alive until
            // semgrep exits (NamedTempFile removes them on drop).
            let custom_rule_files = self_clone.materialize_custom_rules()?;

            let mut cmd = Command::new("semgrep");
            cmd.arg("scan")
                .arg("--json")
                .arg("--quiet")
                .arg(&target_path_clone);

            // Add multiple --config args if rulesets are specified
            // If empty, derive defaults from project languages
            let effective_rulesets = self_clone.derive_default_rulesets();
            if effective_rulesets.is_empty() {
                // No rulesets - let semgrep use its default behavior
            } else {
                for ruleset in &effective_rulesets {
                    cmd.arg("--config").arg(ruleset);
                }
            }
            for file in &custom_rule_files {
                cmd.arg("--config").arg(file.path());
            }

            let output = cmd
                .output()
                .map_err(|e| format!("Failed to run semgrep: {}", e))?;

            if !output.status.success() {
                return Err(format!(
                    "Semgrep failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            parse_json_output(&output.stdout, &self_clone.exclude_rules)
        })
        .await
        .map_err(|e| format!("Semgrep task panicked: {}", e))?
    }
}
