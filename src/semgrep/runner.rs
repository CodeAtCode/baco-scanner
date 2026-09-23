use super::parser::parse_json_output;
use super::rules::SemgrepRunner;
use crate::findings::VulnerabilityFinding;
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
        // Note: cache functionality removed for Semgrep v2+ compatibility
        // The --cache-path and --no-cache flags are no longer supported

        // Inline preset rules become temp files; keep them alive until
        // semgrep exits (NamedTempFile removes them on drop).
        let custom_rule_files = self.materialize_custom_rules()?;

        let mut cmd = tokio::process::Command::new("semgrep");
        cmd.arg("scan")
            .arg("--json")
            .arg("--quiet")
            .arg("--timeout")
            .arg(self.timeout_secs.to_string())
            .arg(target_path);

        // Add multiple --config args if rulesets are specified
        // If empty, derive defaults from project languages
        let effective_rulesets = self.derive_default_rulesets();
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

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            cmd.kill_on_drop(true).output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(format!("semgrep not found: {e}"));
                }
                return Err(format!("semgrep wait failed: {e}"));
            }
            Err(_) => return Err(format!("semgrep timed out after {}s", self.timeout_secs)),
        };

        if !output.status.success() {
            return Err(format!(
                "semgrep exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Extract stems from temp file paths for normalization
        let stems: Vec<String> = custom_rule_files
            .iter()
            .map(|f| {
                f.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default()
            })
            .collect();

        parse_json_output(&output.stdout, &self.exclude_rules, &stems)
    }
}
