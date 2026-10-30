use super::parser::parse_json_output;
use super::rules::SemgrepRunner;
use crate::findings::VulnerabilityFinding;
use tempfile::NamedTempFile;

impl SemgrepRunner {
    /// Build the semgrep command arguments.
    /// Returns a Vec of argument strings that would be passed to semgrep.
    pub fn build_args(&self, target_path: &str, rulesets: &[String]) -> Vec<String> {
        let mut args = vec![
            "scan".to_string(),
            "--json".to_string(),
            "--quiet".to_string(),
            "--timeout".to_string(),
            self.timeout_secs.to_string(),
        ];

        // Add --max-target-bytes if configured
        if let Some(max_bytes) = self.max_target_bytes {
            args.push("--max-target-bytes".to_string());
            args.push(max_bytes.to_string());
        }

        // Add --no-git-ignore if force_scan is enabled
        if self.force_scan {
            args.push("--no-git-ignore".to_string());
        }

        args.push(target_path.to_string());

        // Add multiple --config args if rulesets are specified
        for ruleset in rulesets {
            args.push("--config".to_string());
            args.push(ruleset.clone());
        }

        args
    }
    /// Write each inline `custom_rules` YAML document to a temp .yml file so
    /// `semgrep --config` can consume it. Handles must stay alive until the
    /// semgrep process has exited (NamedTempFile deletes on drop).
    pub fn materialize_custom_rules(&self) -> Result<Vec<NamedTempFile>, String> {
        self.materialize_rules_from_yaml(&self.custom_rules)
    }

    /// Generalized helper: write YAML documents to temp files.
    fn materialize_rules_from_yaml(
        &self,
        yaml_docs: &[String],
    ) -> Result<Vec<NamedTempFile>, String> {
        use std::io::Write;

        let mut files = Vec::with_capacity(yaml_docs.len());
        for (i, yaml) in yaml_docs.iter().enumerate() {
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

    /// Materialize effective custom rules: explicit custom_rules plus derived
    /// default taint rules (when explicit rules are absent).
    pub fn materialize_effective_custom_rules(&self) -> Result<Vec<NamedTempFile>, String> {
        let mut all_yaml = Vec::new();

        // Add explicit custom rules first
        all_yaml.extend(self.custom_rules.clone());

        // Add derived default taint rules if no explicit custom rules
        if self.custom_rules.is_empty() {
            all_yaml.extend(self.derive_default_custom_rules());
        }

        self.materialize_rules_from_yaml(&all_yaml)
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
        // This includes explicit custom_rules plus default taint rules (if no explicit rules).
        let custom_rule_files = self.materialize_effective_custom_rules()?;

        // Derive effective rulesets before building args
        let effective_rulesets = self.derive_default_rulesets();

        // Build arguments using the helper (same logic as build_args for testing)
        let mut cmd = tokio::process::Command::new("semgrep");
        let args = self.build_args(target_path, &effective_rulesets);
        for arg in &args {
            cmd.arg(arg);
        }

        // Add multiple --config args for custom rules (temp files)
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

        if !output.status.success() {
            // Try to parse partial JSON output even on non-zero exit.
            // Only return partial results when actual findings exist —
            // an error with zero findings is a real failure, not a clean scan.
            let stderr_msg = String::from_utf8_lossy(&output.stderr);
            match parse_json_output(&output.stdout, &self.exclude_rules, &stems) {
                Ok(findings) if !findings.is_empty() => {
                    tracing::warn!(
                        "semgrep exited with code {} but produced {} findings from partial output: {}",
                        output.status,
                        findings.len(),
                        stderr_msg
                    );
                    Ok(findings)
                }
                Ok(_) => Err(format!(
                    "semgrep exited {}: no usable output (stderr: {})",
                    output.status, stderr_msg
                )),
                Err(parse_err) => Err(format!(
                    "semgrep exited {} and output parse failed: {} (stderr: {})",
                    output.status, parse_err, stderr_msg
                )),
            }
        } else {
            parse_json_output(&output.stdout, &self.exclude_rules, &stems)
        }
    }
}
