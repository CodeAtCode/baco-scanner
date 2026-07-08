use super::parser::parse_json_output;
use super::rules::SemgrepRunner;
use crate::findings::VulnerabilityFinding;
use std::process::Command;

impl SemgrepRunner {
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

            let mut cmd = Command::new("semgrep");
            cmd.arg("scan")
                .arg("--json")
                .arg("--quiet")
                .arg(&target_path_clone);

            if let Some(config) = &self_clone.config_path {
                cmd.arg("--config").arg(config);
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
