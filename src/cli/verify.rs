use crate::config;
use crate::validation;
use std::path::{Path, PathBuf};
use tracing::info;

pub async fn run_verify(
    input: &Path,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = validation::validate_findings(input)?;
    if findings.is_empty() {
        if !quiet {
            info!("No findings to verify.");
        }
        return Ok(());
    }

    if !quiet {
        tracing::info!("Loaded {} findings to verify", findings.len());
    }

    let config_path =
        config_path.or_else(|| std::env::var("LLM_CONFIG_PATH").map(PathBuf::from).ok());
    let mut config = match &config_path {
        Some(path) => {
            if !path.exists() {
                tracing::error!("Config file not found: {:?}", path);
                return Err("Config file not found".into());
            }
            let path_str = path.to_str().ok_or("Invalid config path")?;
            config::ScannerConfig::from_file(path_str)?
        }
        None => config::ScannerConfig::default(),
    };
    config::apply_env_overrides(&mut config);
    if config.llm.phases.verification.api_key.is_none() {
        tracing::error!("LLM verification API key is not configured.");
        std::process::exit(1);
    }
    let client =
        crate::llm::LlmClient::new(crate::llm::phase_llm_config(&config, "verification", None)?);
    for finding in findings.iter_mut() {
        tracing::info!("Verifying finding: {}", finding.id);
        let messages = vec![
            crate::llm::ChatMessage::system(
                "You are a security expert. Analyze each finding and determine if it is a confirmed vulnerability, false positive, or needs manual review. Return JSON: {\"verification_status\": \"confirmed\"|\"false_positive\"|\"needs_review\", \"verification_notes\": \"explanation\"}",
            ),
            crate::llm::ChatMessage::user(
                format!(
                    "Finding:\n- ID: {}\n- Title: {}\n- Severity: {}\n- File: {}:{}\n- Description: {}\n- CWE: {}\n- Code: {}\n- Recommendation: {}\n\nAnalyze this finding.",
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.file_path,
                    finding.line_number.unwrap_or(0),
                    finding.description,
                    finding.cwe_id.as_deref().unwrap_or("N/A"),
                    finding.code_snippet.as_deref().unwrap_or(""),
                    finding.recommendation.as_deref().unwrap_or("")
                ).as_str()
            ),
        ];
        match client.chat(&messages).await {
            Ok(response_with_model) => {
                tracing::debug!("LLM response: {}", response_with_model.content);
                let (status, notes) =
                    crate::scanner::phases::llm_phases::parse_verification_verdict(
                        &response_with_model.content,
                    );
                finding.verification_status = Some(status);
                finding.verification_notes = Some(notes);
            }
            Err(e) => {
                tracing::error!("LLM verification failed for {}: {}", finding.id, e);
                finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
                finding.verification_error = Some(e.to_string());
            }
        }
    }
    let output_path = format!("{}/verified_findings.json", config.output.dir);

    if !quiet {
        tracing::info!(
            "Writing {} verified findings to {:?}",
            findings.len(),
            output_path
        );
    }
    let json = serde_json::to_string_pretty(&findings)
        .map_err(|e| format!("Failed to serialize verified findings: {}", e))?;
    std::fs::write(&output_path, &json)
        .map_err(|e| format!("Failed to write verified findings: {}", e))?;

    if !quiet {
        info!(
            "Verification complete. Results written to {:?}",
            output_path
        );
    }
    Ok(())
}
