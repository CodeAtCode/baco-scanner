use crate::checkpoint::Checkpoint;
use crate::config::{ConfigError, ScannerConfig};
use crate::findings::VulnerabilityFinding;
use std::path::Path;

/// Validate that a file exists and is a file (not a directory).
pub fn validate_file_exists(path: &Path) -> Result<(), std::io::Error> {
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Path does not exist: {}", path.display()),
        ));
    }
    if !path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Path is not a file: {}", path.display()),
        ));
    }
    Ok(())
}

/// Validate that a config file exists, parses correctly, and passes business rules.
pub fn validate_config(path: &Path) -> Result<ScannerConfig, ConfigError> {
    validate_file_exists(path).map_err(ConfigError::Io)?;
    let content = std::fs::read_to_string(path)?;
    let config: ScannerConfig = toml::from_str(&content)?;
    config.validate()?;
    Ok(config)
}

/// Validate that a findings JSON file exists, parses, and contains well-formed findings.
/// Automatically generates missing IDs for findings.
pub fn validate_findings(path: &Path) -> Result<Vec<VulnerabilityFinding>, String> {
    validate_file_exists(path).map_err(|e| e.to_string())?;
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read findings file {}: {}", path.display(), e))?;
    let mut findings: Vec<VulnerabilityFinding> = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse findings {}: {}", path.display(), e))?;
    if findings.is_empty() {
        return Err(format!("Findings file is empty: {}", path.display()));
    }

    // Generate missing IDs for findings that don't have them
    for (i, finding) in findings.iter_mut().enumerate() {
        if finding.id.is_empty() {
            finding.id = VulnerabilityFinding::generate_id(
                &finding.file_path,
                finding.line_number,
                finding.cwe_id.as_deref().unwrap_or("CWE-000"),
            );
            tracing::debug!("Generated missing ID for finding {}: {}", i, finding.id);
        }
    }

    Ok(findings)
}

/// Validate that a checkpoint file exists, parses, and passes structural checks.
pub fn validate_checkpoint(path: &Path) -> Result<Checkpoint, String> {
    validate_file_exists(path).map_err(|e| e.to_string())?;
    Checkpoint::load(path.to_str().ok_or_else(|| {
        format!(
            "Checkpoint path contains invalid characters: {}",
            path.display()
        )
    })?)
}
