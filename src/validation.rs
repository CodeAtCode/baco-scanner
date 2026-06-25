use crate::checkpoint::Checkpoint;
use crate::config::ScannerConfig;
use crate::findings::VulnerabilityFinding;
use std::path::Path;

/// Validate that a file exists and is a file (not a directory).
pub fn validate_file_exists(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()));
    }
    if !path.is_file() {
        return Err(format!("Path is not a file: {}", path.display()));
    }
    Ok(())
}

/// Validate that a config file exists, parses correctly, and passes business rules.
pub fn validate_config(path: &Path) -> Result<ScannerConfig, String> {
    validate_file_exists(path)?;
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
    let config: ScannerConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;
    config.validate()?;
    Ok(config)
}

/// Validate that a findings JSON file exists, parses, and contains well-formed findings.
/// Automatically generates missing IDs for findings.
pub fn validate_findings(path: &Path) -> Result<Vec<VulnerabilityFinding>, String> {
    validate_file_exists(path)?;
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
    validate_file_exists(path)?;
    Checkpoint::load(path.to_str().ok_or_else(|| {
        format!(
            "Checkpoint path contains invalid characters: {}",
            path.display()
        )
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_file_exists_nonexistent() {
        let result = validate_file_exists(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_validate_file_exists_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_file_exists(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is not a file"));
    }

    #[test]
    fn test_validate_file_exists_valid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = validate_file_exists(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_nonexistent() {
        let result = validate_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "invalid toml {{{").unwrap();

        let result = validate_config(&config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parse"));
    }

    #[test]
    fn test_validate_findings_nonexistent() {
        let result = validate_findings(Path::new("/nonexistent/findings.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_findings_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let findings_path = temp_dir.path().join("findings.json");
        fs::write(&findings_path, "{bad json").unwrap();

        let result = validate_findings(&findings_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parse"));
    }

    #[test]
    fn test_validate_findings_empty_array() {
        let temp_dir = TempDir::new().unwrap();
        let findings_path = temp_dir.path().join("findings.json");
        fs::write(&findings_path, "[]").unwrap();

        let result = validate_findings(&findings_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_findings_valid() {
        let findings_path = std::path::Path::new("/tmp/baco_test_findings.json");
        let findings_json = r#"[{"id": "test-1", "title": "Test", "description": "Desc", "severity": "high", "confidence_score": 0.8, "cwe_id": "CWE-79", "file_path": "src/test.rs", "line_number": 10, "code_snippet": "code", "recommendation": "fix", "already_reported": false, "sources": []}]"#;
        std::fs::write(findings_path, findings_json).unwrap();

        let result = validate_findings(findings_path);
        assert!(result.is_ok(), "Error: {:?}", result.err());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        std::fs::remove_file(findings_path).ok();
    }

    #[test]
    fn test_validate_findings_missing_id() {
        let temp_dir = TempDir::new().unwrap();
        let findings_path = temp_dir.path().join("findings.json");
        let findings_json = r#"[{"id": "", "title": "Test", "description": "Desc", "severity": "high", "confidence_score": 0.8, "file_path": "src/test.rs", "line_number": 10, "code_snippet": "code", "recommendation": "fix", "cwe_id": "CWE-79", "already_reported": false, "sources": []}]"#;
        fs::write(&findings_path, findings_json).unwrap();

        let result = validate_findings(&findings_path);
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].id.is_empty(), "ID should be auto-generated");
        // ID is a SHA256 hex hash (64 characters)
        assert_eq!(findings[0].id.len(), 64, "ID should be a 64-char hex hash");
        assert!(
            findings[0].id.chars().all(|c| c.is_ascii_hexdigit()),
            "ID should be hex-encoded"
        );
    }

    #[test]
    fn test_validate_checkpoint_nonexistent() {
        let result = validate_checkpoint(Path::new("/nonexistent/checkpoint.json"));
        assert!(result.is_err());
    }
}
