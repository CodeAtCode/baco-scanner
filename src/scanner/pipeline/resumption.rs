use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Checkpoint manager for scan resumption.
pub struct CheckpointManager {
    checkpoint_path: PathBuf,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new(checkpoint_path: PathBuf) -> Self {
        Self { checkpoint_path }
    }

    /// Check if checkpoint exists.
    pub fn exists(&self) -> bool {
        self.checkpoint_path.exists()
    }

    /// Save scan state to checkpoint.
    pub async fn save(
        &self,
        phase: &ScanPhase,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        _metrics: &LlmMetricsTracker,
    ) -> Result<(), String> {
        let checkpoint = ScanCheckpoint {
            last_completed_phase: phase.clone(),
            findings: findings.to_vec(),
            analyzed_files: analyzed_files.to_vec(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| format!("Failed to serialize checkpoint: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = self.checkpoint_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directory: {}", e))?;
        }

        fs::write(&self.checkpoint_path, json)
            .map_err(|e| format!("Failed to write checkpoint: {}", e))?;

        Ok(())
    }

    /// Load the last checkpoint.
    pub async fn load(&self) -> Option<ScanCheckpoint> {
        if !self.checkpoint_path.exists() {
            return None;
        }

        let json = fs::read_to_string(&self.checkpoint_path).ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Get the last completed phase from checkpoint.
    pub async fn last_completed_phase(&self) -> Option<ScanPhase> {
        self.load().await.map(|c| c.last_completed_phase)
    }

    /// Delete the checkpoint.
    pub fn delete(&self) -> Result<(), String> {
        if self.checkpoint_path.exists() {
            fs::remove_file(&self.checkpoint_path)
                .map_err(|e| format!("Failed to delete checkpoint: {}", e))?;
        }
        Ok(())
    }
}

/// Configuration for checkpoint behavior.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CheckpointConfig {
    pub enabled: bool,
    pub save_after_each_phase: bool,
    pub checkpoint_path: PathBuf,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            save_after_each_phase: true,
            checkpoint_path: PathBuf::from("checkpoint.json"),
        }
    }
}

/// Scan checkpoint data.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub last_completed_phase: ScanPhase,
    pub findings: Vec<VulnerabilityFinding>,
    pub analyzed_files: Vec<String>,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use tempfile::TempDir;

    fn create_test_finding(title: &str) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
            title: title.to_string(),
            description: format!("Test finding: {}", title),
            severity: Severity::Medium,
            confidence_score: 0.7,
            file_path: "src/test.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("test code".to_string()),
            cwe_id: Some("CWE-79".to_string()),
            verification_status: None,
            sources: vec!["test".to_string()],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
        }
    }

    #[tokio::test]
    async fn test_checkpoint_manager_new() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        assert_eq!(manager.checkpoint_path, checkpoint_path);
    }

    #[tokio::test]
    async fn test_checkpoint_manager_exists_false() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path);

        assert!(!manager.exists());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_save_and_exists() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        let findings = vec![create_test_finding("Test")];
        let analyzed_files = vec!["file1.rs".to_string()];
        let metrics = LlmMetricsTracker::new();

        let result = manager
            .save(&ScanPhase::Indexing, &findings, &analyzed_files, &metrics)
            .await;

        assert!(result.is_ok());
        assert!(manager.exists());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path);

        let result = manager.load().await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        let findings = vec![create_test_finding("Saved Finding")];
        let analyzed_files = vec!["saved.rs".to_string()];
        let metrics = LlmMetricsTracker::new();

        manager
            .save(&ScanPhase::Semgrep, &findings, &analyzed_files, &metrics)
            .await
            .unwrap();

        let loaded = manager.load().await.unwrap();

        assert_eq!(loaded.last_completed_phase, ScanPhase::Semgrep);
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].title, "Saved Finding");
        assert_eq!(loaded.analyzed_files.len(), 1);
        assert_eq!(loaded.analyzed_files[0], "saved.rs");
        assert!(!loaded.timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_last_completed_phase() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        let findings: Vec<VulnerabilityFinding> = vec![];
        let analyzed_files: Vec<String> = vec![];
        let metrics = LlmMetricsTracker::new();

        manager
            .save(&ScanPhase::Reporting, &findings, &analyzed_files, &metrics)
            .await
            .unwrap();

        let phase = manager.last_completed_phase().await.unwrap();

        assert_eq!(phase, ScanPhase::Reporting);
    }

    #[tokio::test]
    async fn test_checkpoint_manager_delete() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        let findings: Vec<VulnerabilityFinding> = vec![];
        let analyzed_files: Vec<String> = vec![];
        let metrics = LlmMetricsTracker::new();

        manager
            .save(&ScanPhase::Indexing, &findings, &analyzed_files, &metrics)
            .await
            .unwrap();

        assert!(manager.exists());

        let result = manager.delete();
        assert!(result.is_ok());
        assert!(!manager.exists());
    }

    #[tokio::test]
    async fn test_checkpoint_manager_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path);

        let result = manager.delete();

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_checkpoint_serialization() {
        let checkpoint = ScanCheckpoint {
            last_completed_phase: ScanPhase::LlmStaticAnalysis,
            findings: vec![create_test_finding("Checkpoint Finding")],
            analyzed_files: vec!["checkpoint.rs".to_string()],
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string_pretty(&checkpoint).unwrap();

        assert!(json.contains("last_completed_phase"));
        assert!(json.contains("LlmStaticAnalysis"));
        assert!(json.contains("findings"));
        assert!(json.contains("analyzed_files"));
        assert!(json.contains("timestamp"));
    }

    #[tokio::test]
    async fn test_scan_checkpoint_deserialization() {
        let json = r#"{
            "last_completed_phase": "GitAnalysis",
            "findings": [],
            "analyzed_files": ["file1.rs", "file2.rs"],
            "timestamp": "2024-06-15T12:00:00+00:00"
        }"#;

        let checkpoint: ScanCheckpoint = serde_json::from_str(json).unwrap();

        assert_eq!(checkpoint.last_completed_phase, ScanPhase::GitAnalysis);
        assert!(checkpoint.findings.is_empty());
        assert_eq!(checkpoint.analyzed_files.len(), 2);
        assert_eq!(checkpoint.analyzed_files[0], "file1.rs");
    }

    #[test]
    fn test_checkpoint_config_default() {
        let config = CheckpointConfig::default();

        assert!(config.enabled);
        assert!(config.save_after_each_phase);
        assert_eq!(config.checkpoint_path, PathBuf::from("checkpoint.json"));
    }

    #[test]
    fn test_checkpoint_config_custom() {
        let config = CheckpointConfig {
            enabled: false,
            save_after_each_phase: false,
            checkpoint_path: PathBuf::from("custom/path/checkpoint.json"),
        };

        assert!(!config.enabled);
        assert!(!config.save_after_each_phase);
        assert_eq!(
            config.checkpoint_path,
            PathBuf::from("custom/path/checkpoint.json")
        );
    }

    #[tokio::test]
    async fn test_checkpoint_save_creates_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested/checkpoint.json");

        let manager = CheckpointManager::new(nested_path.clone());

        let findings: Vec<VulnerabilityFinding> = vec![];
        let analyzed_files: Vec<String> = vec![];
        let metrics = LlmMetricsTracker::new();

        let result = manager
            .save(&ScanPhase::Indexing, &findings, &analyzed_files, &metrics)
            .await;

        assert!(result.is_ok());
        assert!(nested_path.exists());
    }

    #[tokio::test]
    async fn test_checkpoint_save_empty_findings() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        let manager = CheckpointManager::new(checkpoint_path.clone());

        let findings: Vec<VulnerabilityFinding> = vec![];
        let analyzed_files: Vec<String> = vec![];
        let metrics = LlmMetricsTracker::new();

        let result = manager
            .save(&ScanPhase::Indexing, &findings, &analyzed_files, &metrics)
            .await;

        assert!(result.is_ok());

        let loaded = manager.load().await.unwrap();
        assert!(loaded.findings.is_empty());
        assert!(loaded.analyzed_files.is_empty());
    }

    #[tokio::test]
    async fn test_checkpoint_load_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");

        fs::write(&checkpoint_path, "invalid json content").unwrap();

        let manager = CheckpointManager::new(checkpoint_path);

        let result = manager.load().await;

        assert!(result.is_none());
    }
}
