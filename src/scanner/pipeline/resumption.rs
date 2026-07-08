//! Checkpoint management for phase resumption.
//!
//! Handles saving and loading scan state to allow resuming
//! interrupted scans from the last completed phase.

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Checkpoint data for resuming scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub last_completed_phase: ScanPhase,
    pub findings: Vec<VulnerabilityFinding>,
    pub analyzed_files: Vec<String>,
    pub timestamp: String,
}

/// Manages checkpoint save/load operations.
pub struct CheckpointManager {
    checkpoint_path: PathBuf,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new(checkpoint_path: PathBuf) -> Self {
        Self { checkpoint_path }
    }

    /// Check if a checkpoint exists.
    pub fn exists(&self) -> bool {
        self.checkpoint_path.exists()
    }

    /// Save a checkpoint with current scan state.
    pub async fn save(
        &self,
        phase: &ScanPhase,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        _metrics_tracker: &LlmMetricsTracker,
    ) -> Result<(), String> {
        let checkpoint = ScanCheckpoint {
            last_completed_phase: phase.clone(),
            findings: findings.to_vec(),
            analyzed_files: analyzed_files.to_vec(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // Ensure parent directory exists
        if let Some(parent) = self.checkpoint_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create checkpoint directory: {}", e))?;
        }

        // Serialize and save
        let json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| format!("Failed to serialize checkpoint: {}", e))?;

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
