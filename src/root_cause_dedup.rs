//! Root Cause Deduplication Module
//!
//! Groups vulnerability findings by root cause using SHA256 hash of:
//! - vulnerability_type (from title or description)
//! - file_path
//! - normalized code_snippet
//!
//! This ensures findings with the same underlying cause are grouped together,
//! even if they appear at different locations in the codebase.

use crate::findings::{Severity, VulnerabilityFinding};
use crate::scanner_types::cve::RootCauseGroup;
use crate::scanner_types::severity::V3Severity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Deduplicates vulnerability findings by grouping them by root cause
pub struct RootCauseDeduplicator {
    groups: HashMap<String, RootCauseGroup>,
}

impl RootCauseDeduplicator {
    /// Create a new RootCauseDeduplicator
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Compute root cause ID from vulnerability finding
    /// Uses SHA256 hash of: vulnerability_type + file_path + normalized code_snippet
    pub fn compute_root_cause_id(finding: &VulnerabilityFinding) -> String {
        let mut hasher = Sha256::new();

        // Use title as vulnerability type (normalized to lowercase)
        let vulnerability_type = finding.title.to_lowercase();
        hasher.update(vulnerability_type.as_bytes());
        hasher.update(b"|");

        // Add file path
        hasher.update(finding.file_path.as_bytes());
        hasher.update(b"|");

        // Add normalized code snippet (whitespace normalized)
        let normalized_snippet = normalize_code_snippet(finding.code_snippet.as_deref());
        hasher.update(normalized_snippet.as_bytes());

        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Deduplicate findings by grouping them by root cause
    pub fn deduplicate(&mut self, findings: Vec<VulnerabilityFinding>) -> Vec<RootCauseGroup> {
        for finding in findings {
            let root_cause_id = Self::compute_root_cause_id(&finding);

            let group = self.groups.entry(root_cause_id.clone()).or_insert_with(|| {
                RootCauseGroup::new(
                    &root_cause_id,
                    &finding.title,
                    convert_severity(finding.severity),
                )
            });

            group.add_finding(
                &finding.id,
                &finding.file_path,
                finding.line_number.unwrap_or(0),
            );
        }

        self.groups.values().cloned().collect()
    }

    /// Merge multiple groups together, combining their findings
    pub fn merge_groups(&mut self, groups: Vec<RootCauseGroup>) {
        for group in groups {
            let entry = self
                .groups
                .entry(group.root_cause_id.clone())
                .or_insert_with(|| {
                    RootCauseGroup::new(&group.root_cause_id, &group.description, group.severity)
                });

            // Merge findings and locations
            for finding_id in group.findings {
                if !entry.findings.contains(&finding_id) {
                    entry.findings.push(finding_id);
                }
            }
            for location in group.all_locations {
                if !entry.all_locations.contains(&location) {
                    entry.all_locations.push(location);
                }
            }
        }
    }

    /// Get all groups
    pub fn into_groups(self) -> Vec<RootCauseGroup> {
        self.groups.into_values().collect()
    }

    /// Get the number of groups
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

impl Default for RootCauseDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global false positive store for cross-scan persistence
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalFpStore {
    fp_ids: HashSet<String>,
    #[serde(skip)]
    path: PathBuf,
}

impl GlobalFpStore {
    /// Create a new empty GlobalFpStore with the given path
    pub fn with_path(path: &Path) -> Self {
        Self {
            fp_ids: HashSet::new(),
            path: path.to_path_buf(),
        }
    }

    /// Load the FP store from a JSON file
    /// If the file is missing or invalid, returns an empty store
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<HashSet<String>>(&content) {
                Ok(fp_ids) => Self {
                    fp_ids,
                    path: path.to_path_buf(),
                },
                Err(e) => {
                    tracing::warn!("Failed to parse FP store at {:?}: {}", path, e);
                    Self::with_path(path)
                }
            },
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to read FP store at {:?}: {}", path, e);
                }
                Self::with_path(path)
            }
        }
    }

    /// Save the FP store to disk as JSON
    pub fn save(&self) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(&self.fp_ids).map_err(std::io::Error::other)?;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, json)
    }

    /// Mark a root cause ID as a false positive
    pub fn mark_false_positive(&mut self, id: &str) {
        self.fp_ids.insert(id.to_string());
        if let Err(e) = self.save() {
            tracing::warn!("Failed to save FP store after marking {}: {}", id, e);
        }
    }

    /// Check if a root cause ID is marked as a false positive
    pub fn is_false_positive(&self, id: &str) -> bool {
        self.fp_ids.contains(id)
    }

    /// Remove a root cause ID from the false positive store
    pub fn remove(&mut self, id: &str) {
        self.fp_ids.remove(id);
        if let Err(e) = self.save() {
            tracing::warn!("Failed to save FP store after removing {}: {}", id, e);
        }
    }

    /// Get the number of false positive IDs in the store
    pub fn len(&self) -> usize {
        self.fp_ids.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.fp_ids.is_empty()
    }
}

/// Normalize code snippet for hashing (remove whitespace variations)
pub fn normalize_code_snippet(snippet: Option<&str>) -> String {
    match snippet {
        Some(s) => s.chars().filter(|c| !c.is_whitespace()).collect::<String>(),
        None => String::new(),
    }
}

/// Convert findings::Severity to scanner_types::V3Severity
pub fn convert_severity(severity: Severity) -> V3Severity {
    match severity {
        Severity::Critical => V3Severity::Critical,
        Severity::High => V3Severity::High,
        Severity::Medium => V3Severity::Medium,
        Severity::Low => V3Severity::Low,
        Severity::Info => V3Severity::Low,
    }
}
