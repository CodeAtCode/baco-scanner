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
fn normalize_code_snippet(snippet: Option<&str>) -> String {
    match snippet {
        Some(s) => s.chars().filter(|c| !c.is_whitespace()).collect::<String>(),
        None => String::new(),
    }
}

/// Convert findings::Severity to scanner_types::V3Severity
fn convert_severity(severity: Severity) -> V3Severity {
    match severity {
        Severity::Critical => V3Severity::Critical,
        Severity::High => V3Severity::High,
        Severity::Medium => V3Severity::Medium,
        Severity::Low => V3Severity::Low,
        Severity::Info => V3Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(
        id: &str,
        title: &str,
        file_path: &str,
        line_number: Option<u32>,
        code_snippet: Option<&str>,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: title.to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: file_path.to_string(),
            line_number,
            code_snippet: code_snippet.map(String::from),
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.9),
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }
    }

    #[test]
    fn test_compute_root_cause_id_same_inputs() {
        let finding1 = make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );
        let finding2 = make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

        assert_eq!(id1, id2, "Same inputs should produce same root cause ID");
    }

    #[test]
    fn test_compute_root_cause_id_different_files() {
        let finding1 = make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );
        let finding2 = make_finding(
            "f2",
            "SQL Injection",
            "src/api.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

        assert_ne!(
            id1, id2,
            "Different files should produce different root cause IDs"
        );
    }

    #[test]
    fn test_compute_root_cause_id_different_snippets() {
        let finding1 = make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );
        let finding2 = make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM admin"),
        );

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

        assert_ne!(
            id1, id2,
            "Different code snippets should produce different root cause IDs"
        );
    }

    #[test]
    fn test_compute_root_cause_id_normalizes_whitespace() {
        // Same code, different whitespace
        let finding1 = make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT *\nFROM users"),
        );
        let finding2 = make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        );

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

        assert_eq!(
            id1, id2,
            "Normalized whitespace should produce same root cause ID"
        );
    }

    #[test]
    fn test_deduplicate_same_root_cause() {
        let mut dedup = RootCauseDeduplicator::new();

        // Same title, same file, same snippet = same root cause
        let findings = vec![
            make_finding(
                "f1",
                "SQL Injection",
                "src/db.rs",
                Some(42),
                Some("SELECT * FROM users"),
            ),
            make_finding(
                "f2",
                "SQL Injection",
                "src/db.rs",
                Some(100),
                Some("SELECT * FROM users"),
            ),
        ];

        let groups = dedup.deduplicate(findings);

        assert_eq!(groups.len(), 1, "Should have 1 group for same root cause");
        // Use iterator to find the group instead of index
        let total_findings: usize = groups.iter().map(|g| g.findings.len()).sum();
        assert_eq!(total_findings, 2, "Group should contain both findings");
    }

    #[test]
    fn test_deduplicate_different_root_causes() {
        let mut dedup = RootCauseDeduplicator::new();

        let findings = vec![
            make_finding(
                "f1",
                "SQL Injection",
                "src/db.rs",
                Some(42),
                Some("SELECT * FROM users"),
            ),
            make_finding(
                "f2",
                "XSS",
                "src/api.rs",
                Some(100),
                Some("<script>alert(1)</script>"),
            ),
        ];

        let groups = dedup.deduplicate(findings);

        assert_eq!(
            groups.len(),
            2,
            "Should have 2 groups for different root causes"
        );
    }

    #[test]
    fn test_deduplicate_preserves_locations() {
        let mut dedup = RootCauseDeduplicator::new();

        // Same file path, different line numbers - should group together
        let findings = vec![
            make_finding(
                "f1",
                "SQL Injection",
                "src/db.rs",
                Some(42),
                Some("SELECT * FROM users"),
            ),
            make_finding(
                "f2",
                "SQL Injection",
                "src/db.rs",
                Some(100),
                Some("SELECT * FROM users"),
            ),
        ];

        let groups = dedup.deduplicate(findings);

        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.all_locations.len(), 2);
        assert!(group.all_locations.contains(&("src/db.rs".to_string(), 42)));
        assert!(group
            .all_locations
            .contains(&("src/db.rs".to_string(), 100)));
    }

    #[test]
    fn test_merge_groups() {
        let mut dedup = RootCauseDeduplicator::new();

        let group1 = RootCauseGroup::new("abc123", "SQL Injection", V3Severity::High);
        let mut group1 = group1;
        group1.add_finding("f1", "src/db.rs", 42);

        let group2 = RootCauseGroup::new(
            "abc123", // Same ID - should merge
            "SQL Injection",
            V3Severity::High,
        );
        let mut group2 = group2;
        group2.add_finding("f2", "src/api.rs", 100);

        dedup.merge_groups(vec![group1, group2]);

        assert_eq!(dedup.group_count(), 1);
        let groups = dedup.into_groups();
        // Use iterator since HashMap iteration order is non-deterministic
        let total_findings: usize = groups.iter().map(|g| g.findings.len()).sum();
        assert_eq!(total_findings, 2);
    }

    #[test]
    fn test_deduplicate_with_no_code_snippet() {
        let mut dedup = RootCauseDeduplicator::new();

        let findings = vec![
            make_finding("f1", "SQL Injection", "src/db.rs", Some(42), None),
            make_finding("f2", "SQL Injection", "src/db.rs", Some(100), None),
        ];

        let groups = dedup.deduplicate(findings);

        assert_eq!(
            groups.len(),
            1,
            "Should group findings even without code snippet"
        );
    }

    #[test]
    fn test_deduplicate_case_insensitive_title() {
        let finding1 = make_finding(
            "f1",
            "sql injection",
            "src/db.rs",
            Some(42),
            Some("SELECT *"),
        );
        let finding2 = make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT *"),
        );

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

        assert_eq!(id1, id2, "Case-insensitive title should produce same ID");
    }
}
