//! BACO v3 Shared Types
//!
//! Common data structures for all v3 features:
//! - Severity rubric scoring
//! - CVE bootstrap
//! - Root cause deduplication
//! - Multi-verifier voting
//! - Auto-patching
//! - PoC compilation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity rubric with 6 frozen dimensions (from Anthropic methodology)
/// These const values MUST NOT be changed after T3 freeze
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SeverityRubric {
    /// How easily can an attacker reach this code? (0.0-1.0)
    pub reachability: f32,
    /// How much control does attacker have over inputs? (0.0-1.0)
    pub attacker_control: f32,
    /// How many preconditions must be met? (0.0-1.0, lower = more preconditions)
    pub preconditions_factor: f32,
    /// Does exploit require authentication?
    pub auth_required: bool,
    /// What type of access does exploit provide?
    pub access_type: AccessType,
    /// What is the blast radius of successful exploit?
    pub blast_radius: BlastRadius,
}

impl Default for SeverityRubric {
    fn default() -> Self {
        Self {
            reachability: 0.5,
            attacker_control: 0.5,
            preconditions_factor: 0.5,
            auth_required: false,
            access_type: AccessType::Read,
            blast_radius: BlastRadius::Medium,
        }
    }
}

impl SeverityRubric {
    /// Create a new rubric with validated dimensions
    pub fn new(
        reachability: f32,
        attacker_control: f32,
        preconditions_factor: f32,
        auth_required: bool,
        access_type: AccessType,
        blast_radius: BlastRadius,
    ) -> Self {
        // Clamp all float values to 0.0-1.0 range
        let reachability = reachability.clamp(0.0, 1.0);
        let attacker_control = attacker_control.clamp(0.0, 1.0);
        let preconditions_factor = preconditions_factor.clamp(0.0, 1.0);

        Self {
            reachability,
            attacker_control,
            preconditions_factor,
            auth_required,
            access_type,
            blast_radius,
        }
    }

    /// Get auth factor multiplier
    pub fn auth_factor(&self) -> f32 {
        if self.auth_required {
            0.5 // Authentication reduces severity
        } else {
            1.0 // No auth requirement = full severity
        }
    }

    /// Get access weight multiplier
    pub fn access_weight(&self) -> f32 {
        match self.access_type {
            AccessType::Read => 0.5,
            AccessType::Write => 0.8,
            AccessType::Both => 1.0,
        }
    }

    /// Get blast radius weight
    pub fn blast_radius_weight(&self) -> f32 {
        match self.blast_radius {
            BlastRadius::Low => 0.3,
            BlastRadius::Medium => 0.6,
            BlastRadius::High => 0.85,
            BlastRadius::Critical => 1.0,
        }
    }
}

/// Type of access a vulnerability provides
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AccessType {
    #[default]
    Read,
    Write,
    Both,
}

/// Blast radius of a successful exploit
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BlastRadius {
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

/// Dimensions extracted from a rubric for scoring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RubricDimensions {
    pub reachability: f32,
    pub attacker_control: f32,
    pub preconditions_factor: f32,
    pub auth_required: bool,
    pub access_type: AccessType,
    pub blast_radius: BlastRadius,
}

impl From<SeverityRubric> for RubricDimensions {
    fn from(rubric: SeverityRubric) -> Self {
        Self {
            reachability: rubric.reachability,
            attacker_control: rubric.attacker_control,
            preconditions_factor: rubric.preconditions_factor,
            auth_required: rubric.auth_required,
            access_type: rubric.access_type,
            blast_radius: rubric.blast_radius,
        }
    }
}

/// Final severity score with breakdown
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RubricScore {
    pub raw_score: f32,
    pub dimensions: RubricDimensions,
    pub severity_override: Option<V3Severity>,
}

impl RubricScore {
    pub fn new(
        raw_score: f32,
        dimensions: RubricDimensions,
        severity_override: Option<V3Severity>,
    ) -> Self {
        Self {
            raw_score: raw_score.clamp(0.0, 1.0),
            dimensions,
            severity_override,
        }
    }

    /// Get final severity (override if present, otherwise map from raw score)
    pub fn severity(&self) -> V3Severity {
        if let Some(override_sev) = self.severity_override {
            override_sev
        } else {
            Self::map_to_severity(self.raw_score)
        }
    }

    /// Map raw score to severity level
    pub fn map_to_severity(raw: f32) -> V3Severity {
        if raw >= 0.8 {
            V3Severity::Critical
        } else if raw >= 0.5 {
            V3Severity::High
        } else if raw >= 0.2 {
            V3Severity::Medium
        } else {
            V3Severity::Low
        }
    }
}

/// Severity levels (CVSS-compatible) - renamed to avoid conflict with findings::Severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum V3Severity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

/// CVE entry from CISA KEV or NVD
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: V3Severity,
    pub source: CveSource,
    pub affected_products: Vec<String>,
    pub published_date: Option<String>,
}

impl CveEntry {
    pub fn new(cve_id: &str, description: &str, severity: V3Severity, source: CveSource) -> Self {
        Self {
            cve_id: cve_id.to_string(),
            description: description.to_string(),
            severity,
            source,
            affected_products: Vec::new(),
            published_date: None,
        }
    }
}

/// Source of CVE data
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CveSource {
    #[default]
    NVD,
    KEV, // CISA Known Exploited Vulnerabilities - higher priority
}

/// Root cause group for deduplication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RootCauseGroup {
    pub root_cause_id: String, // SHA256 hash of AST slice
    pub findings: Vec<String>, // Finding IDs
    pub description: String,
    pub all_locations: Vec<(String, u32)>, // (file_path, line_number)
    pub severity: V3Severity,
}

impl RootCauseGroup {
    pub fn new(root_cause_id: &str, description: &str, severity: V3Severity) -> Self {
        Self {
            root_cause_id: root_cause_id.to_string(),
            findings: Vec::new(),
            description: description.to_string(),
            all_locations: Vec::new(),
            severity,
        }
    }

    pub fn add_finding(&mut self, finding_id: &str, file_path: &str, line_number: u32) {
        self.findings.push(finding_id.to_string());
        self.all_locations
            .push((file_path.to_string(), line_number));
    }
}

/// Verifier verdict in multi-verifier voting
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum VerifierVerdict {
    Confirmed,
    Rejected,
    #[default]
    Inconclusive,
}

/// Candidate patch for auto-patching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PatchCandidate {
    pub diff: String,
    pub file_path: String,
    pub applied: bool,
    pub validation_result: Option<PatchValidationResult>,
}

impl PatchCandidate {
    pub fn new(diff: &str, file_path: &str) -> Self {
        Self {
            diff: diff.to_string(),
            file_path: file_path.to_string(),
            applied: false,
            validation_result: None,
        }
    }
}

/// Result of patch validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PatchValidationResult {
    pub compiles: bool,
    pub tests_pass: bool,
    pub warnings: u32,
    pub error_message: Option<String>,
}

impl PatchValidationResult {
    pub fn success() -> Self {
        Self {
            compiles: true,
            tests_pass: true,
            warnings: 0,
            error_message: None,
        }
    }

    pub fn failure(error_message: &str) -> Self {
        Self {
            compiles: false,
            tests_pass: false,
            warnings: 0,
            error_message: Some(error_message.to_string()),
        }
    }
}

/// PoC compilation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PoCCompileResult {
    pub language: String,
    pub compiles: bool,
    pub errors: Vec<String>,
}

impl PoCCompileResult {
    pub fn success(language: &str) -> Self {
        Self {
            language: language.to_string(),
            compiles: true,
            errors: Vec::new(),
        }
    }

    pub fn failure(language: &str, errors: Vec<String>) -> Self {
        Self {
            language: language.to_string(),
            compiles: false,
            errors,
        }
    }
}

/// Project stack for CVE bootstrap
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProjectStack {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub dependencies: Vec<Dependency>,
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: DependencyEcosystem,
}

/// Dependency ecosystem
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DependencyEcosystem {
    #[default]
    CratesIo,
    Npm,
    PyPi,
    Maven,
    GoModules,
}

/// CVE cluster for threat intel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveCluster {
    pub pattern_name: String,
    pub cve_count: u32,
    pub example_cves: Vec<String>,
    pub affected_dependencies: Vec<String>,
}

/// Majority verdict from multi-verifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MajorityVerdict {
    pub final_verdict: VerifierVerdict,
    pub vote_count: HashMap<VerifierVerdict, u32>,
    pub confidence: f32,
    pub verdicts: Vec<VerifierVerdict>,
}

impl MajorityVerdict {
    pub fn new(
        final_verdict: VerifierVerdict,
        confidence: f32,
        verdicts: Vec<VerifierVerdict>,
    ) -> Self {
        let mut vote_count = HashMap::new();
        for v in &verdicts {
            *vote_count.entry(*v).or_insert(0) += 1;
        }

        Self {
            final_verdict,
            vote_count,
            confidence,
            verdicts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_rubric_constructor() {
        let rubric =
            SeverityRubric::new(0.8, 0.9, 0.7, false, AccessType::Write, BlastRadius::High);

        assert_eq!(rubric.reachability, 0.8);
        assert_eq!(rubric.attacker_control, 0.9);
        assert_eq!(rubric.preconditions_factor, 0.7);
        assert!(!rubric.auth_required);
        assert_eq!(rubric.access_type, AccessType::Write);
        assert_eq!(rubric.blast_radius, BlastRadius::High);
    }

    #[test]
    fn test_severity_rubric_clamps_values() {
        let rubric = SeverityRubric::new(
            1.5,  // Should clamp to 1.0
            -0.5, // Should clamp to 0.0
            2.0,  // Should clamp to 1.0
            false,
            AccessType::Read,
            BlastRadius::Low,
        );

        assert_eq!(rubric.reachability, 1.0);
        assert_eq!(rubric.attacker_control, 0.0);
        assert_eq!(rubric.preconditions_factor, 1.0);
    }

    #[test]
    fn test_rubric_score_mapping() {
        assert_eq!(RubricScore::map_to_severity(0.9), V3Severity::Critical);
        assert_eq!(RubricScore::map_to_severity(0.6), V3Severity::High);
        assert_eq!(RubricScore::map_to_severity(0.3), V3Severity::Medium);
        assert_eq!(RubricScore::map_to_severity(0.1), V3Severity::Low);
    }

    #[test]
    fn test_cve_entry_creation() {
        let cve = CveEntry::new(
            "CVE-2024-1234",
            "Test vulnerability",
            V3Severity::High,
            CveSource::KEV,
        );

        assert_eq!(cve.cve_id, "CVE-2024-1234");
        assert_eq!(cve.severity, V3Severity::High);
        assert_eq!(cve.source, CveSource::KEV);
    }

    #[test]
    fn test_root_cause_group() {
        let mut group =
            RootCauseGroup::new("abc123", "Missing authentication", V3Severity::Critical);

        group.add_finding("f1", "src/auth.rs", 42);
        group.add_finding("f2", "src/api.rs", 108);

        assert_eq!(group.findings.len(), 2);
        assert_eq!(group.all_locations.len(), 2);
        assert_eq!(group.all_locations[0], ("src/auth.rs".to_string(), 42));
    }

    #[test]
    fn test_patch_validation_result() {
        let success = PatchValidationResult::success();
        assert!(success.compiles);
        assert!(success.tests_pass);
        assert!(success.error_message.is_none());

        let failure = PatchValidationResult::failure("Syntax error");
        assert!(!failure.compiles);
        assert!(!failure.tests_pass);
        assert_eq!(failure.error_message, Some("Syntax error".to_string()));
    }

    #[test]
    fn test_poc_compile_result() {
        let success = PoCCompileResult::success("rust");
        assert!(success.compiles);
        assert!(success.errors.is_empty());

        let failure =
            PoCCompileResult::failure("python", vec!["SyntaxError: invalid syntax".to_string()]);
        assert!(!failure.compiles);
        assert_eq!(failure.errors.len(), 1);
    }

    #[test]
    fn test_majority_verdict() {
        let verdicts = vec![
            VerifierVerdict::Confirmed,
            VerifierVerdict::Rejected,
            VerifierVerdict::Confirmed,
        ];

        let majority = MajorityVerdict::new(VerifierVerdict::Confirmed, 0.67, verdicts.clone());

        assert_eq!(majority.final_verdict, VerifierVerdict::Confirmed);
        assert_eq!(
            majority
                .vote_count
                .get(&VerifierVerdict::Confirmed)
                .unwrap(),
            &2
        );
        assert_eq!(majority.confidence, 0.67);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let rubric =
            SeverityRubric::new(0.8, 0.9, 0.7, true, AccessType::Both, BlastRadius::Critical);

        let serialized = serde_json::to_string(&rubric).unwrap();
        let deserialized: SeverityRubric = serde_json::from_str(&serialized).unwrap();

        assert_eq!(rubric, deserialized);
    }
}
