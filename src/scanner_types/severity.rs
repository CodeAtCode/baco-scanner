//! Severity rubric and scoring types

use serde::{Deserialize, Serialize};

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

/// Severity levels (CVSS-compatible) - renamed to avoid conflict with findings::Severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum V3Severity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization_roundtrip() {
        let rubric =
            SeverityRubric::new(0.8, 0.9, 0.7, true, AccessType::Both, BlastRadius::Critical);

        let serialized = serde_json::to_string(&rubric).unwrap();
        let deserialized: SeverityRubric = serde_json::from_str(&serialized).unwrap();

        assert_eq!(rubric, deserialized);
    }
}
