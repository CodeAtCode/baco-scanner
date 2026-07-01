//! Project and dependency-related types

use serde::{Deserialize, Serialize};

use super::poc::VerifierVerdict;
use std::collections::HashMap;

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

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: DependencyEcosystem,
}

/// Project stack for CVE bootstrap
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProjectStack {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub dependencies: Vec<Dependency>,
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
}
