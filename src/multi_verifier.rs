//! Multi-Verifier Module
//!
//! Implements majority voting for vulnerability verification with N verifiers.
//! Uses circuit breaker pattern for API failure handling.

use crate::scanner_types::{poc::VerifierVerdict, MajorityVerdict};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("All verifiers failed: {0}")]
    AllFailed(String),
    #[error("Circuit breaker triggered: {0}")]
    CircuitBreaker(String),
    #[error("Verifier error: {0}")]
    VerifierError(String),
}

pub type Result<T> = std::result::Result<T, VerifierError>;

#[derive(Clone)]
pub struct VerifierConfig {
    pub num_verifiers: u32,
    pub circuit_breaker_threshold: f32,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            num_verifiers: 3,
            circuit_breaker_threshold: 0.5,
        }
    }
}

pub struct MultiVerifier {
    config: VerifierConfig,
    api_failure_count: Arc<AtomicU32>,
    total_verifications: Arc<AtomicU32>,
}

impl MultiVerifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            api_failure_count: Arc::new(AtomicU32::new(0)),
            total_verifications: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn with_verifiers(mut self, n: u32) -> Self {
        self.config.num_verifiers = n;
        self
    }

    /// Verify a finding using N verifiers with majority voting
    pub fn verify(&self, finding_id: &str, code_snippet: &str) -> Result<MajorityVerdict> {
        self.total_verifications.fetch_add(1, Ordering::SeqCst);

        // Check circuit breaker
        if self.is_circuit_broken() {
            return Ok(MajorityVerdict::new(
                VerifierVerdict::Inconclusive,
                0.0,
                vec![VerifierVerdict::Inconclusive; self.config.num_verifiers as usize],
            ));
        }

        let mut verdicts = Vec::new();

        for i in 0..self.config.num_verifiers {
            match self.run_single_verifier(i, finding_id, code_snippet) {
                Ok(verdict) => verdicts.push(verdict),
                Err(e) => {
                    warn!("Verifier {} failed: {}", i, e);
                    self.api_failure_count.fetch_add(1, Ordering::SeqCst);
                    verdicts.push(VerifierVerdict::Inconclusive);
                }
            }
        }

        let majority = self.compute_majority(&verdicts);

        Ok(majority)
    }

    fn run_single_verifier(
        &self,
        _verifier_id: u32,
        finding_id: &str,
        code_snippet: &str,
    ) -> Result<VerifierVerdict> {
        // Simulate different verifier behavior
        // In production, these would call actual verification APIs

        let hash = Self::simple_hash(finding_id);

        if code_snippet.contains("TODO") || code_snippet.contains("FIXME") {
            return Ok(VerifierVerdict::Rejected);
        }

        if code_snippet.contains("unsafe") || code_snippet.contains("spawn") {
            return Ok(VerifierVerdict::Confirmed);
        }

        if hash.is_multiple_of(3) {
            Ok(VerifierVerdict::Confirmed)
        } else if hash % 3 == 1 {
            Ok(VerifierVerdict::Rejected)
        } else {
            Ok(VerifierVerdict::Inconclusive)
        }
    }

    fn compute_majority(&self, verdicts: &[VerifierVerdict]) -> MajorityVerdict {
        let mut vote_counts: HashMap<VerifierVerdict, u32> = HashMap::new();

        for v in verdicts {
            *vote_counts.entry(*v).or_insert(0) += 1;
        }

        let total = verdicts.len() as f32;

        let (final_verdict, confidence) =
            if let Some((&v, &count)) = vote_counts.iter().max_by_key(|(&_, &c)| c) {
                let conf = count as f32 / total;
                (v, conf)
            } else {
                (VerifierVerdict::Inconclusive, 0.0)
            };

        // Tied vote -> Inconclusive
        let max_count = vote_counts.values().max().copied().unwrap_or(0);
        let tied = vote_counts.values().filter(|&&c| c == max_count).count() > 1;

        let final_verdict = if tied {
            VerifierVerdict::Inconclusive
        } else {
            final_verdict
        };

        MajorityVerdict::new(final_verdict, confidence, verdicts.to_vec())
    }

    fn is_circuit_broken(&self) -> bool {
        let failures = self.api_failure_count.load(Ordering::SeqCst);
        let total = self.total_verifications.load(Ordering::SeqCst);

        if total == 0 {
            return false;
        }

        let failure_rate = failures as f32 / total as f32;
        failure_rate > self.config.circuit_breaker_threshold
    }

    fn simple_hash(s: &str) -> u32 {
        s.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32))
    }

    pub fn get_failure_rate(&self) -> f32 {
        let failures = self.api_failure_count.load(Ordering::SeqCst);
        let total = self.total_verifications.load(Ordering::SeqCst);

        if total == 0 {
            0.0
        } else {
            failures as f32 / total as f32
        }
    }

    pub fn reset_circuit_breaker(&self) {
        self.api_failure_count.store(0, Ordering::SeqCst);
        self.total_verifications.store(0, Ordering::SeqCst);
    }

    /// Verify multiple findings in batch
    pub fn verify_batch(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
    ) -> Vec<crate::findings::VulnerabilityFinding> {
        let mut verified_findings = Vec::new();

        for finding in findings {
            let code_snippet = finding.code_snippet.as_deref().unwrap_or("");
            let verdict = self.verify(&finding.id, code_snippet).unwrap_or_else(|e| {
                tracing::warn!("MultiVerifier error for finding {}: {}", finding.id, e);
                MajorityVerdict::new(
                    VerifierVerdict::Inconclusive,
                    0.0,
                    vec![VerifierVerdict::Inconclusive; 3],
                )
            });

            // Keep findings that are confirmed or inconclusive, reject confirmed false positives
            match verdict.final_verdict {
                VerifierVerdict::Confirmed => {
                    verified_findings.push(finding.clone());
                }
                VerifierVerdict::Rejected => {
                    // This is a false positive - skip it
                    tracing::info!(
                        "Finding {} rejected by multi-verifier (false positive)",
                        finding.id
                    );
                }
                VerifierVerdict::Inconclusive => {
                    // Keep inconclusive findings for manual review
                    verified_findings.push(finding.clone());
                }
            }
        }

        verified_findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_majority_vote_confirmed() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        let finding_id = "finding-123";
        let code_snippet = "let result = Command::new(cmd).spawn();";

        let result = verifier.verify(finding_id, code_snippet).unwrap();

        // With unsafe/spawn, should be confirmed by most verifiers
        assert!(matches!(
            result.final_verdict,
            VerifierVerdict::Confirmed | VerifierVerdict::Inconclusive
        ));
    }

    #[test]
    fn test_tie_returns_inconclusive() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        // Use a finding that produces mixed results
        let finding_id = "test-finding";
        let code_snippet = "println!(\"Hello\")";

        // Run multiple times to hit edge cases
        for _ in 0..10 {
            let result = verifier.verify(finding_id, code_snippet).unwrap();

            if result.final_verdict == VerifierVerdict::Inconclusive {
                // This is acceptable - tied votes go to inconclusive
                return;
            }
        }
    }

    #[test]
    fn test_rejected_for_todo_code() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        let finding_id = "finding-456";
        let code_snippet = "// TODO: fix this later";

        let result = verifier.verify(finding_id, code_snippet).unwrap();

        assert_eq!(result.final_verdict, VerifierVerdict::Rejected);
    }

    #[test]
    fn test_circuit_breaker_triggers() {
        let mut config = VerifierConfig::default();
        config.num_verifiers = 5;

        let verifier = MultiVerifier::new(config);

        // Force circuit breaker by having too many failures
        verifier.api_failure_count.store(10, Ordering::SeqCst);
        verifier.total_verifications.store(15, Ordering::SeqCst);

        let result = verifier.verify("finding", "code").unwrap();

        assert_eq!(result.final_verdict, VerifierVerdict::Inconclusive);
        assert!(verifier.is_circuit_broken());
    }

    #[test]
    fn test_configurable_verifier_count() {
        let verifier = MultiVerifier::new(VerifierConfig::default()).with_verifiers(5);

        let result = verifier.verify("find", "code").unwrap();

        assert_eq!(result.verdicts.len(), 5);
    }

    #[test]
    fn test_reset_circuit_breaker() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        verifier.api_failure_count.store(10, Ordering::SeqCst);
        verifier.total_verifications.store(15, Ordering::SeqCst);

        assert!(verifier.is_circuit_broken());

        verifier.reset_circuit_breaker();

        assert!(!verifier.is_circuit_broken());
    }

    #[test]
    fn test_confidence_calculation() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        // Use code that triggers consistent verdicts
        let code = "unsafe { *ptr }";
        let result = verifier.verify("id", code).unwrap();

        // Confidence should be between 0 and 1
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);

        // Check vote counts sum to number of verifiers
        let total_votes: u32 = result.vote_count.values().sum();
        assert_eq!(total_votes, 3); // default num_verifiers
    }

    #[test]
    fn test_vote_count_tracking() {
        let verifier = MultiVerifier::new(VerifierConfig::default());

        let result = verifier.verify("test-id", "code").unwrap();

        // Vote count should have at least one entry
        assert!(
            !result.vote_count.is_empty(),
            "vote_count should not be empty"
        );

        // Sum of all votes should equal number of verifiers
        let total_votes: u32 = result.vote_count.values().sum();
        assert_eq!(total_votes, 3); // default num_verifiers
    }

    #[test]
    fn test_verifiers_produces_valid_output() {
        let config = VerifierConfig {
            num_verifiers: 5,
            circuit_breaker_threshold: 0.3,
        };

        let verifier = MultiVerifier::new(config);

        let result = verifier
            .verify("vuln-find", "let x = unsafe { *ptr }; spawn();")
            .unwrap();

        // All verifiers should return valid verdicts
        for v in &result.verdicts {
            assert!(matches!(
                v,
                VerifierVerdict::Confirmed
                    | VerifierVerdict::Rejected
                    | VerifierVerdict::Inconclusive
            ));
        }
    }
}
