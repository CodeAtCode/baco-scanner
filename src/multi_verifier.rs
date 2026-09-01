//! Multi-Verifier Module
//!
//! ⚠️ EXPERIMENTAL STUB — DISABLED BY DEFAULT
//!
//! This module implements a hash-based stub for majority voting verification.
//! The verdicts are NOT real evidence — they are computed as `simple_hash(finding_id) % 3`
//! plus simple keyword matches (TODO/FIXME → Rejected, unsafe/spawn → Confirmed).
//!
//! This is a placeholder implementation disabled by default (`enable_multi_verifier=false`)
//! until proper verification logic is implemented.

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
    pub api_failure_count: Arc<AtomicU32>,
    pub total_verifications: Arc<AtomicU32>,
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

    pub fn run_single_verifier(
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

        if hash % 3 == 0 {
            Ok(VerifierVerdict::Confirmed)
        } else if hash % 3 == 1 {
            Ok(VerifierVerdict::Rejected)
        } else {
            Ok(VerifierVerdict::Inconclusive)
        }
    }

    pub fn compute_majority(&self, verdicts: &[VerifierVerdict]) -> MajorityVerdict {
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

    pub fn is_circuit_broken(&self) -> bool {
        let failures = self.api_failure_count.load(Ordering::SeqCst);
        let total = self.total_verifications.load(Ordering::SeqCst);

        if total == 0 {
            return false;
        }

        let failure_rate = failures as f32 / total as f32;
        failure_rate > self.config.circuit_breaker_threshold
    }

    pub fn simple_hash(s: &str) -> u32 {
        s.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32))
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
        self.verify_batch_with_evidence(findings)
    }

    /// Verify multiple findings in batch with evidence collection
    pub fn verify_batch_with_evidence(
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

            // Add evidence for every verified finding (confirmed or inconclusive)
            let mut finding_with_evidence = finding.clone();
            finding_with_evidence.add_evidence(
                crate::evidence::EvidenceSource::IndependentVerifier("multi_verifier".into()),
                1.0,
                format!("Multi-verifier verdict: {:?}", verdict.final_verdict),
            );

            // Keep findings that are confirmed or inconclusive, reject confirmed false positives
            match verdict.final_verdict {
                VerifierVerdict::Confirmed => {
                    verified_findings.push(finding_with_evidence);
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
                    verified_findings.push(finding_with_evidence);
                }
            }
        }

        verified_findings
    }
}
