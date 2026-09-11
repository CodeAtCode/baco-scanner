//! Scan health report - end-of-scan visibility into what actually ran
//!
//! Aggregates per-phase status, LLM outcomes, file counts, and token usage.

use crate::checkpoint::ScanPhase;
use crate::llm_metrics::LlmMetrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a single scan phase
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhaseStatus {
    pub phase: String,
    pub status: PhaseStatusKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatusKind {
    #[default]
    Run,
    Skipped,
}

/// LLM call outcome classification
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub enum LlmOutcomeClass {
    #[default]
    Ok,
    AuthFailure,
    Timeout,
    RateLimit,
    OtherError,
}

/// File processing counters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCounters {
    pub indexed: u64,
    pub analyzed: u64,
    pub dropped_by_size: u64,
    pub chunked: u64,
    pub truncated: u64,
}

/// Token usage per phase
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub phase: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

/// Budget tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetStatus {
    pub cap_maybe: Option<u64>,
    pub used: u64,
    pub pct_of_cap: Option<f64>,
}

/// Scan health report - aggregates visibility into what ran during a scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanHealth {
    /// Per-phase status (run | skipped + reason string)
    pub phase_status: Vec<PhaseStatus>,

    /// LLM call outcomes by error class
    pub llm_outcomes: HashMap<String, u64>,

    /// File processing counters
    pub files: FileCounters,

    /// Token usage per phase
    pub tokens_by_phase: Vec<TokenUsage>,

    /// Total token usage
    pub total_tokens: u64,

    /// Budget used vs cap if configured
    pub budget: BudgetStatus,

    /// LLM metrics summary (ok/failed counts)
    pub llm_ok: u64,
    pub llm_failed: u64,
}

impl ScanHealth {
    /// Create a new empty health report
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a phase as run
    pub fn record_phase_run(&mut self, phase: &ScanPhase) {
        self.phase_status.push(PhaseStatus {
            phase: phase_name(phase),
            status: PhaseStatusKind::Run,
            reason: None,
        });
    }

    /// Record a phase as skipped with reason
    pub fn record_phase_skipped(&mut self, phase: &ScanPhase, reason: &str) {
        self.phase_status.push(PhaseStatus {
            phase: phase_name(phase),
            status: PhaseStatusKind::Skipped,
            reason: Some(reason.to_string()),
        });
    }

    /// Record an LLM outcome by class
    pub fn record_llm_outcome(&mut self, outcome_class: &LlmOutcomeClass) {
        let key = match outcome_class {
            LlmOutcomeClass::Ok => "ok".to_string(),
            LlmOutcomeClass::AuthFailure => "auth_failure".to_string(),
            LlmOutcomeClass::Timeout => "timeout".to_string(),
            LlmOutcomeClass::RateLimit => "rate_limit".to_string(),
            LlmOutcomeClass::OtherError => "other_error".to_string(),
        };
        *self.llm_outcomes.entry(key).or_default() += 1;
    }

    /// Increment indexed file counter
    pub fn increment_indexed(&mut self) {
        self.files.indexed += 1;
    }

    /// Set indexed file count (bulk set)
    pub fn set_indexed(&mut self, count: u64) {
        self.files.indexed = count;
    }

    /// Increment analyzed file counter
    pub fn increment_analyzed(&mut self) {
        self.files.analyzed += 1;
    }

    /// Set analyzed file count (bulk set)
    pub fn set_analyzed(&mut self, count: u64) {
        self.files.analyzed = count;
    }

    /// Increment dropped-by-size counter
    pub fn increment_dropped_by_size(&mut self) {
        self.files.dropped_by_size += 1;
    }

    /// Set dropped-by-size count (bulk set)
    pub fn set_dropped_by_size(&mut self, count: u64) {
        self.files.dropped_by_size = count;
    }

    /// Increment chunked counter
    pub fn increment_chunked(&mut self) {
        self.files.chunked += 1;
    }

    /// Set chunked count (bulk set)
    pub fn set_chunked(&mut self, count: u64) {
        self.files.chunked = count;
    }

    /// Increment truncated counter
    pub fn increment_truncated(&mut self) {
        self.files.truncated += 1;
    }

    /// Set truncated count (bulk set)
    pub fn set_truncated(&mut self, count: u64) {
        self.files.truncated = count;
    }

    /// Record token usage for a phase
    pub fn record_tokens(&mut self, phase: &ScanPhase, prompt: u64, completion: u64) {
        let total = prompt.saturating_add(completion);
        self.tokens_by_phase.push(TokenUsage {
            phase: phase_name(phase),
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
        });
        self.total_tokens = self.total_tokens.saturating_add(total);
    }

    /// Set budget cap and used amount
    pub fn set_budget(&mut self, cap: Option<u64>, used: u64) {
        self.budget = BudgetStatus {
            cap_maybe: cap,
            used,
            pct_of_cap: cap.map(|c| (used as f64) / (c as f64) * 100.0),
        };
    }

    /// Set LLM success/fail counts from metrics
    pub fn set_llm_counts(&mut self, ok: u64, failed: u64) {
        self.llm_ok = ok;
        self.llm_failed = failed;
    }

    /// Check if all LLM phases were skipped
    pub fn all_llm_phases_skipped(&self) -> bool {
        let llm_phases = [
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::SecurityAgentVerification,
        ];
        llm_phases.iter().all(|p| {
            self.phase_status.iter().any(|ps| {
                ps.phase == phase_name(p) && matches!(ps.status, PhaseStatusKind::Skipped)
            })
        })
    }

    /// Build a summary string for console output
    pub fn summary(&self) -> String {
        let run_count = self
            .phase_status
            .iter()
            .filter(|ps| matches!(ps.status, PhaseStatusKind::Run))
            .count();
        let skip_count = self
            .phase_status
            .iter()
            .filter(|ps| matches!(ps.status, PhaseStatusKind::Skipped))
            .count();

        let mut parts = Vec::new();
        parts.push(format!("phases: {}/{} run/skipped", run_count, skip_count));
        parts.push(format!(
            "files: {} indexed, {} analyzed",
            self.files.indexed, self.files.analyzed
        ));
        if self.files.dropped_by_size > 0 {
            parts.push(format!("dropped_by_size: {}", self.files.dropped_by_size));
        }
        if self.files.chunked > 0 {
            parts.push(format!("chunked: {}", self.files.chunked));
        }
        if self.files.truncated > 0 {
            parts.push(format!("truncated: {}", self.files.truncated));
        }
        parts.push(format!(
            "llm: {}/{} ok/failed",
            self.llm_ok, self.llm_failed
        ));
        if self.total_tokens > 0 {
            parts.push(format!("tokens: {}", self.total_tokens));
        }
        if let Some(cap) = self.budget.cap_maybe {
            parts.push(format!(
                "budget: {}/{} ({:.1}%)",
                self.budget.used,
                cap,
                self.budget.pct_of_cap.unwrap_or(0.0)
            ));
        }

        parts.join(" | ")
    }

    /// Build the blind-marker line if applicable
    pub fn blind_marker(&self) -> Option<String> {
        if self.all_llm_phases_skipped() && self.llm_ok == 0 {
            Some("SCAN PARTIALLY BLIND: LLM phases skipped — check config".to_string())
        } else {
            None
        }
    }
}

/// Convert ScanPhase to string name
fn phase_name(phase: &ScanPhase) -> String {
    match phase {
        ScanPhase::Indexing => "Indexing".to_string(),
        ScanPhase::Semgrep => "Semgrep".to_string(),
        ScanPhase::CweRouting => "CweRouting".to_string(),
        ScanPhase::CpgSlice => "CpgSlice".to_string(),
        ScanPhase::LlmStaticAnalysis => "LlmStaticAnalysis".to_string(),
        ScanPhase::LlmDiscovery => "LlmDiscovery".to_string(),
        ScanPhase::LlmVerification => "LlmVerification".to_string(),
        ScanPhase::TicketCrossRef => "TicketCrossRef".to_string(),
        ScanPhase::GitAnalysis => "GitAnalysis".to_string(),
        ScanPhase::CrossFileAnalysis => "CrossFileAnalysis".to_string(),
        ScanPhase::ConfidenceScoring => "ConfidenceScoring".to_string(),
        ScanPhase::AiAggregation => "AiAggregation".to_string(),
        ScanPhase::Reporting => "Reporting".to_string(),
        ScanPhase::ThreatModeling => "ThreatModeling".to_string(),
        ScanPhase::RootCauseDedup => "RootCauseDedup".to_string(),
        ScanPhase::MultiVerifier => "MultiVerifier".to_string(),
        ScanPhase::AutoPatching => "AutoPatching".to_string(),
        ScanPhase::CveBootstrap => "CveBootstrap".to_string(),
        ScanPhase::PocCompiler => "PocCompiler".to_string(),
        ScanPhase::VariantSearch => "VariantSearch".to_string(),
        ScanPhase::SecurityAgentVerification => "SecurityAgentVerification".to_string(),
        ScanPhase::RuleSynthesis => "RuleSynthesis".to_string(),
        ScanPhase::Validate => "Validate".to_string(),
        ScanPhase::ExploitSynth => "ExploitSynth".to_string(),
        ScanPhase::Complete => "Complete".to_string(),
        ScanPhase::Error => "Error".to_string(),
    }
}

/// Builder-style helper for constructing ScanHealth from LlmMetrics
pub fn from_llm_metrics(metrics: &LlmMetrics) -> (u64, u64) {
    (metrics.total_success, metrics.total_failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_health_default() {
        let health = ScanHealth::default();
        assert!(health.phase_status.is_empty());
        assert_eq!(health.files.indexed, 0);
        assert_eq!(health.total_tokens, 0);
    }

    #[test]
    fn test_record_phase_run() {
        let mut health = ScanHealth::new();
        health.record_phase_run(&ScanPhase::Indexing);
        assert_eq!(health.phase_status.len(), 1);
        assert!(matches!(
            health.phase_status[0].status,
            PhaseStatusKind::Run
        ));
        assert_eq!(health.phase_status[0].phase, "Indexing");
    }

    #[test]
    fn test_record_phase_skipped() {
        let mut health = ScanHealth::new();
        health.record_phase_skipped(
            &ScanPhase::LlmDiscovery,
            "incomplete llm.phases.discovery config",
        );
        assert_eq!(health.phase_status.len(), 1);
        assert!(matches!(
            health.phase_status[0].status,
            PhaseStatusKind::Skipped
        ));
        assert_eq!(
            health.phase_status[0].reason,
            Some("incomplete llm.phases.discovery config".to_string())
        );
    }

    #[test]
    fn test_file_counters() {
        let mut health = ScanHealth::new();
        health.set_indexed(100);
        health.set_analyzed(80);
        health.set_dropped_by_size(5);
        health.set_chunked(10);
        health.set_truncated(3);

        assert_eq!(health.files.indexed, 100);
        assert_eq!(health.files.analyzed, 80);
        assert_eq!(health.files.dropped_by_size, 5);
        assert_eq!(health.files.chunked, 10);
        assert_eq!(health.files.truncated, 3);
    }

    #[test]
    fn test_llm_outcomes() {
        let mut health = ScanHealth::new();
        health.record_llm_outcome(&LlmOutcomeClass::Ok);
        health.record_llm_outcome(&LlmOutcomeClass::Ok);
        health.record_llm_outcome(&LlmOutcomeClass::AuthFailure);

        assert_eq!(health.llm_outcomes.get("ok"), Some(&2));
        assert_eq!(health.llm_outcomes.get("auth_failure"), Some(&1));
    }

    #[test]
    fn test_token_recording() {
        let mut health = ScanHealth::new();
        health.record_tokens(&ScanPhase::LlmDiscovery, 100, 50);
        health.record_tokens(&ScanPhase::LlmVerification, 200, 100);

        assert_eq!(health.total_tokens, 450);
        assert_eq!(health.tokens_by_phase.len(), 2);
        assert_eq!(health.tokens_by_phase[0].total_tokens, 150);
        assert_eq!(health.tokens_by_phase[1].total_tokens, 300);
    }

    #[test]
    fn test_budget_status() {
        let mut health = ScanHealth::new();
        health.set_budget(Some(1000), 250);

        assert_eq!(health.budget.cap_maybe, Some(1000));
        assert_eq!(health.budget.used, 250);
        assert!((health.budget.pct_of_cap.unwrap() - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_all_llm_phases_skipped() {
        let mut health = ScanHealth::new();
        // Record all LLM phases as skipped
        health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
        health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
        health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
        health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");

        assert!(health.all_llm_phases_skipped());
    }

    #[test]
    fn test_blind_marker() {
        let mut health = ScanHealth::new();
        // No LLM phases skipped yet
        assert!(health.blind_marker().is_none());

        // Skip all LLM phases with no successes
        health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
        health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
        health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
        health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");
        health.set_llm_counts(0, 0);

        assert_eq!(
            health.blind_marker(),
            Some("SCAN PARTIALLY BLIND: LLM phases skipped — check config".to_string())
        );
    }

    #[test]
    fn test_summary() {
        let mut health = ScanHealth::new();
        health.record_phase_run(&ScanPhase::Indexing);
        health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
        health.set_indexed(50);
        health.set_analyzed(40);
        health.set_llm_counts(0, 0);

        let summary = health.summary();
        assert!(summary.contains("phases: 1/1 run/skipped"));
        assert!(summary.contains("files: 50 indexed, 40 analyzed"));
        assert!(summary.contains("llm: 0/0 ok/failed"));
    }

    #[test]
    fn test_serialization() {
        let mut health = ScanHealth::new();
        health.record_phase_run(&ScanPhase::Indexing);
        health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
        health.set_indexed(100);
        health.set_llm_counts(5, 2);

        let json = serde_json::to_string(&health).unwrap();
        let parsed: ScanHealth = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.phase_status.len(), 2);
        assert_eq!(parsed.files.indexed, 100);
        assert_eq!(parsed.llm_ok, 5);
        assert_eq!(parsed.llm_failed, 2);
    }
}
