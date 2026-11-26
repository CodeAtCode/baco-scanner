//! Scan health report - end-of-scan visibility into what actually ran
//!
//! Aggregates per-phase status, LLM outcomes, file counts, and token usage.

use crate::checkpoint::ScanPhase;
use crate::llm::metrics::LlmMetrics;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatusKind {
    #[default]
    Run,
    Skipped,
    /// The phase ran and failed. Distinct from Run so a dead phase cannot be
    /// mistaken for a clean one, and distinct from Skipped so it is not
    /// reported as a deliberate exclusion.
    Failed,
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

    /// Budget used vs cap if configured
    pub budget: BudgetStatus,

    /// LLM metrics summary (ok/failed counts)
    pub llm_ok: u64,
    pub llm_failed: u64,
}

/// Whether the scan indexed files and then analysed none of them.
///
/// The zero-LLM-call warning does not cover this: a single triage call makes the
/// call count non-zero, and the symptom it would need to report -- a clean
/// report for a scan that looked at nothing -- goes unmentioned.
pub fn scan_analysed_nothing(indexed: u64, analyzed: u64) -> bool {
    indexed > 0 && analyzed == 0
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

    /// Record a phase as failed with the reason it died.
    ///
    /// A phase that errors is neither a phase that ran nor one that was
    /// deliberately excluded. Reporting it as either is what made a dead
    /// Semgrep run indistinguishable from a clean target.
    pub fn record_phase_failed(&mut self, phase: &ScanPhase, reason: &str) {
        self.phase_status.push(PhaseStatus {
            phase: phase_name(phase),
            status: PhaseStatusKind::Failed,
            reason: Some(reason.to_string()),
        });
    }

    /// Flip an already-recorded phase to failed, keeping one entry per phase.
    pub fn mark_phase_failed(&mut self, phase: &ScanPhase, reason: &str) {
        let name = phase_name(phase);
        if let Some(entry) = self.phase_status.iter_mut().find(|ps| ps.phase == name) {
            entry.status = PhaseStatusKind::Failed;
            entry.reason = Some(reason.to_string());
        } else {
            self.record_phase_failed(phase, reason);
        }
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

    /// Set indexed file count (bulk set)
    pub fn set_indexed(&mut self, count: u64) {
        self.files.indexed = count;
    }

    /// Set analyzed file count (bulk set)
    pub fn set_analyzed(&mut self, count: u64) {
        self.files.analyzed = count;
    }

    /// Set dropped-by-size count (bulk set)
    pub fn set_dropped_by_size(&mut self, count: u64) {
        self.files.dropped_by_size = count;
    }

    /// Set chunked count (bulk set)
    pub fn set_chunked(&mut self, count: u64) {
        self.files.chunked = count;
    }

    /// Set truncated count (bulk set)
    pub fn set_truncated(&mut self, count: u64) {
        self.files.truncated = count;
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
        ];
        llm_phases.iter().all(|p| {
            self.phase_status.iter().any(|ps| {
                ps.phase == phase_name(p) && matches!(ps.status, PhaseStatusKind::Skipped)
            })
        })
    }

    /// Detect which LLM phases were skipped due to config issues
    /// Returns a vector of (phase, reason) pairs for phases that should have run but didn't
    pub fn detect_llm_config_skips(
        llm_phases_config: &crate::config::llm::LlmPhasesConfig,
        ran_phases: &[String],
    ) -> Vec<(ScanPhase, String)> {
        let mut skips = Vec::new();

        // Map of phase -> config key -> phase name for error messages
        let llm_phase_checks = [
            (
                ScanPhase::LlmStaticAnalysis,
                "static_analysis",
                "llm.phases.static_analysis",
            ),
            (ScanPhase::LlmDiscovery, "discovery", "llm.phases.discovery"),
            (
                ScanPhase::LlmVerification,
                "verification",
                "llm.phases.verification",
            ),
        ];

        for (phase, config_key, config_path) in llm_phase_checks {
            // Skip if phase already ran (it's in the ran_phases list)
            if ran_phases.contains(&phase_name(&phase)) {
                continue;
            }

            // Check if config is incomplete (no API key)
            let phase_config = match config_key {
                "static_analysis" => &llm_phases_config.static_analysis,
                "discovery" => &llm_phases_config.discovery,
                "verification" => &llm_phases_config.verification,
                _ => continue,
            };

            if phase_config.api_key.is_none() {
                skips.push((
                    phase,
                    format!("no API key configured (set {}.{})", config_path, "api_key"),
                ));
            }
        }

        skips
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
        let failed_count = self
            .phase_status
            .iter()
            .filter(|ps| matches!(ps.status, PhaseStatusKind::Failed))
            .count();

        let mut parts = Vec::new();
        if failed_count > 0 {
            parts.push(format!(
                "phases: {} run, {} skipped, {} FAILED",
                run_count, skip_count, failed_count
            ));
        } else {
            parts.push(format!("phases: {} run, {} skipped", run_count, skip_count));
        }
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
        if skip_count > 0 {
            let skipped_list: Vec<String> = self
                .phase_status
                .iter()
                .filter(|ps| matches!(ps.status, PhaseStatusKind::Skipped))
                .map(|ps| {
                    format!(
                        "{}({})",
                        ps.phase,
                        ps.reason.as_deref().unwrap_or("unknown")
                    )
                })
                .collect();
            parts.push(format!(
                "skipped ({}): {}",
                skip_count,
                skipped_list.join(", ")
            ));
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
pub fn phase_name(phase: &ScanPhase) -> String {
    match phase {
        ScanPhase::Indexing => "Indexing".to_string(),
        ScanPhase::Semgrep => "Semgrep".to_string(),
        ScanPhase::CweRouting => "CweRouting".to_string(),
        ScanPhase::LlmStaticAnalysis => "LlmStaticAnalysis".to_string(),
        ScanPhase::LlmDiscovery => "LlmDiscovery".to_string(),
        ScanPhase::LlmVerification => "LlmVerification".to_string(),
        ScanPhase::Validate => "Validate".to_string(),
        ScanPhase::TicketCrossRef => "TicketCrossRef".to_string(),
        ScanPhase::GitAnalysis => "GitAnalysis".to_string(),
        ScanPhase::CrossFileAnalysis => "CrossFileAnalysis".to_string(),
        ScanPhase::ConfidenceScoring => "ConfidenceScoring".to_string(),
        ScanPhase::AiAggregation => "AiAggregation".to_string(),
        ScanPhase::Reporting => "Reporting".to_string(),
        ScanPhase::RootCauseDedup => "RootCauseDedup".to_string(),
        ScanPhase::CveBootstrap => "CveBootstrap".to_string(),
        ScanPhase::Complete => "Complete".to_string(),
        ScanPhase::Error => "Error".to_string(),
    }
}

/// Builder-style helper for constructing ScanHealth from LlmMetrics
/// Returns (ok_calls, failed_calls)
pub fn from_llm_metrics(metrics: &LlmMetrics) -> (u64, u64) {
    (metrics.total_success, metrics.total_failed)
}

/// Phases that a configuration flag turns off.
///
/// The recording pass marks every planned phase as run, so without this the
/// operator sees a phase listed as executed when they had disabled it.
pub fn detect_config_skips(config: &crate::config::ScannerConfig) -> Vec<(ScanPhase, String)> {
    let checks: [(ScanPhase, bool, &str); 4] = [
        (
            ScanPhase::CweRouting,
            config.router.enabled,
            "router.enabled",
        ),
        (
            ScanPhase::ConfidenceScoring,
            config.scanner.performance.enable_confidence_refinement,
            "scanner.performance.enable_confidence_refinement",
        ),
        (
            ScanPhase::CveBootstrap,
            config.scanner.performance.enable_cve_bootstrap,
            "scanner.performance.enable_cve_bootstrap",
        ),
        (
            ScanPhase::RootCauseDedup,
            config.scanner.performance.enable_root_cause_dedup,
            "scanner.performance.enable_root_cause_dedup",
        ),
    ];

    checks
        .into_iter()
        .filter(|(_, enabled, _)| !enabled)
        .map(|(phase, _, key)| (phase, format!("disabled by `{key} = false`")))
        .collect()
}

impl ScanHealth {
    /// Apply a list of skips over the recorded phase statuses.
    ///
    /// The initial pass records every planned phase as run, so a skip has to
    /// overwrite that entry rather than add a second one.
    pub fn apply_skips(&mut self, skips: &[(ScanPhase, String)]) {
        for (phase, reason) in skips {
            match self
                .phase_status
                .iter_mut()
                .find(|ps| ps.phase == phase_name(phase))
            {
                Some(entry) => {
                    entry.status = PhaseStatusKind::Skipped;
                    entry.reason = Some(reason.clone());
                }
                None => self.record_phase_skipped(phase, reason),
            }
        }
    }
}
