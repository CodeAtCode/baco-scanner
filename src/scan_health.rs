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

/// Per-phase spend tracking (tokens + optional cost)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhaseSpend {
    pub phase: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Cost in same currency as pricing config (empty if no pricing provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
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

    /// Per-phase spend (tokens + optional cost)
    #[serde(default)]
    pub phase_spend: Vec<PhaseSpend>,

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
            (
                ScanPhase::SecurityAgentVerification,
                "security_agent_verification",
                "llm.phases.security_agent_verification",
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
                "security_agent_verification" => &llm_phases_config.security_agent_verification,
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

    /// Compute per-phase spend from operation metrics and pricing table
    /// Returns a vector of PhaseSpend entries, one per unique phase
    pub fn compute_phase_spend(
        operation_metrics: &HashMap<String, crate::llm_metrics::OperationMetrics>,
        pricing: Option<&HashMap<String, crate::config::ModelPricing>>,
    ) -> Vec<PhaseSpend> {
        use std::collections::HashMap as StdHashMap;

        // Aggregate tokens by phase
        let mut phase_tokens: StdHashMap<String, (u64, u64)> = StdHashMap::new();
        for op in operation_metrics.values() {
            let entry = phase_tokens.entry(op.phase.clone()).or_insert((0, 0));
            entry.0 += op.prompt_tokens;
            entry.1 += op.completion_tokens;
        }

        // Build PhaseSpend entries
        let mut spend = Vec::new();
        for (phase, (prompt, completion)) in phase_tokens {
            let total = prompt.saturating_add(completion);
            let cost = pricing.and_then(|p| {
                // Try to find pricing for any model - use first match
                p.values()
                    .next()
                    .map(|model_pricing| model_pricing.cost(prompt, completion))
            });

            spend.push(PhaseSpend {
                phase,
                prompt_tokens: prompt,
                completion_tokens: completion,
                total_tokens: total,
                cost,
            });
        }

        // Sort by phase name for deterministic output
        spend.sort_by(|a, b| a.phase.cmp(&b.phase));
        spend
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
        parts.push(format!("phases: {} run, {} skipped", run_count, skip_count));
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
pub fn phase_name(phase: &ScanPhase) -> String {
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
/// Returns (ok_calls, failed_calls)
pub fn from_llm_metrics(
    metrics: &LlmMetrics,
    _pricing: Option<&HashMap<String, crate::config::ModelPricing>>,
) -> (u64, u64) {
    (metrics.total_success, metrics.total_failed)
}
