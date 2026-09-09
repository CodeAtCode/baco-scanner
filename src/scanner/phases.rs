use crate::checkpoint::ScanPhase;
use crate::config;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use indicatif::ProgressBar;

pub mod llm_phases;
mod other_phases;

/// Configuration for run_phase execution
pub struct PhaseConfig<'a> {
    pub phase: &'a ScanPhase,
    pub findings: Vec<VulnerabilityFinding>,
    pub pb: &'a ProgressBar,
    pub analyzed_files: &'a [String],
    pub metrics_tracker: &'a LlmMetricsTracker,
    pub target_path: &'a std::path::Path,
    pub config: &'a config::ScannerConfig,
    pub project_stack: &'a Option<crate::scanner_types::project::ProjectStack>,
}

/// Macro to reduce boilerplate in phase dispatch
/// Calls the handler and wraps (findings, files) into the full result tuple
macro_rules! dispatch_phase {
    ($scanner:expr, $handler:expr, $cfg:expr) => {{
        let (findings, files) = $handler($scanner, $cfg).await?;
        Ok((findings, files, Vec::new()))
    }};
}

/// Execute a single scan phase and return updated findings and analyzed files
/// For LlmVerification phase, also returns rejected findings (FalsePositives with reasons)
pub async fn run_phase(
    scanner: &super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(
    Vec<VulnerabilityFinding>,
    Vec<String>,
    Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
)> {
    use ScanPhase::*;

    match cfg.phase {
        Indexing => dispatch_phase!(scanner, other_phases::run_indexing, cfg),
        Semgrep => dispatch_phase!(scanner, other_phases::run_semgrep, cfg),
        CpgSlice => dispatch_phase!(scanner, other_phases::run_cpg_slice, cfg),
        LlmStaticAnalysis => dispatch_phase!(scanner, llm_phases::run_llm_static_analysis, cfg),
        LlmDiscovery => dispatch_phase!(scanner, llm_phases::run_llm_discovery, cfg),
        LlmVerification => llm_phases::run_llm_verification(scanner, cfg).await,
        Validate => dispatch_phase!(scanner, other_phases::run_validate, cfg),
        SecurityAgentVerification => {
            dispatch_phase!(scanner, llm_phases::run_security_agent_verification, cfg)
        }
        TicketCrossRef => dispatch_phase!(scanner, other_phases::run_ticket_cross_ref, cfg),
        GitAnalysis => dispatch_phase!(scanner, other_phases::run_git_analysis, cfg),
        CrossFileAnalysis => dispatch_phase!(scanner, other_phases::run_cross_file_analysis, cfg),
        ConfidenceScoring => dispatch_phase!(scanner, other_phases::run_confidence_scoring, cfg),
        AiAggregation => dispatch_phase!(scanner, other_phases::run_ai_aggregation, cfg),
        Reporting => {
            let (findings, files, _rejected) = other_phases::run_reporting(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ThreatModeling => dispatch_phase!(scanner, other_phases::run_threat_modeling, cfg),
        RootCauseDedup => dispatch_phase!(scanner, other_phases::run_root_cause_dedup, cfg),
        MultiVerifier => dispatch_phase!(scanner, other_phases::run_multi_verifier, cfg),
        AutoPatching => dispatch_phase!(scanner, other_phases::run_auto_patching, cfg),
        CveBootstrap => dispatch_phase!(scanner, other_phases::run_cve_bootstrap, cfg),
        PocCompiler => dispatch_phase!(scanner, other_phases::run_poc_compiler, cfg),
        VariantSearch => dispatch_phase!(scanner, other_phases::run_variant_search, cfg),
        CweRouting => dispatch_phase!(scanner, other_phases::run_cwe_routing, cfg),
        RuleSynthesis => dispatch_phase!(scanner, other_phases::run_rule_synthesis, cfg),
        ExploitSynth => dispatch_phase!(scanner, other_phases::run_exploit_synth, cfg),
        Complete | Error => {
            let (findings, files) = other_phases::run_default(cfg).await?;
            Ok((findings, files, Vec::new()))
        }
    }
}
