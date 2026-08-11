use crate::checkpoint::ScanPhase;
use crate::config;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use indicatif::ProgressBar;

mod llm_phases;
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

/// Execute a single scan phase and return updated findings and analyzed files
pub async fn run_phase(
    scanner: &super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let phase = cfg.phase.clone();
    match phase {
        ScanPhase::Indexing => other_phases::run_indexing(scanner, cfg).await,
        ScanPhase::Semgrep => other_phases::run_semgrep(scanner, cfg).await,
        ScanPhase::CpgSlice => other_phases::run_cpg_slice(scanner, cfg).await,
        ScanPhase::LlmStaticAnalysis => llm_phases::run_llm_static_analysis(scanner, cfg).await,
        ScanPhase::LlmDiscovery => llm_phases::run_llm_discovery(scanner, cfg).await,
        ScanPhase::LlmVerification => llm_phases::run_llm_verification(scanner, cfg).await,
        ScanPhase::Validate => other_phases::run_validate(scanner, cfg).await,
        ScanPhase::SecurityAgentVerification => {
            llm_phases::run_security_agent_verification(scanner, cfg).await
        }
        ScanPhase::TicketCrossRef => other_phases::run_ticket_cross_ref(scanner, cfg).await,
        ScanPhase::GitAnalysis => other_phases::run_git_analysis(scanner, cfg).await,
        ScanPhase::CrossFileAnalysis => other_phases::run_cross_file_analysis(scanner, cfg).await,
        ScanPhase::ConfidenceScoring => other_phases::run_confidence_scoring(scanner, cfg).await,
        ScanPhase::AiAggregation => other_phases::run_ai_aggregation(scanner, cfg).await,
        ScanPhase::Reporting => other_phases::run_reporting(scanner, cfg).await,
        ScanPhase::ThreatModeling => other_phases::run_threat_modeling(scanner, cfg).await,
        ScanPhase::RootCauseDedup => other_phases::run_root_cause_dedup(scanner, cfg).await,
        ScanPhase::MultiVerifier => other_phases::run_multi_verifier(scanner, cfg).await,
        ScanPhase::AutoPatching => other_phases::run_auto_patching(scanner, cfg).await,
        ScanPhase::CveBootstrap => other_phases::run_cve_bootstrap(scanner, cfg).await,
        ScanPhase::PocCompiler => other_phases::run_poc_compiler(scanner, cfg).await,
        ScanPhase::VariantSearch => other_phases::run_variant_search(scanner, cfg).await,
        ScanPhase::CweRouting => other_phases::run_cwe_routing(scanner, cfg).await,
        ScanPhase::RuleSynthesis => other_phases::run_rule_synthesis(scanner, cfg).await,
        ScanPhase::ExploitSynth => other_phases::run_exploit_synth(scanner, cfg).await,
        _ => other_phases::run_default(cfg).await,
    }
}
