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
    let phase = cfg.phase.clone();
    match phase {
        ScanPhase::Indexing => {
            let (findings, files) = other_phases::run_indexing(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::Semgrep => {
            let (findings, files) = other_phases::run_semgrep(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::CpgSlice => {
            let (findings, files) = other_phases::run_cpg_slice(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::LlmStaticAnalysis => {
            let (findings, files) = llm_phases::run_llm_static_analysis(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::LlmDiscovery => {
            let (findings, files) = llm_phases::run_llm_discovery(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::LlmVerification => llm_phases::run_llm_verification(scanner, cfg).await,
        ScanPhase::Validate => {
            let (findings, files) = other_phases::run_validate(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::SecurityAgentVerification => {
            let (findings, files) =
                llm_phases::run_security_agent_verification(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::TicketCrossRef => {
            let (findings, files) = other_phases::run_ticket_cross_ref(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::GitAnalysis => {
            let (findings, files) = other_phases::run_git_analysis(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::CrossFileAnalysis => {
            let (findings, files) = other_phases::run_cross_file_analysis(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::ConfidenceScoring => {
            let (findings, files) = other_phases::run_confidence_scoring(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::AiAggregation => {
            let (findings, files) = other_phases::run_ai_aggregation(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::Reporting => {
            let (findings, files, _rejected) = other_phases::run_reporting(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::ThreatModeling => {
            let (findings, files) = other_phases::run_threat_modeling(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::RootCauseDedup => {
            let (findings, files) = other_phases::run_root_cause_dedup(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::MultiVerifier => {
            let (findings, files) = other_phases::run_multi_verifier(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::AutoPatching => {
            let (findings, files) = other_phases::run_auto_patching(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::CveBootstrap => {
            let (findings, files) = other_phases::run_cve_bootstrap(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::PocCompiler => {
            let (findings, files) = other_phases::run_poc_compiler(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::VariantSearch => {
            let (findings, files) = other_phases::run_variant_search(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::CweRouting => {
            let (findings, files) = other_phases::run_cwe_routing(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::RuleSynthesis => {
            let (findings, files) = other_phases::run_rule_synthesis(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        ScanPhase::ExploitSynth => {
            let (findings, files) = other_phases::run_exploit_synth(scanner, cfg).await?;
            Ok((findings, files, Vec::new()))
        }
        _ => {
            let (findings, files) = other_phases::run_default(cfg).await?;
            Ok((findings, files, Vec::new()))
        }
    }
}
