//! Scanner module - orchestrates security scanning phases

pub mod checkpoint;
mod core;
mod env;
mod helpers;
mod orchestrator;
pub(crate) mod parallel;
pub mod phases;
mod pipeline;
mod sequential;

// Re-export public API from core
pub use core::{Scanner, ScannerState};

// Re-export pipeline orchestration
pub use pipeline::orchestrator::{Orchestrator, PhaseGraph};
pub use pipeline::resumption::{CheckpointManager, ScanCheckpoint};

// Re-export phases for testing
#[cfg(test)]
pub use phases::{run_phase, PhaseConfig};

// Re-export utility functions from env
pub use env::{extract_owner_repo_from_url, get_git_remote_url};
// Re-export parallel module types for testing
pub use parallel::{
    combine_parallel_results, has_valid_checkpoint_findings, run_indexing_phase,
    run_llm_static_phase, run_semgrep_phase, ParallelPhaseConfig, ParallelPhaseResult,
};

// Use the checkpoint module for save/load
use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use checkpoint::{load_checkpoint_findings, save_checkpoint};

// Re-export Scanner methods that need access to all modules
impl Scanner {
    /// Execute a single scan phase
    pub(crate) async fn run_phase(
        &self,
        phase: &ScanPhase,
        findings: Vec<VulnerabilityFinding>,
        pb: &indicatif::ProgressBar,
        analyzed_files: &[String],
    ) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
        phases::run_phase(
            self,
            phases::PhaseConfig {
                phase,
                findings,
                pb,
                analyzed_files,
                metrics_tracker: &self.metrics_tracker,
                target_path: &self.target_path,
                config: &self.config,
                project_stack: &self.project_stack,
            },
        )
        .await
        .map_err(|e| e.to_string())
    }

    /// Save checkpoint with current findings
    #[allow(dead_code)]
    async fn save_checkpoint(
        &self,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        phase: &ScanPhase,
    ) -> Result<(), String> {
        save_checkpoint(
            &self.checkpoint_path,
            &self.config,
            findings,
            analyzed_files,
            phase,
            &self.metrics_tracker,
        )
        .await
    }

    /// Load findings from checkpoint for a specific phase
    #[allow(dead_code)]
    async fn load_checkpoint_findings(&self, phase: &ScanPhase) -> Vec<VulnerabilityFinding> {
        load_checkpoint_findings(&self.checkpoint_path, phase).await
    }

    /// Return the number of parallel phases (for testing)
    pub fn scheduled_parallel_phases() -> usize {
        4 // Indexing, Semgrep, CpgSlice, LlmStaticAnalysis
    }

    /// Return the number of sequential phases (for testing)
    pub fn scheduled_sequential_phases() -> usize {
        20 // All sequential phases including Validate
    }

    /// Return parallel and sequential phase counts (for testing)
    pub fn scheduled_phase_counts() -> (usize, usize) {
        (
            Self::scheduled_parallel_phases(),
            Self::scheduled_sequential_phases(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, LlmPhasesConfig, PerformanceSettings, ScannerSettings};
    use crate::findings::Severity;
    use crate::phase::helpers::create_test_finding_simple;
    use indicatif::ProgressBar;
    use std::path::PathBuf;

    fn create_test_config() -> crate::config::ScannerConfig {
        crate::config::ScannerConfig {
            project: crate::config::ProjectConfig {
                languages: vec!["rust".to_string()],
                ..Default::default()
            },
            scanner: ScannerSettings {
                max_file_size_kb: 1024,
                exclude_paths: vec![],
                semgrep: crate::config::SemgrepSettings::default(),
                performance: PerformanceSettings::default(),
                ..Default::default()
            },
            llm: crate::config::LlmConfig {
                phases: LlmPhasesConfig::default(),
                timeout_secs: 30,
                max_retries: 3,
                retry_backoff_ms: 1000,
                ..Default::default()
            },
            output: crate::config::OutputConfig {
                dir: "/tmp/test_output".to_string(),
                ..Default::default()
            },
            agent: AgentConfig::default(),
            tickets: crate::config::TicketConfig { systems: vec![] },
            router: crate::config::RouterConfig::default(),
            aggregation: crate::config::AggregationConfig::default(),
            rulesynth: crate::config::RuleSynthConfig::default(),
            normalization: crate::config::NormalizationConfig::default(),
            cpg: crate::config::CpgConfig::default(),
            exploit: crate::config::ExploitConfig::default(),
            validate: Default::default(),
            vultriage: Default::default(),
            policy_sampling: Default::default(),
            agent_scaffold: Default::default(),
            pacvd: Default::default(),
            agent_flow: Default::default(),
        }
    }

    #[test]
    fn test_scan_phase_all_variants_exist() {
        let phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::CweRouting,
            ScanPhase::CpgSlice,
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::Validate,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::Reporting,
            ScanPhase::ThreatModeling,
            ScanPhase::RootCauseDedup,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::CveBootstrap,
            ScanPhase::PocCompiler,
            ScanPhase::VariantSearch,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::RuleSynthesis,
            ScanPhase::ExploitSynth,
            ScanPhase::Complete,
            ScanPhase::Error,
        ];

        assert_eq!(phases.len(), 26);
    }

    #[test]
    fn test_scan_phase_debug_format() {
        assert_eq!(format!("{:?}", ScanPhase::Indexing), "Indexing");
        assert_eq!(format!("{:?}", ScanPhase::Semgrep), "Semgrep");
        assert_eq!(
            format!("{:?}", ScanPhase::LlmStaticAnalysis),
            "LlmStaticAnalysis"
        );
        assert_eq!(format!("{:?}", ScanPhase::Complete), "Complete");
    }

    #[tokio::test]
    async fn test_indexing_phase_empty_findings() {
        let config = create_test_config();
        let pb = ProgressBar::new(100);
        let target_path = PathBuf::from(".");

        let scanner = Scanner::new(config.clone(), target_path.clone(), false);

        let result = scanner
            .run_phase(&ScanPhase::Indexing, vec![], &pb, &[])
            .await;
        assert!(result.is_ok());

        let (findings, analyzed_files) = result.unwrap();
        assert!(findings.is_empty());
        assert_eq!(analyzed_files.len(), 0);
    }

    #[tokio::test]
    async fn test_cross_file_analysis_phase() {
        let config = create_test_config();
        let pb = ProgressBar::new(100);
        let target_path = PathBuf::from(".");

        let findings = vec![
            create_test_finding_simple("Cross File 1", Severity::Medium),
            create_test_finding_simple("Cross File 2", Severity::Medium),
        ];

        let scanner = Scanner::new(config.clone(), target_path.clone(), false);
        let result = scanner
            .run_phase(&ScanPhase::CrossFileAnalysis, findings, &pb, &[])
            .await;

        assert!(result.is_ok());
        let (findings, _) = result.unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn test_reporting_phase() {
        let config = create_test_config();
        let pb = ProgressBar::new(100);
        let target_path = PathBuf::from(".");

        let findings = vec![
            create_test_finding_simple("Report 1", Severity::Critical),
            create_test_finding_simple("Report 2", Severity::High),
            create_test_finding_simple("Report 3", Severity::Medium),
        ];

        let scanner = Scanner::new(config.clone(), target_path.clone(), false);
        let result = scanner
            .run_phase(&ScanPhase::Reporting, findings, &pb, &[])
            .await;

        assert!(result.is_ok());
        let (findings, _) = result.unwrap();
        assert_eq!(findings.len(), 3);
    }

    #[tokio::test]
    async fn test_phase_with_mixed_severities() {
        let config = create_test_config();
        let pb = ProgressBar::new(100);
        let target_path = PathBuf::from(".");

        let findings = vec![
            create_test_finding_simple("Critical Issue", Severity::Critical),
            create_test_finding_simple("High Issue", Severity::High),
            create_test_finding_simple("Medium Issue", Severity::Medium),
            create_test_finding_simple("Low Issue", Severity::Low),
        ];

        let scanner = Scanner::new(config.clone(), target_path.clone(), false);
        let result = scanner
            .run_phase(&ScanPhase::CrossFileAnalysis, findings, &pb, &[])
            .await;

        assert!(result.is_ok());
        let (findings, _) = result.unwrap();
        assert_eq!(findings.len(), 4);
    }
}
