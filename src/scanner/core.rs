//! Scanner core types and state management

use crate::checkpoint::ScanPhase;
use crate::config;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use crate::scanner_types::{cve::CveEntry, project::ProjectStack};

use indicatif::{MultiProgress, ProgressBar};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;

// Type alias for phase result to reduce complexity
#[allow(dead_code)]
type PhaseResult = crate::error::ScanResult<(
    Vec<VulnerabilityFinding>,
    Vec<String>,
    Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
)>;

pub struct ScannerState {
    pub findings: Vec<VulnerabilityFinding>,
    pub current_phase: ScanPhase,
    pub files_scanned: usize,
    pub errors: Vec<String>,
    pub cve_entries: Vec<CveEntry>,
    pub project_stack: Option<ProjectStack>,
    pub rejected_findings: Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
}

pub struct Scanner {
    pub state: Arc<watch::Sender<ScannerState>>,
    pub(super) progress: MultiProgress,
    pub config: config::ScannerConfig,
    pub target_path: PathBuf,
    pub checkpoint_path: PathBuf,
    pub(super) force: bool,
    pub metrics_tracker: LlmMetricsTracker,
    #[allow(dead_code)]
    cve_entries: Vec<CveEntry>,
    pub project_stack: Option<ProjectStack>,
}

impl Scanner {
    pub fn findings(&self) -> Vec<VulnerabilityFinding> {
        self.state.borrow().findings.clone()
    }

    pub fn findings_mut(&self) -> Vec<VulnerabilityFinding> {
        self.state.borrow().findings.clone()
    }

    pub fn update_findings(&self, findings: Vec<VulnerabilityFinding>) {
        self.state.send_modify(|s| {
            s.findings = findings;
        });
    }

    /// Check for early termination based on finding threshold.
    /// Returns Ok(true) if termination triggered, Ok(false) otherwise.
    #[allow(dead_code)]
    async fn check_early_termination(
        &self,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        phase: &ScanPhase,
        pb: &ProgressBar,
    ) -> Result<bool, String> {
        let threshold = self.config.scanner.performance.early_termination_threshold;

        if threshold > 0.0 && findings.len() as f32 > threshold {
            tracing::warn!(
                "Early termination triggered after phase {:?}: {} findings > threshold {}",
                phase,
                findings.len(),
                threshold
            );

            if let Err(e) = self.save_checkpoint(findings, analyzed_files, phase).await {
                tracing::warn!("Failed to save checkpoint before early termination: {}", e);
            }

            pb.set_message(format!(
                "Early termination: {} findings (threshold: {})",
                findings.len(),
                threshold
            ));
            pb.finish();

            return Ok(true);
        }

        Ok(false)
    }

    pub fn add_finding(&self, finding: VulnerabilityFinding) {
        self.state.send_modify(|s| {
            s.findings.push(finding);
        });
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn new(config: config::ScannerConfig, target_path: PathBuf, force: bool) -> Self {
        Self::with_initial_findings(config, target_path, Vec::new(), force)
    }

    pub fn with_initial_findings(
        config: config::ScannerConfig,
        target_path: PathBuf,
        initial_findings: Vec<VulnerabilityFinding>,
        force: bool,
    ) -> Self {
        let (sender, _) = watch::channel(ScannerState {
            findings: initial_findings,
            current_phase: ScanPhase::Indexing,
            files_scanned: 0,
            errors: Vec::new(),
            cve_entries: Vec::new(),
            project_stack: None,
            rejected_findings: Vec::new(),
        });

        let output_dir = PathBuf::from(&config.output.dir);
        let checkpoint_path = output_dir.join("checkpoint.json");

        Self {
            state: Arc::new(sender),
            progress: MultiProgress::new(),
            config,
            target_path,
            checkpoint_path,
            force,
            metrics_tracker: LlmMetricsTracker::new(),
            cve_entries: Vec::new(),
            project_stack: None,
        }
    }

    pub async fn run(&self) -> crate::error::ScanResult<Vec<VulnerabilityFinding>> {
        super::orchestrator::run_scanner(self)
            .await
            .map_err(|e| e.into())
    }

    /// Extract owner and repository name from a Git URL
    pub fn extract_owner_repo_from_url(url: &str) -> Option<(String, String)> {
        super::env::extract_owner_repo_from_url(url)
    }

    /// Get Git remote URL from a repository path
    pub fn get_git_remote_url(repo_path: &str) -> Option<String> {
        super::env::get_git_remote_url(repo_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::ScanPhase;
    use crate::config::{
        LlmConfig, LlmPhasesConfig, OutputConfig, PerformanceSettings, ProjectConfig, ScannerConfig,
    };
    use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};

    /// Test helper: Create a minimal valid ScannerConfig for testing
    fn create_test_config() -> ScannerConfig {
        ScannerConfig {
            project: ProjectConfig {
                name: "test-project".to_string(),
                path: "/tmp/test-project".to_string(),
                languages: vec![],
            },
            output: OutputConfig {
                dir: "/tmp/test-output".to_string(),
                evidence_gate: false,
                include_rejected: false,
            },
            scanner: crate::config::ScannerSettings {
                max_file_size_kb: 1024,
                exclude_paths: vec![],
                semgrep: crate::config::SemgrepSettings::default(),
                performance: PerformanceSettings::default(),
            },
            llm: LlmConfig {
                timeout_secs: 30,
                max_retries: 3,
                retry_backoff_ms: 1000,
                max_concurrent: 4,
                phases: LlmPhasesConfig::default(),
                temperature: 0.5,
                max_reasoning_tokens: None,
                enable_llm_cache: false,
                cache_dir: None,
            },
            tickets: crate::config::TicketConfig::default(),
            agent: crate::config::AgentConfig::default(),
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
            vuln_spec: Default::default(),
            citation_verification: Default::default(),
            prior_runs: Default::default(),
            org_context: Default::default(),
        }
    }

    #[test]
    fn test_scanner_new_creates_initial_state() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config.clone(), target_path.clone(), false);

        assert_eq!(scanner.config.project.name, "test-project");
        assert_eq!(scanner.target_path, target_path);
        assert_eq!(scanner.state.borrow().findings.len(), 0);
        assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);
        assert_eq!(scanner.state.borrow().files_scanned, 0);
        assert_eq!(scanner.state.borrow().errors.len(), 0);
    }

    #[test]
    fn test_scanner_with_initial_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let initial_findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }];

        let scanner =
            Scanner::with_initial_findings(config, target_path, initial_findings.clone(), false);

        assert_eq!(scanner.state.borrow().findings.len(), 1);
        assert_eq!(scanner.state.borrow().findings[0].id, "test-1");
    }

    #[test]
    fn test_scanner_force_flag() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, true); // force = true

        assert!(scanner.force);
    }

    #[test]
    fn test_scanner_findings_method() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Initially empty
        assert!(scanner.findings().is_empty());

        // Add a finding
        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        });

        assert_eq!(scanner.findings().len(), 1);
    }

    #[test]
    fn test_scanner_findings_mut_method() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Low,
            confidence_score: 0.3,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        });

        let findings = scanner.findings_mut();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_scanner_update_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Add initial finding
        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test 1".to_string(),
            description: "Test desc 1".to_string(),
            severity: Severity::Info,
            confidence_score: 0.1,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        });

        assert_eq!(scanner.findings().len(), 1);

        // Update with new findings
        let new_findings = vec![VulnerabilityFinding {
            id: "test-2".to_string(),
            title: "Test 2".to_string(),
            description: "Test desc 2".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "sql.rs".to_string(),
            line_number: Some(100),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Confirmed),
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }];

        scanner.update_findings(new_findings.clone());
        assert_eq!(scanner.findings().len(), 1);
        assert_eq!(scanner.findings()[0].id, "test-2");
    }

    #[test]
    fn test_scanner_target_path() {
        let config = create_test_config();
        let target_path = PathBuf::from("/custom/path/to/project");
        let scanner = Scanner::new(config, target_path.clone(), false);

        assert_eq!(scanner.target_path(), &target_path);
    }

    #[test]
    fn test_scanner_checkpoint_path_computed_from_config() {
        let mut config = create_test_config();
        config.output.dir = "/tmp/custom-output".to_string();
        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(
            scanner.checkpoint_path,
            PathBuf::from("/tmp/custom-output/checkpoint.json")
        );
    }

    #[test]
    fn test_scanner_state_initial_values() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let state = scanner.state.borrow();
        assert!(state.findings.is_empty());
        assert_eq!(state.current_phase, ScanPhase::Indexing);
        assert_eq!(state.files_scanned, 0);
        assert!(state.errors.is_empty());
        assert!(state.cve_entries.is_empty());
        assert!(state.project_stack.is_none());
    }

    #[test]
    fn test_scanner_metrics_tracker_initialization() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let _scanner = Scanner::new(config, target_path, false);

        // Just verify the scanner was created with a metrics tracker
        // The actual metrics tracking is tested in other modules
        // LlmMetricsTracker is always initialized, we can't easily test its internals here
    }

    #[test]
    fn test_scanner_with_different_force_values() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");

        let scanner_force = Scanner::new(config.clone(), target_path.clone(), true);
        let scanner_no_force = Scanner::new(config, target_path, false);

        assert!(scanner_force.force);
        assert!(!scanner_no_force.force);
    }

    #[test]
    fn test_scanner_checkpoint_path_with_nested_output_dir() {
        let mut config = create_test_config();
        config.output.dir = "/tmp/output/nested/path".to_string();
        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(
            scanner.checkpoint_path,
            PathBuf::from("/tmp/output/nested/path/checkpoint.json")
        );
    }

    #[tokio::test]
    async fn test_check_early_termination_below_threshold() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }];

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should NOT terminate (1 finding < 1000 threshold)
    }

    /// Test helper: Create a test VulnerabilityFinding
    fn create_test_finding(id: &str) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }
    }

    #[tokio::test]
    async fn test_check_early_termination_above_threshold() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 2.0; // Low threshold for testing
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Create 5 findings (above threshold of 2)
        let findings: Vec<VulnerabilityFinding> = (0..5)
            .map(|i| create_test_finding(&format!("test-{}", i)))
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Should terminate (5 findings > 2 threshold)
    }

    #[tokio::test]
    async fn test_check_early_termination_disabled() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 0.0; // Disabled
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Create many findings but threshold is 0 (disabled)
        let findings: Vec<VulnerabilityFinding> = (0..10000)
            .map(|i| create_test_finding(&format!("test-{}", i)))
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should NOT terminate (threshold = 0 means disabled)
    }
}
