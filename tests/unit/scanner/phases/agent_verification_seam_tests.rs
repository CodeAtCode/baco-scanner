//! Unit tests for the agent_verification seam (injected runner pattern).
//!
//! These tests verify the `apply_*` helper functions and the guard branches
//! in the wrapper without needing a live LLM client. They use a fake
//! `SecurityAgentRunner` to exercise the injected runner path.

use baco::agent;
use baco::agent_flow::AgentOutput;
use baco::agent_flow::{self, AgentFlowHarness, Diagnostic, ExecutionResult, RewriteProposal};
use baco::checkpoint::ScanPhase;
use baco::config;
use baco::evidence::EvidenceSource;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::metrics::LlmMetricsTracker;
use baco::scanner::Scanner;
use baco::scanner::phases::PhaseConfig;
use baco::scanner::phases::llm_phases::agent_verification::{
    SecurityAgentRunner, apply_agent_failure, apply_agent_result, apply_flow_outcome,
    run_agent_blocks, run_security_agent_verification,
};
use indicatif::ProgressBar;
use std::path::PathBuf;

use crate::fixtures::{create_test_config_central as create_test_config, make_aggregation_finding};

// ============================================================================
// Fake Agent Runner
// ============================================================================

#[allow(dead_code)]
struct FakeAgent {
    verify_result: Option<Result<agent::AgentFinding, String>>,
    flow_result: Option<Result<ExecutionResult, String>>,
    /// Successive flow results, so a test can drive the flow across iterations.
    /// `Mutex` because the trait methods take `&self` and each has to advance.
    flow_sequence: std::sync::Mutex<std::collections::VecDeque<Result<ExecutionResult, String>>>,
    flow_calls: std::sync::atomic::AtomicUsize,
    propose_calls: std::sync::atomic::AtomicUsize,
    propose_result: Option<Result<RewriteProposal, String>>,
}

#[allow(dead_code)]
impl FakeAgent {
    fn new() -> Self {
        Self {
            verify_result: None,
            flow_result: None,
            flow_sequence: std::sync::Mutex::new(std::collections::VecDeque::new()),
            flow_calls: std::sync::atomic::AtomicUsize::new(0),
            propose_calls: std::sync::atomic::AtomicUsize::new(0),
            propose_result: None,
        }
    }

    /// Drive the flow across iterations: each `run_flow` pops the next result,
    /// the last one repeating once the sequence is exhausted.
    fn with_flow_sequence(mut self, results: Vec<Result<ExecutionResult, String>>) -> Self {
        self.flow_sequence = std::sync::Mutex::new(results.into());
        self
    }

    fn with_verify_success(mut self, finding: agent::AgentFinding) -> Self {
        self.verify_result = Some(Ok(finding));
        self
    }

    fn with_verify_error(mut self, error: &str) -> Self {
        self.verify_result = Some(Err(error.to_string()));
        self
    }

    fn with_flow_success(mut self, outputs: Vec<AgentOutput>) -> Self {
        self.flow_result = Some(Ok(ExecutionResult { outputs, rounds: 1 }));
        self
    }

    fn with_flow_error(mut self, error: &str) -> Self {
        self.flow_result = Some(Err(error.to_string()));
        self
    }

    fn with_propose_success(
        mut self,
        edits: Vec<agent_flow::HarnessEdit>,
        rationale: &str,
    ) -> Self {
        self.propose_result = Some(Ok(RewriteProposal {
            edits,
            rationale: rationale.to_string(),
        }));
        self
    }

    fn with_propose_error(mut self, error: &str) -> Self {
        self.propose_result = Some(Err(error.to_string()));
        self
    }
}

impl SecurityAgentRunner for FakeAgent {
    fn verify_finding<'a>(
        &'a self,
        _file_path: &'a str,
        _finding: &'a VulnerabilityFinding,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<agent::AgentFinding, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.verify_result.clone().unwrap_or(Err(
                "FakeAgent not configured for verify_finding".to_string()
            ))
        })
    }

    fn run_flow<'a>(
        &'a self,
        _harness: &'a AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ExecutionResult, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.flow_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut sequence = self.flow_sequence.lock().expect("flow sequence lock");
            if let Some(next) = sequence.pop_front() {
                return next;
            }
            self.flow_result
                .clone()
                .unwrap_or(Err("FakeAgent not configured for run_flow".to_string()))
        })
    }

    fn propose_rewrite<'a>(
        &'a self,
        _diagnostic: &'a Diagnostic,
        _harness: &'a AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RewriteProposal, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.propose_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.propose_result.clone().unwrap_or(Err(
                "FakeAgent not configured for propose_rewrite".to_string(),
            ))
        })
    }
}

// ============================================================================
// apply_agent_result tests
// ============================================================================

// ============================================================================
// Seam traversal: the block that owns the loop, driven by the fake runner.
// Without these the trait is never exercised in production shape, and the
// loop that maps each finding through the agent stays unexecuted.
// ============================================================================

fn base_config() -> config::ScannerConfig {
    let mut config = create_test_config();
    // Keep the filesystem walk out of the way: the scaffold is a separate path
    // and these tests are about the runner seam.
    config.agent_scaffold.enabled = false;
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled = false;
    config
}

#[tokio::test]
async fn test_run_agent_blocks_applies_verified_result_to_each_finding() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = base_config();
    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let verified = agent::AgentFinding {
        finding: make_finding(),
        compile_path: Some(PathBuf::from("/target/test.o")),
        test_source_path: None,
        test_log: Some("compiled and passed".to_string()),
        agent_turns: 3,
        tools_used: vec!["file_write".to_string(), "test_run".to_string()],
    };
    let fake = FakeAgent::new().with_verify_success(verified);

    let findings = vec![make_finding(), make_finding()];
    let (out, _files) = run_agent_blocks(findings, &pb, &analyzed, dir.path(), &config, &fake)
        .await
        .expect("agent blocks run");

    assert_eq!(out.len(), 2, "every finding goes through the runner");
    for finding in &out {
        assert_eq!(
            finding.agent_evidence_path.as_deref(),
            Some("/target/test.o"),
            "the verified finding records the compiled artefact"
        );
        assert_eq!(
            finding.verification_notes.as_deref(),
            Some("compiled and passed")
        );
    }
}

#[tokio::test]
async fn test_run_agent_blocks_marks_findings_failed_when_the_agent_errors() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = base_config();
    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let fake = FakeAgent::new().with_verify_error("sandbox refused the test");
    let findings = vec![make_finding()];
    let (out, _files) = run_agent_blocks(findings, &pb, &analyzed, dir.path(), &config, &fake)
        .await
        .expect("agent blocks run");

    assert_eq!(out[0].verification_status, Some(VerificationStatus::Failed));
    assert_eq!(
        out[0].verification_notes.as_deref(),
        Some("Agent verification failed: sandbox refused the test"),
        "the reason survives onto the finding rather than being swallowed"
    );
}

#[tokio::test]
async fn test_run_agent_blocks_survives_a_flow_that_produces_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = base_config();
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled = true;
    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let verified = agent::AgentFinding {
        finding: make_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: Some("no proof written".to_string()),
        agent_turns: 1,
        tools_used: vec![],
    };
    // The flow errors, so it contributes neither a diagnosis nor a rewrite.
    let fake = FakeAgent::new()
        .with_verify_success(verified)
        .with_flow_error("harness has a cycle");

    let findings = vec![make_finding()];
    let (out, _files) = run_agent_blocks(findings, &pb, &analyzed, dir.path(), &config, &fake)
        .await
        .expect("a failing flow must not fail the phase");

    assert_eq!(out[0].verification_status, None);
    assert_eq!(
        out[0].verification_notes.as_deref(),
        Some("no proof written"),
        "the agent's own log stands when the flow adds nothing"
    );
    let sources: Vec<_> = out[0]
        .evidence
        .iter()
        .map(|e| format!("{:?}", e.source))
        .collect();
    assert!(
        !sources.iter().any(|s| s.contains("agent_flow")),
        "a flow that produced nothing must not leave flow evidence behind: {sources:?}"
    );
}

#[tokio::test]
async fn test_run_agent_blocks_flow_converges_after_one_rewrite() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = base_config();
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled = true;
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .max_iterations = 4;
    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let quiet = agent::AgentFinding {
        finding: make_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };
    // First iteration fails, so a rewrite is proposed; second one succeeds, so
    // the loop converges instead of running out its budget.
    let fake = FakeAgent::new()
        .with_verify_success(quiet)
        .with_flow_sequence(vec![
            Ok(ExecutionResult {
                outputs: vec![AgentOutput {
                    role: "analyst".to_string(),
                    content: "could not confirm".to_string(),
                    success: false,
                }],
                rounds: 1,
            }),
            Ok(ExecutionResult {
                outputs: vec![AgentOutput {
                    role: "analyst".to_string(),
                    content: "confirmed".to_string(),
                    success: true,
                }],
                rounds: 2,
            }),
        ])
        .with_propose_success(Vec::new(), "ask for the failing input explicitly");

    let (out, _files) = run_agent_blocks(
        vec![make_finding()],
        &pb,
        &analyzed,
        dir.path(),
        &config,
        &fake,
    )
    .await
    .expect("agent blocks run");

    assert_eq!(
        fake.flow_calls.load(Ordering::SeqCst),
        2,
        "convergence stops the loop; it does not spend the iteration budget"
    );
    assert_eq!(
        fake.propose_calls.load(Ordering::SeqCst),
        1,
        "a rewrite is proposed only for the iteration that failed"
    );

    let sources: Vec<String> = out[0]
        .evidence
        .iter()
        .map(|e| format!("{:?}", e.source))
        .collect();
    assert!(
        sources.iter().any(|s| s.contains("agent_flow_diagnosis")),
        "the converged run still records a diagnosis: {sources:?}"
    );
    assert!(
        sources.iter().any(|s| s.contains("agent_flow_rewrite")),
        "the proposal that drove convergence is recorded: {sources:?}"
    );
}

#[tokio::test]
async fn test_run_agent_blocks_flow_spends_its_budget_without_converging() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = base_config();
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled = true;
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .max_iterations = 2;
    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let quiet = agent::AgentFinding {
        finding: make_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };
    // Never succeeds, so the loop runs its budget out.
    let never_ok = ExecutionResult {
        outputs: vec![AgentOutput {
            role: "analyst".to_string(),
            content: "still stuck".to_string(),
            success: false,
        }],
        rounds: 0,
    };
    let fake = FakeAgent::new()
        .with_verify_success(quiet)
        .with_flow_sequence(vec![Ok(never_ok.clone()), Ok(never_ok)])
        .with_propose_success(Vec::new(), "another try");

    let (out, _files) = run_agent_blocks(
        vec![make_finding()],
        &pb,
        &analyzed,
        dir.path(),
        &config,
        &fake,
    )
    .await
    .expect("a flow that never converges must not fail the phase");

    assert_eq!(
        fake.flow_calls.load(Ordering::SeqCst),
        2,
        "the loop stops at max_iterations rather than running forever"
    );
    assert_eq!(out.len(), 1, "the finding still comes back");
}

#[tokio::test]
async fn test_run_agent_blocks_uses_scaffold_context_when_the_agent_says_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A real tree, so the scaffold has something to index and look up.
    std::fs::write(
        dir.path().join("lib.rs"),
        "fn parse_input(raw: &str) -> usize {\n    raw.len()\n}\n\nfn main() {\n    parse_input(\"x\");\n}\n",
    )
    .expect("write source");

    let mut config = base_config();
    config.agent_scaffold.enabled = true;
    config.project.languages = vec!["rust".to_string()];
    config.scanner.exclude_paths = vec![];

    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    // The agent returns no log and no paths, which is exactly when the scaffold
    // context is supposed to be the fallback.
    let quiet = agent::AgentFinding {
        finding: make_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };
    let fake = FakeAgent::new().with_verify_success(quiet);

    let mut finding = make_finding();
    finding.title = "Buffer overflow in parse_input()".to_string();
    // The extractor reads code_snippet first and only falls back to the title,
    // so a finding that ships a snippet is never matched on its title.
    finding.code_snippet = None;
    finding.file_path = dir.path().join("lib.rs").to_string_lossy().to_string();

    let (out, _files) = run_agent_blocks(vec![finding], &pb, &analyzed, dir.path(), &config, &fake)
        .await
        .expect("agent blocks run");

    let notes = out[0]
        .verification_notes
        .clone()
        .expect("the scaffold context stands in for a silent agent");
    assert!(
        notes.contains("parse_input"),
        "the scaffold points the agent at the target function: {notes}"
    );
    assert!(
        notes.contains("raw.len()"),
        "the scaffold carries the function source, not just its name: {notes}"
    );
}

#[tokio::test]
async fn test_run_agent_blocks_survives_scaffold_over_an_empty_tree() {
    let dir = tempfile::tempdir().expect("temp dir");

    let mut config = base_config();
    config.agent_scaffold.enabled = true;
    config.project.languages = vec!["rust".to_string()];
    config.scanner.exclude_paths = vec![];

    let pb = ProgressBar::hidden();
    let analyzed: Vec<String> = vec![];

    let quiet = agent::AgentFinding {
        finding: make_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: Some("agent spoke".to_string()),
        agent_turns: 1,
        tools_used: vec![],
    };
    let fake = FakeAgent::new().with_verify_success(quiet);

    let mut finding = make_finding();
    finding.title = "Something in absent_function()".to_string();
    finding.code_snippet = None;

    let (out, _files) = run_agent_blocks(vec![finding], &pb, &analyzed, dir.path(), &config, &fake)
        .await
        .expect("an empty tree must not fail the phase");

    assert_eq!(
        out[0].verification_notes.as_deref(),
        Some("agent spoke"),
        "nothing to scaffold, so the agent log stands"
    );
}

#[test]
fn test_apply_agent_result_prefers_compile_path() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: Some(PathBuf::from("/target/test.o")),
        test_source_path: Some(PathBuf::from("/src/test.rs")),
        test_log: Some("test log".to_string()),
        agent_turns: 5,
        tools_used: vec!["tool1".to_string()],
    };

    apply_agent_result(&mut finding, &result, None);

    assert_eq!(
        finding.agent_evidence_path,
        Some("/target/test.o".to_string())
    );
}

#[test]
fn test_apply_agent_result_falls_back_to_test_source_path() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: Some(PathBuf::from("/src/test.rs")),
        test_log: Some("test log".to_string()),
        agent_turns: 5,
        tools_used: vec!["tool1".to_string()],
    };

    apply_agent_result(&mut finding, &result, None);

    assert_eq!(
        finding.agent_evidence_path,
        Some("/src/test.rs".to_string())
    );
}

#[test]
fn test_apply_agent_result_falls_back_to_turn_count() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: None,
        test_log: Some("test log".to_string()),
        agent_turns: 3,
        tools_used: vec!["tool1".to_string(), "tool2".to_string()],
    };

    apply_agent_result(&mut finding, &result, None);

    assert_eq!(
        finding.agent_evidence_path,
        Some("3 turns, 2 tools".to_string())
    );
}

#[test]
fn test_apply_agent_result_sets_verification_notes_from_test_log() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: None,
        test_log: Some("agent test log output".to_string()),
        agent_turns: 1,
        tools_used: vec![],
    };

    apply_agent_result(&mut finding, &result, None);

    assert_eq!(
        finding.verification_notes,
        Some("agent test log output".to_string())
    );
}

#[test]
fn test_apply_agent_result_prefers_test_log_over_scaffold_context() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: None,
        test_log: Some("agent test log".to_string()),
        agent_turns: 1,
        tools_used: vec![],
    };

    apply_agent_result(&mut finding, &result, Some("scaffold context".to_string()));

    assert_eq!(
        finding.verification_notes,
        Some("agent test log".to_string())
    );
}

#[test]
fn test_apply_agent_result_uses_scaffold_context_when_no_test_log() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 1,
        tools_used: vec![],
    };

    apply_agent_result(&mut finding, &result, Some("scaffold context".to_string()));

    assert_eq!(
        finding.verification_notes,
        Some("scaffold context".to_string())
    );
}

#[test]
fn test_apply_agent_result_adds_evidence_entry() {
    let mut finding = make_finding();
    let result = agent::AgentFinding {
        finding: finding.clone(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };

    apply_agent_result(&mut finding, &result, None);

    assert!(!finding.evidence.is_empty());
    let has_agent_verification = finding
        .evidence
        .iter()
        .any(|e| matches!(e.source, EvidenceSource::SecurityAgentVerification(_)));
    assert!(has_agent_verification);
}

// ============================================================================
// apply_agent_failure tests
// ============================================================================

#[test]
fn test_apply_agent_failure_sets_status_to_failed() {
    let mut finding = make_finding();

    apply_agent_failure(&mut finding, "connection timeout", None);

    assert_eq!(
        finding.verification_status,
        Some(VerificationStatus::Failed)
    );
}

#[test]
fn test_apply_agent_failure_records_error_in_notes() {
    let mut finding = make_finding();

    apply_agent_failure(&mut finding, "connection timeout", None);

    assert!(
        finding
            .verification_notes
            .unwrap()
            .contains("connection timeout")
    );
}

#[test]
fn test_apply_agent_failure_prefers_scaffold_context_over_error() {
    let mut finding = make_finding();

    apply_agent_failure(
        &mut finding,
        "connection timeout",
        Some("scaffold context".to_string()),
    );

    assert_eq!(
        finding.verification_notes,
        Some("scaffold context".to_string())
    );
}

#[test]
fn test_apply_agent_failure_adds_evidence_entry() {
    let mut finding = make_finding();

    apply_agent_failure(&mut finding, "error message", None);

    assert!(!finding.evidence.is_empty());
    let has_agent_verification = finding
        .evidence
        .iter()
        .any(|e| matches!(e.source, EvidenceSource::SecurityAgentVerification(_)));
    assert!(has_agent_verification);
}

// ============================================================================
// apply_flow_outcome tests
// ============================================================================

#[test]
fn test_apply_flow_outcome_records_diagnosis_evidence() {
    let mut finding = make_finding();

    apply_flow_outcome(&mut finding, Some("diagnosis summary".to_string()), None);

    assert!(!finding.evidence.is_empty());
    let has_diagnosis = finding.evidence.iter().any(|e| {
        matches!(
            e.source,
            EvidenceSource::SecurityAgentVerification(ref s) if s == "agent_flow_diagnosis"
        )
    });
    assert!(has_diagnosis);
}

#[test]
fn test_apply_flow_outcome_records_rewrite_evidence() {
    let mut finding = make_finding();

    apply_flow_outcome(&mut finding, None, Some("proposed rewrite".to_string()));

    assert!(!finding.evidence.is_empty());
    let has_rewrite = finding.evidence.iter().any(|e| {
        matches!(
            e.source,
            EvidenceSource::SecurityAgentVerification(ref s) if s == "agent_flow_rewrite"
        )
    });
    assert!(has_rewrite);
}

#[test]
fn test_apply_flow_outcome_sets_notes_from_diagnosis() {
    let mut finding = make_finding();

    apply_flow_outcome(&mut finding, Some("diagnosis summary".to_string()), None);

    assert_eq!(
        finding.verification_notes,
        Some("diagnosis summary".to_string())
    );
}

#[test]
fn test_apply_flow_outcome_leaves_notes_alone_when_only_rewrite_present() {
    let mut finding = make_finding();
    finding.verification_notes = Some("existing notes".to_string());

    apply_flow_outcome(&mut finding, None, Some("proposed rewrite".to_string()));

    assert_eq!(
        finding.verification_notes,
        Some("existing notes".to_string())
    );
}

// ============================================================================
// Wrapper guard tests
// ============================================================================

#[tokio::test]
async fn test_wrapper_short_circuits_when_agent_disabled() {
    let scanner = Scanner::new(config::ScannerConfig::default(), PathBuf::from("."), false);
    let mut config = create_test_config();
    config.agent.enabled = false; // Disabled

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![make_finding()];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_security_agent_verification(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _) = result.unwrap();
    // Should return early without processing
    assert_eq!(updated.len(), findings.len());
}

#[tokio::test]
async fn test_wrapper_short_circuits_when_api_key_missing() {
    let scanner = Scanner::new(config::ScannerConfig::default(), PathBuf::from("."), false);
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = None; // Missing

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![make_finding()];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_security_agent_verification(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

#[tokio::test]
async fn test_wrapper_short_circuits_when_llm_client_unavailable() {
    let scanner = Scanner::new(config::ScannerConfig::default(), PathBuf::from("."), false);
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    // No base_url set, so LLM client creation will fail

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![make_finding()];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_security_agent_verification(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// Helpers
// ============================================================================

fn make_finding() -> VulnerabilityFinding {
    make_aggregation_finding(
        "test-id",
        Severity::High,
        0.9,
        "test.rs",
        Some(42),
        Some("CWE-789"),
        None,
    )
}
