//! Diagnoser for AgentFlow execution results (P5.4).
//!
//! Analyzes execution outputs and external feedback signals (coverage,
//! sanitizer crashes, traces) to produce structured diagnostic feedback
//! that the proposer uses to rewrite the harness.

use super::dsl::FeedbackChannel;
use super::executor::{AgentOutput, ExecutionResult};
use std::collections::BTreeSet;

/// A signal collected from the test environment after harness execution.
#[derive(Debug, Clone, PartialEq)]
pub enum FeedbackSignal {
    CoverageIncrease(f64),
    BranchHit(u32),
    SanitizerCrash { kind: String, location: String },
    TraceEvent { label: String, value: String },
    Pass,
    Fail(String),
}

/// Diagnostic feedback produced by the diagnoser.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub signals: Vec<FeedbackSignal>,
    pub summary: String,
    pub should_rewrite: bool,
}

impl Diagnostic {
    pub fn is_success(&self) -> bool {
        !self.should_rewrite
    }
}

/// Diagnose an execution result given the set of feedback channels that fired.
pub fn diagnose(
    execution: &ExecutionResult,
    feedback_channels: &BTreeSet<FeedbackChannel>,
    signals: Vec<FeedbackSignal>,
) -> Diagnostic {
    let all_succeeded = execution.is_success();

    let has_crash = signals
        .iter()
        .any(|s| matches!(s, FeedbackSignal::SanitizerCrash { .. }));
    let has_coverage = signals
        .iter()
        .any(|s| matches!(s, FeedbackSignal::CoverageIncrease(_)));
    let has_pass = signals.iter().any(|s| matches!(s, FeedbackSignal::Pass));
    let has_fail = signals.iter().any(|s| matches!(s, FeedbackSignal::Fail(_)));

    let channels_referenced = feedback_channels.iter().any(|c| {
        matches!(
            c,
            FeedbackChannel::Coverage | FeedbackChannel::Sanitizer | FeedbackChannel::Outcome
        )
    });

    let should_rewrite =
        !all_succeeded || has_fail || (channels_referenced && !has_pass && !has_crash);

    let summary = build_summary(
        all_succeeded,
        has_crash,
        has_coverage,
        has_pass,
        &execution.outputs,
    );

    Diagnostic {
        signals,
        summary,
        should_rewrite,
    }
}

fn build_summary(
    all_succeeded: bool,
    has_crash: bool,
    has_coverage: bool,
    has_pass: bool,
    outputs: &[AgentOutput],
) -> String {
    let mut parts = Vec::new();

    if all_succeeded {
        parts.push("all agents completed".to_string());
    } else {
        let failed: Vec<&str> = outputs
            .iter()
            .filter(|o| !o.success)
            .map(|o| o.role.as_str())
            .collect();
        parts.push(format!("failed agents: {}", failed.join(", ")));
    }

    if has_crash {
        parts.push("sanitizer crash observed".to_string());
    }
    if has_coverage {
        parts.push("coverage increased".to_string());
    }
    if has_pass {
        parts.push("test passed".to_string());
    }

    parts.join("; ")
}

/// Format a diagnostic for the LLM proposer.
pub fn format_diagnostic(diagnostic: &Diagnostic) -> String {
    let signal_str: Vec<String> = diagnostic
        .signals
        .iter()
        .map(|s| match s {
            FeedbackSignal::CoverageIncrease(v) => format!("coverage +{:.1}%", v * 100.0),
            FeedbackSignal::BranchHit(n) => format!("branches hit: {}", n),
            FeedbackSignal::SanitizerCrash { kind, location } => {
                format!("crash: {} at {}", kind, location)
            }
            FeedbackSignal::TraceEvent { label, value } => format!("trace {}: {}", label, value),
            FeedbackSignal::Pass => "test passed".to_string(),
            FeedbackSignal::Fail(msg) => format!("test failed: {}", msg),
        })
        .collect();

    format!(
        "Diagnostic:\n  Signals: {}\n  Summary: {}\n  Rewrite needed: {}",
        signal_str.join(", "),
        diagnostic.summary,
        if diagnostic.should_rewrite {
            "yes"
        } else {
            "no"
        }
    )
}
