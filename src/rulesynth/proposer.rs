//! LLM proposer loop for MoCQ rule synthesis (P3.3).
//!
//! Iteratively asks the LLM to propose a Pattern (in DSL), validates it
//! against the trace corpus, feeds back the validation outcome, and repeats
//! until the pattern converges (F1 >= threshold) or `max_iterations` is reached.

use super::pattern_dsl::{parse_pattern, Pattern};
use super::symbolic_validator::{format_feedback, validate, LabelledTrace, ValidationOutcome};
use crate::llm::{ChatMessage, LlmClient};

/// Threshold F1 score for convergence.
const CONVERGENCE_F1: f64 = 0.8;

/// Run the propose-validate-rewrite loop.
///
/// Returns the best pattern found and its validation outcome.
/// If the LLM never produces a parseable pattern, returns `None`.
pub async fn run_proposer_loop(
    llm: &LlmClient,
    cwe: &str,
    traces: &[LabelledTrace],
    max_iterations: u8,
) -> Option<(Pattern, ValidationOutcome)> {
    let mut best: Option<(Pattern, ValidationOutcome)> = None;
    let mut feedback = String::new();

    for round in 0..max_iterations {
        let messages = build_prompt_messages(cwe, &feedback, round);
        let response = llm.chat(&messages).await.ok()?;
        let pattern = extract_pattern(&response.content)?;

        let outcome = validate(&pattern, traces);
        if best
            .as_ref()
            .map_or(true, |(_, o)| outcome.score() > o.score())
        {
            best = Some((pattern.clone(), outcome.clone()));
        }

        if outcome.f1 >= CONVERGENCE_F1 {
            break;
        }

        feedback = format_feedback(&outcome);
    }

    best
}

pub fn build_prompt_messages(cwe: &str, feedback: &str, round: u8) -> Vec<ChatMessage> {
    let system = format!(
        "You are a vulnerability pattern designer. Produce a single pattern line for {}.\n\
         Format: PATTERN <id> CWE-<n> <source> -> <sink_func>[<arg_pos>] <severity>\n\
         Source is 'return' or 'param[N]'. Severity is LOW/MEDIUM/HIGH/CRITICAL.\n\
         Respond with ONLY the pattern line, nothing else.",
        cwe
    );

    let user = if round == 0 {
        format!("Propose a pattern for {}.", cwe)
    } else {
        format!(
            "Previous attempt feedback:\n{}\n\nRewrite the pattern to improve F1 score.",
            feedback
        )
    };

    vec![
        ChatMessage {
            role: "system".to_string(),
            content: system,
        },
        ChatMessage {
            role: "user".to_string(),
            content: user,
        },
    ]
}

pub fn extract_pattern(text: &str) -> Option<Pattern> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("PATTERN") {
            if let Ok(p) = parse_pattern(line) {
                return Some(p);
            }
        }
    }
    None
}
