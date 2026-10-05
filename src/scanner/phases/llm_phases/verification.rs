use crate::agent;
use crate::checkpoint::ScanPhase;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::llm::{ChatMessage, LlmChatClient};
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::{PoCFormat, PoCGenerationEngine};
use crate::prompt::loader::{load_hunt_prompts, load_phase_prompts};
use crate::prompt::templates::cwe_to_hunt_domain;
use crate::scanner::phases::PhaseConfig;
use crate::scanner::progress::progress_position;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

/// Rejected finding with its rejection reason.
pub type RejectedFinding = (VulnerabilityFinding, String);

/// Batch verification verdict item (index + verdict + reason)
#[derive(Deserialize, Debug)]
struct BatchVerdictItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    index: Option<usize>,
    #[serde(default)]
    verification_status: String,
    verification_notes: Option<String>,
    /// The seven-question gate the prompt asks for. It was always requested and
    /// never read, so the status was the model's unsupported word.
    #[serde(default)]
    seven_question_gate: Option<SevenQuestionGate>,
    #[serde(default)]
    concrete_impact_proof: Option<ImpactProof>,
}

#[derive(Deserialize, Debug, Default)]
struct SevenQuestionGate {
    #[serde(default)]
    reachability: Option<String>,
    #[serde(default)]
    controllability: Option<String>,
    #[serde(default)]
    preconditions: Option<String>,
    #[serde(default)]
    impact: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct ImpactProof {
    #[serde(default)]
    attack_vector: Option<String>,
    #[serde(default)]
    is_theoretical: Option<bool>,
}

/// A gate answer as a decision: `Some(true)`/`Some(false)` for a stated yes or
/// no, `None` for anything else.
///
/// "unknown" must land on `None`. Treating it as a no would let an unanswered
/// question kill a finding, and treating it as a yes would let it through --
/// either way the judge would decide the finding by what it failed to say.
fn answered_yes(answer: &Option<String>) -> Option<bool> {
    let answer = answer.as_deref()?.trim().to_ascii_lowercase();
    match answer.as_str() {
        "yes" | "true" | "confirmed" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

/// Apply the gate the prompt already states, to a verdict the model returned.
///
/// The prompt defines it: a hard NO on reachability or controllability kills the
/// finding, a YES on preconditions kills it, and passing the first three still
/// needs all four remaining answers affirmative. Anything short of that is
/// `needs_review`. Without this the seven questions were decoration -- the
/// parser read `verification_status` and dropped them, so `confirmed` was the
/// model's word with nothing behind it.
///
/// Returns a reason when the verdict was downgraded.
/// Whether the judge was shown any of the finding's code.
///
/// The prompt asks the seven questions "against the CODE SHOWN", and
/// `build_volatile_verification_tail` only emits code for a finding that has a
/// line to read around or a snippet attached. A finding with neither is graded
/// from its own description, so `confirmed` on one is a judgement about prose.
pub fn judge_saw_no_code(finding: &VulnerabilityFinding) -> bool {
    let no_snippet = finding
        .code_snippet
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty);
    no_snippet && finding.line_number.is_none()
}

/// Refute a confirmed finding by reading the code, not the model's opinion of it.
///
/// The seven gate questions are the model judging itself: it is shown ±5 lines
/// around the anchored line and asked whether a guard is present. When the guard
/// is there but outside that window, or the model simply misreads it, it answers
/// "no" and the finding survives.
///
/// This asks the same question the detection phase asks, from the same code. If
/// the function the title names contains a required security primitive, the
/// finding is a false positive -- decided by reading the body, not by asking.
/// No LLM call is involved, and the two phases can no longer disagree about
/// what a primitive is.
///
/// Only ever downgrades. A finding that is not confirmed is left alone.
pub fn refute_with_primitive_check(
    finding: &VulnerabilityFinding,
    status: VerificationStatus,
    notes: &str,
    primitives: &std::collections::HashMap<String, Vec<String>>,
) -> (VerificationStatus, String) {
    if status != VerificationStatus::Confirmed {
        return (status, notes.to_string());
    }
    if let Some((_body, found)) = anchored_body_containing_primitive(finding, primitives) {
        let reason = format!(
            "not confirmed: {} found in the body of the function this finding names",
            found
        );
        let merged = if notes.trim().is_empty() {
            reason
        } else {
            format!("{notes} ({reason})")
        };
        return (VerificationStatus::FalsePositive, merged);
    }
    (status, notes.to_string())
}

/// The body of the function the title names, if it contains a primitive.
///
/// Returns the body and which primitive matched, so the reason names the
/// evidence rather than asserting that a check happened.
fn anchored_body_containing_primitive(
    finding: &VulnerabilityFinding,
    primitives: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(String, String)> {
    let language = extract_language_from_path(&finding.file_path);
    let for_language = primitives.get(&language)?;
    if for_language.is_empty() {
        return None;
    }
    let name = crate::llm_analysis::function_names_in_title(&finding.title)
        .into_iter()
        .next()?;
    let content = std::fs::read_to_string(&finding.file_path).ok()?;
    let ranges = crate::llm_analysis::function_line_ranges(&content, &language);
    let (start, end) = *ranges.get(&name)?;

    let body = body_of(&content, start, end)?;
    let found = for_language
        .iter()
        .find(|p| !p.is_empty() && body.contains(p.as_str()))?
        .clone();
    Some((body, found))
}

/// The function body, by its 1-indexed line range.
fn body_of(content: &str, start_line: usize, end_line: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let from = start_line.checked_sub(1)?;
    let to = end_line.min(lines.len());
    if from >= to {
        return None;
    }
    Some(lines[from..to].join("\n"))
}

/// Cap a verdict on a finding the judge was shown nothing for.
///
/// A real finding can reach here without a line: a chunked file whose reported
/// position did not map, or a hook whose handler name the AST could not
/// resolve. Losing the line is the right outcome -- a wrong line is worse --
/// but it must not also buy a confirmation nobody checked.
pub fn cap_blind_verdict(
    status: VerificationStatus,
    finding: &VulnerabilityFinding,
    notes: &str,
) -> (VerificationStatus, String) {
    if status != VerificationStatus::Confirmed || !judge_saw_no_code(finding) {
        return (status, notes.to_string());
    }
    let reason = "not confirmed: no line and no snippet, so no code was shown to verify against";
    let merged = if notes.trim().is_empty() {
        reason.to_string()
    } else {
        format!("{notes} ({reason})")
    };
    (VerificationStatus::NeedsReview, merged)
}

fn apply_gate_parts(
    status: &mut VerificationStatus,
    gate: Option<&SevenQuestionGate>,
    proof: Option<&ImpactProof>,
) -> Option<String> {
    if *status != VerificationStatus::Confirmed {
        return None;
    }
    // A Confirmed verdict without a gate is a prompt bug or model error.
    // The prompt now explicitly asks for the gate, so its absence is visible.
    // Fail loudly by downgrading to NeedsReview rather than silently passing.
    let gate = match gate {
        Some(g) => g,
        None => {
            *status = VerificationStatus::NeedsReview;
            return Some("gate: missing seven_question_gate for confirmed verdict".to_string());
        }
    };

    if answered_yes(&gate.reachability) == Some(false) {
        *status = VerificationStatus::FalsePositive;
        return Some("gate: not reachable from user input".to_string());
    }
    if answered_yes(&gate.controllability) == Some(false) {
        *status = VerificationStatus::FalsePositive;
        return Some("gate: attacker does not control the input".to_string());
    }
    if answered_yes(&gate.preconditions) == Some(true) {
        *status = VerificationStatus::FalsePositive;
        return Some("gate: blocked by existing validation".to_string());
    }
    if answered_yes(&gate.context) == Some(false) {
        *status = VerificationStatus::FalsePositive;
        return Some("gate: test or example code, not a production path".to_string());
    }
    if answered_yes(&gate.impact) == Some(false) {
        *status = VerificationStatus::FalsePositive;
        return Some("gate: no concrete security impact".to_string());
    }
    if answered_yes(&gate.evidence) == Some(false) {
        *status = VerificationStatus::NeedsReview;
        return Some("gate: no code evidence for the claim".to_string());
    }
    if answered_yes(&gate.confidence) == Some(false) {
        *status = VerificationStatus::NeedsReview;
        return Some("gate: judge does not hold it a true positive".to_string());
    }

    // The prompt requires a concrete impact scenario, and downgrades a
    // theoretical one. A confirmed finding with none is unbacked.
    if let Some(proof) = proof {
        let empty = proof
            .attack_vector
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty);
        if empty || proof.is_theoretical == Some(true) {
            *status = VerificationStatus::NeedsReview;
            return Some("gate: impact is theoretical or unstated".to_string());
        }
    }

    None
}

/// Load the verification prompt from prompts/phases/llm_verification.md.
/// This is the single source of truth for the LLM Verification phase prompt.
pub fn load_verification_prompt() -> String {
    let loaded = load_phase_prompts(None);
    let prompt = loaded.get("llm_verification").map(String::as_str);
    match prompt {
        Some(text) if !text.trim().is_empty() => text.to_string(),
        other => panic!(
            "prompts/phases/llm_verification.md is missing or empty (loaded value: {:?}). \
             The verification phase cannot run without its prompt: an empty prompt sent to the \
             model produces arbitrary verdicts for every finding, and they would be recorded as \
             if they were the model's reasoned answer. This is a packaging fault, not a runtime \
             condition to recover from.",
            other.unwrap_or("<absent>")
        ),
    }
}

/// Build stable prefix for verification prompt (byte-stable across findings in same phase+domain)
/// Returns the prefix that should be cached by LLM providers.
pub fn build_stable_verification_prefix(
    findings: &[VulnerabilityFinding],
    hunt_prompts: &HashMap<String, String>,
    required_primitives: &HashMap<String, Vec<String>>,
) -> String {
    // Load the prompt from the .md file - this is the single source of truth
    let mut prefix = load_verification_prompt();

    // Add hunt domain guidance (stable within phase+domain)
    let mut added_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    for finding in findings {
        if let Some(domain) = finding
            .cwe_id
            .as_ref()
            .and_then(|cwe| cwe_to_hunt_domain(cwe))
        {
            let domain_str = domain.to_string();
            if added_domains.insert(domain_str.clone()) {
                if let Some(hunt_prompt) = hunt_prompts.get(&domain_str) {
                    if !hunt_prompt.is_empty() {
                        prefix.push_str(&format!(
                            "=== HUNT DOMAIN GUIDANCE ({}) ===\n{}\n=== END HUNT GUIDANCE ===\n\n",
                            domain_str, hunt_prompt
                        ));
                    }
                }
            }
        }
    }

    // Add required security primitives section per language
    // Build set of languages present in findings based on file extensions
    let mut finding_languages: std::collections::HashSet<String> = std::collections::HashSet::new();
    for finding in findings {
        let lang = extract_language_from_path(&finding.file_path);
        finding_languages.insert(lang);
    }

    // Sort language keys alphabetically for byte-stable output
    let mut sorted_langs: Vec<&String> = required_primitives
        .keys()
        .filter(|k| finding_languages.contains(*k))
        .collect();
    sorted_langs.sort();

    for lang_key in sorted_langs {
        if let Some(primitives) = required_primitives.get(lang_key) {
            if !primitives.is_empty() {
                let primitives_str = primitives.join(", ");
                prefix.push_str(&format!(
                    "## Required Security Primitives (language: {})\n\
                     For findings in {} files that describe privileged actions (database writes, option updates, capability-gated routes, AJAX/REST handlers), the following framework primitives MUST be present in the shown code or surrounding context before the privileged action:\n\
                     {}\n\
                     If NONE of these primitives appear in the code or its surrounding context, treat the ABSENCE as evidence strengthening the finding (missing CSRF/authorization control). If any primitive IS present, treat it as a mitigating factor and record it in mitigating_factors.\n\n",
                    lang_key, lang_key, primitives_str
                ));
            }
        }
    }

    prefix
}

/// Extract language key from file path for required primitives matching.
/// .phtml -> "php"; otherwise extension string as-is.
pub fn extract_language_from_path(file_path: &str) -> String {
    if let Some(ext) = std::path::Path::new(file_path).extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        if ext_str == "phtml" {
            return "php".to_string();
        }
        return ext_str;
    }
    String::new()
}

/// Build volatile tail for verification prompt (finding-specific content)
/// This content varies per finding and should come AFTER the stable prefix.
pub fn build_volatile_verification_tail(
    findings: &[VulnerabilityFinding],
    _hunt_prompts: &HashMap<String, String>,
) -> String {
    let mut tail = String::new();

    for (i, finding) in findings.iter().enumerate() {
        tail.push_str(&format!(
            "Finding #{}: {}\n\
             Location: {}:{}\n\
             Description: {}\n\
             Sources: {:?}\n",
            i,
            finding.title,
            finding.file_path,
            finding.line_number.unwrap_or(0),
            finding.description,
            finding.sources
        ));

        if let Some(ref snippet) = finding.code_snippet {
            tail.push_str(&format!("Vulnerable code:\n```\n{}\n```\n", snippet));
        }

        // Add surrounding code context from disk (±5 lines)
        if let Some(line_num) = finding.line_number {
            if let Ok(content) = fs::read_to_string(&finding.file_path) {
                let lines: Vec<&str> = content.lines().collect();
                let start = if line_num >= 6 {
                    (line_num - 6) as usize
                } else {
                    0
                };
                let end = std::cmp::min(line_num as usize + 5, lines.len());
                let context_lines: Vec<String> = (start..end)
                    .map(|i| format!("{:5}: {}", i + 1, lines[i]))
                    .collect();
                tail.push_str(&format!(
                    "Code context ({}:{}):\n{}\n",
                    finding.file_path,
                    line_num,
                    context_lines.join("\n")
                ));
            }
        }

        tail.push_str("\n---\n\n");
    }

    tail.push_str(
         "Return JSON array now. Each element must include:\n\
          - \"index\": <0-based position of the finding in the batch (0, 1, 2, ...)>\n\
          - \"verification_status\": \"confirmed|false_positive|needs_review\"\n\
          - \"verification_notes\": \"detailed reasoning including gate answers and seven-question gate application\"\n\
          - \"seven_question_gate\": {\"reachability\": \"yes|no|unknown\", \"controllability\": \"yes|no|unknown\", \"preconditions\": \"yes|no|unknown\", \"impact\": \"yes|no|unknown\", \"context\": \"yes|no|unknown\", \"evidence\": \"yes|no|unknown\", \"confidence\": \"yes|no|unknown\"}\n\
          - \"concrete_impact_proof\": {\"attack_vector\": \"exact attack scenario with input and location\", \"consequence\": \"specific security impact\", \"is_theoretical\": true|false}\n\
          Example: [{\"index\": 0, \"verification_status\": \"confirmed\", \"seven_question_gate\": {...}, \"concrete_impact_proof\": {...}}, ...]\n"
     );
    tail
}

/// Parse batch verification verdict from LLM output.
/// Returns Vec of (status, notes) per finding index.
/// Failed items become NeedsReview with raw text in notes.
///
/// Supports two modes:
/// - Index-based: When verdicts include "index" field, match by index
/// - Positional fallback: When index is missing, use array order (with warning)
pub fn parse_batch_verification_verdict(
    content: &str,
    expected_count: usize,
) -> Vec<(VerificationStatus, String)> {
    let cleaned = content
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim_start_matches("json")
        .trim();

    match serde_json::from_str::<Vec<BatchVerdictItem>>(cleaned) {
        Ok(items) => {
            let mut results =
                vec![(VerificationStatus::NeedsReview, String::new()); expected_count];

            // Check if any item is missing index → positional fallback
            let has_index = items.iter().any(|item| item.index.is_some());
            let uses_fallback = !has_index;

            if uses_fallback {
                tracing::warn!(
                    "Batch verification response missing 'index' fields for {} items; using positional fallback",
                    items.len()
                );
            }

            for (pos, item) in items.into_iter().enumerate() {
                let idx = if let Some(index) = item.index {
                    index
                } else {
                    // Positional fallback
                    pos
                };

                if idx < expected_count {
                    let mut status = match item.verification_status.as_str() {
                        "confirmed" => VerificationStatus::Confirmed,
                        "false_positive" => VerificationStatus::FalsePositive,
                        _ => VerificationStatus::NeedsReview,
                    };
                    let mut notes = if item.verification_status.is_empty() {
                        "Batch parse missing verification_status for this item".to_string()
                    } else {
                        item.verification_notes.clone().unwrap_or_default()
                    };
                    if let Some(reason) = apply_gate_parts(
                        &mut status,
                        item.seven_question_gate.as_ref(),
                        item.concrete_impact_proof.as_ref(),
                    ) {
                        notes = if notes.is_empty() {
                            reason
                        } else {
                            format!("{notes} ({reason})")
                        };
                    }
                    results[idx] = (status, notes);
                }
            }

            // Mark missing items as NeedsReview
            for r in results.iter_mut().take(expected_count) {
                if r.1.is_empty() && r.0 == VerificationStatus::NeedsReview {
                    r.1 = "Batch parse missing this item".to_string();
                }
            }

            results
        }
        Err(_) => {
            // Entire batch failed - return all NeedsReview with raw content
            vec![(VerificationStatus::NeedsReview, content.to_string()); expected_count]
        }
    }
}

/// Verify findings in batches to reduce LLM API calls.
/// Returns tuple of (results Vec, positional_fallback_count).
pub async fn verify_findings_batched<C: LlmChatClient>(
    client: &C,
    findings: &[VulnerabilityFinding],
    batch_size: usize,
    hunt_prompts: &HashMap<String, String>,
    required_primitives: &HashMap<String, Vec<String>>,
) -> (Vec<(VerificationStatus, String)>, u64) {
    if batch_size <= 1 || findings.is_empty() {
        // Signal fallback needed by returning empty vec
        return (Vec::new(), 0);
    }

    let mut all_results = Vec::with_capacity(findings.len());
    let mut batch_start = 0;
    let mut total_fallback_count = 0u64;

    while batch_start < findings.len() {
        let batch_end = (batch_start + batch_size).min(findings.len());
        let batch = &findings[batch_start..batch_end];

        let prompt_text = format!(
            "{}{}",
            build_stable_verification_prefix(batch, hunt_prompts, required_primitives),
            build_volatile_verification_tail(batch, hunt_prompts)
        );
        let messages = vec![
            ChatMessage::system(
                "You are a security vulnerability verifier. Analyze findings and return JSON array verdicts.\n\
                 STRICT OUTPUT FORMAT: Return ONLY valid JSON array with no prose outside.\n\
                 Do NOT include any text before or after the JSON.",
            ),
            ChatMessage::user(&prompt_text),
        ];

        match client.chat(&messages).await {
            Ok(response) => {
                let results = parse_batch_verification_verdict(&response.content, batch.len());

                // Count positional fallbacks
                let cleaned = response
                    .content
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim_start_matches("json")
                    .trim();
                if let Ok(items) = serde_json::from_str::<Vec<BatchVerdictItem>>(cleaned) {
                    let has_index = items.iter().any(|item| item.index.is_some());
                    if !has_index && !items.is_empty() {
                        total_fallback_count += items.len() as u64;
                        tracing::warn!(
                            "Batch verification response missing 'index' fields for {} items; using positional fallback",
                            items.len()
                        );
                    }
                }

                all_results.extend(results);
            }
            Err(e) => {
                // Batch failed - mark all as NeedsReview
                tracing::warn!("Batch verification failed: {}", e);
                for _ in 0..batch.len() {
                    all_results.push((
                        VerificationStatus::NeedsReview,
                        format!("Batch error: {}", e),
                    ));
                }
            }
        }

        batch_start = batch_end;
    }

    // Log total fallback count for this batch verification
    if total_fallback_count > 0 {
        tracing::info!(
            "Total positional fallbacks in batch verification: {}",
            total_fallback_count
        );
    }

    (all_results, total_fallback_count)
}

/// Run LLM verification phase (phase 8 of 23).
pub async fn run_llm_verification(
    scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>, Vec<RejectedFinding>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack,
    } = cfg;

    tracing::info!("Running LLM verification phase...");
    let base = pb.position();
    let phase_num =
        crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::LlmVerification);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!(
        "Phase {}/{}: LLM verification (validating findings with AI analysis)...",
        phase_num, total
    ));

    let total_findings = findings.len();
    let use_agent_mode = config.agent.enabled;

    if let Some(_api_key) = &config.llm.phases.verification.api_key {
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        let client = match crate::llm::create_llm_client_with_metrics(scanner, "verification") {
            Some(client) => client,
            None => {
                tracing::warn!(
                    "Verification skipped: LLM client unavailable (incomplete llm.phases.verification config)"
                );
                pb.set_position(base + 100);
                return Ok((findings, analyzed_files.to_vec(), Vec::new()));
            }
        };

        if use_agent_mode {
            let progress_cb = Arc::new(move |msg: String| {
                tracing::debug!("Agent verify: {}", msg);
            });
            let agent_session =
                agent::AgentSession::new(client, &config.agent, target_path, progress_cb);

            for (i, finding) in findings.iter_mut().enumerate() {
                pb.set_position(progress_position(base, i, total_findings));
                pb.set_message(format!(
                    "Phase {}/{}: Agent verifying [{}/{}] - {}",
                    phase_num,
                    total,
                    i + 1,
                    total_findings,
                    finding.title
                ));

                match agent_session
                    .verify_finding(&finding.file_path, finding)
                    .await
                {
                    Ok(agent_finding) => {
                        let converted: crate::findings::VulnerabilityFinding =
                            agent_finding.into_finding();
                        finding.verification_status = converted.verification_status;
                        finding.verification_notes = converted
                            .verification_notes
                            .or(finding.verification_notes.clone());
                        if finding.agent_evidence_path.is_none() {
                            finding.agent_evidence_path = converted.agent_evidence_path;
                        }
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("verification".into()),
                            0.8,
                            format!(
                                "LLM verification verdict: {:?}",
                                finding.verification_status
                            ),
                        );
                        tracing::info!(
                            "Verification verdict [agent]: {:?} — {} ({}:{:?})",
                            finding.verification_status,
                            finding.title,
                            finding.file_path,
                            finding.line_number
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Agent verification failed for {}: {}",
                            finding.file_path,
                            e
                        );
                        finding.verification_status = Some(VerificationStatus::NeedsReview);
                        finding.verification_notes = Some(format!("Agent error: {}", e));
                    }
                }

                tokio::task::yield_now().await;
            }
        } else {
            // Non-agent mode: use direct LLM verification
            // Load hunt prompts once for all findings
            let hunt_prompts = load_hunt_prompts(None);

            // Use batched verification (batch_size=8 by default)
            // Note: config-overridable if a natural knob exists; currently hardcoded per T14 spec
            let batch_size = 8;

            if batch_size > 1 {
                // Batched path
                let batch_results = verify_findings_batched(
                    &client,
                    &findings,
                    batch_size,
                    &hunt_prompts,
                    &config.knowledge.required_security_primitives,
                )
                .await;

                // Apply batch results to findings
                let (batch_results, _fallback_count) = batch_results;
                for (i, finding) in findings.iter_mut().enumerate() {
                    pb.set_position(progress_position(base, i, total_findings));
                    pb.set_message(format!(
                        "Phase {}/{}: Verifying [{}/{}] - {} (batched)",
                        phase_num,
                        total,
                        i + 1,
                        total_findings,
                        finding.title
                    ));

                    if i < batch_results.len() {
                        let (status, notes) = &batch_results[i];
                        let (status, notes) = cap_blind_verdict(*status, finding, notes);
                        let (status, notes) = refute_with_primitive_check(
                            finding,
                            status,
                            &notes,
                            &config.knowledge.required_security_primitives,
                        );
                        finding.verification_status = Some(status);
                        finding.verification_notes = Some(notes.clone());
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("verification".into()),
                            0.8,
                            format!(
                                "LLM verification verdict: {:?}",
                                finding.verification_status
                            ),
                        );
                        tracing::info!(
                            "Verification verdict [batched]: {:?} — {} ({}:{:?})",
                            status,
                            finding.title,
                            finding.file_path,
                            finding.line_number
                        );
                    }
                }
            } else {
                // Per-finding fallback (original path)
                for (i, finding) in findings.iter_mut().enumerate() {
                    pb.set_position(progress_position(base, i, total_findings));
                    pb.set_message(format!(
                        "Phase {}/{}: Verifying findings [{}/{}] - {}",
                        phase_num,
                        total,
                        i + 1,
                        total_findings,
                        finding.title
                    ));

                    // Build stable prefix + volatile tail for prompt caching
                    let stable_prefix = build_stable_verification_prefix(
                        std::slice::from_ref(finding),
                        &hunt_prompts,
                        &config.knowledge.required_security_primitives,
                    );
                    let volatile_tail = build_volatile_verification_tail(
                        std::slice::from_ref(finding),
                        &hunt_prompts,
                    );
                    let prompt_text = format!("{}{}", stable_prefix, volatile_tail);

                    let messages = vec![
                        ChatMessage::system(
                            "You are a security vulnerability verifier. Analyze the finding and determine if it's a true positive, false positive, or needs review.\n\nSTRICT OUTPUT FORMAT: Return ONLY valid JSON with no prose outside the JSON object.\n\nJSON schema:\n{\n  \"verification_status\": \"confirmed|false_positive|needs_review\",\n  \"verification_notes\": \"detailed reasoning for the verdict\"\n}\n\nDo NOT include any text before or after the JSON.",
                        ),
                        ChatMessage::user(&prompt_text),
                    ];
                    let result = client.chat(&messages).await;

                    if let Ok(response_with_model) = result {
                        let (status, notes) =
                            parse_verification_verdict(&response_with_model.content);
                        let (status, notes) = cap_blind_verdict(status, finding, &notes);
                        let (status, notes) = refute_with_primitive_check(
                            finding,
                            status,
                            &notes,
                            &config.knowledge.required_security_primitives,
                        );
                        finding.verification_status = Some(status);
                        finding.verification_notes = Some(notes);
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("verification".into()),
                            0.8,
                            format!(
                                "LLM verification verdict: {:?}",
                                finding.verification_status
                            ),
                        );
                    }
                }
            }
        }
        pb.set_position(base + 100);
        pb.set_message(format!(
            "Phase {}/{}: Verification complete - verified {} findings",
            phase_num, total, total_findings
        ));
    } else {
        tracing::debug!("No API key for verification, skipping LLM verification");
        pb.set_message(format!(
            "Phase {}/{}: No API key configured - skipping verification",
            phase_num, phase_num
        ));
    }

    // Step 2: Generate PoCs for high-severity confirmed findings
    pb.set_message(format!(
        "Phase {}/{}: Generating PoCs for high-severity findings...",
        phase_num, total
    ));

    let context = crate::analysis_context::AnalysisContext::default();
    let poc_engine = PoCGenerationEngine::new();

    // Determine target languages for PoC based on project stack
    let poc_formats = if let Some(stack) = project_stack {
        let mut formats = Vec::new();
        for lang in &stack.languages {
            match lang.to_lowercase().as_str() {
                "rust" => formats.push(PoCFormat::Rust),
                "python" => formats.push(PoCFormat::Python),
                "javascript" | "typescript" => formats.push(PoCFormat::Python), // Default to Python for JS
                "go" => formats.push(PoCFormat::Go),
                _ => formats.push(PoCFormat::Python),
            }
        }
        if formats.is_empty() {
            formats.push(PoCFormat::Python)
        }
        formats
    } else {
        vec![PoCFormat::Python]
    };

    // Generate PoCs for findings that are confirmed or have high severity
    let high_severity_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.verification_status,
                Some(VerificationStatus::Confirmed) | None
            ) && f.severity.is_high_or_critical()
        })
        .cloned()
        .collect();

    if !high_severity_findings.is_empty() {
        let poc_result = poc_engine.generate(&high_severity_findings, &context, &poc_formats);
        let poc_count = poc_result.proofs.len();

        for poc in &poc_result.proofs {
            if let Some(finding) = findings.iter_mut().find(|f| f.id == poc.finding_id) {
                finding.poc_code = Some(poc.code.clone());
                finding.poc_format = Some(match poc.format {
                    PoCFormat::Rust => "rust".to_string(),
                    PoCFormat::Python => "python".to_string(),
                    PoCFormat::Shell => "shell".to_string(),
                    PoCFormat::Go => "go".to_string(),
                });

                // Step 3: Validate PoC using compiler
                let lang_str = match poc.format {
                    PoCFormat::Rust => "rust",
                    PoCFormat::Python => "python",
                    PoCFormat::Shell => "shell",
                    PoCFormat::Go => "go",
                };

                let compile_result = PocCompiler::compile_check(&poc.code, lang_str);

                if compile_result.compiles {
                    tracing::debug!("PoC compiled successfully for finding {}", finding.id);
                } else {
                    tracing::warn!(
                        "PoC compilation failed for finding {}: {:?}",
                        finding.id,
                        compile_result.errors
                    );
                }
            }
        }

        // Also generate mitigation code
        for finding in &mut findings.iter_mut().filter(|f| {
            matches!(
                f.verification_status,
                Some(VerificationStatus::Confirmed) | None
            ) && f.severity.is_high_or_critical()
        }) {
            if let Some(mitigation) = poc_engine.generate_mitigation(finding) {
                finding.mitigation_code = Some(mitigation.code);
            }
        }

        tracing::info!(
            "Generated {} PoCs for {} high-severity findings",
            poc_count,
            high_severity_findings.len()
        );
    }

    pb.set_position(pb.position() + 100);

    // Separate rejected findings (FalsePositive status) with their reasons
    let mut kept_findings = Vec::new();
    let mut rejected_findings = Vec::new();

    for finding in findings {
        match finding.verification_status {
            Some(VerificationStatus::FalsePositive) => {
                let reason = finding.verification_notes.clone().unwrap_or_else(|| {
                    "Marked as false positive during LLM verification".to_string()
                });
                rejected_findings.push((finding, reason));
            }
            _ => kept_findings.push(finding),
        }
    }

    for (finding, reason) in &rejected_findings {
        let snippet: String = reason.chars().take(120).collect();
        tracing::info!("Rejected: {} — {}", finding.title, snippet);
    }
    tracing::info!(
        "Verification summary: {} kept, {} rejected",
        kept_findings.len(),
        rejected_findings.len()
    );

    Ok((kept_findings, analyzed_files.to_vec(), rejected_findings))
}

/// Parse a strict-JSON verification verdict from LLM output.
///
/// Code fences are stripped; if the text does not parse as the verdict
/// object, the finding degrades to `NeedsReview` with the raw response
/// preserved in the notes.
///
/// Salvage path: if strict parse fails and the content is a JSON array,
/// take element 0 and extract verification_notes/status from it.
pub fn parse_verification_verdict(content: &str) -> (VerificationStatus, String) {
    #[derive(Deserialize, Debug)]
    struct VerificationVerdict {
        #[serde(rename = "verification_status")]
        status: String,
        #[serde(rename = "verification_notes")]
        notes: Option<String>,
    }

    let cleaned = content
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim_start_matches("json")
        .trim();

    // Try strict parse first (existing behavior)
    match serde_json::from_str::<VerificationVerdict>(cleaned) {
        Ok(verdict) => {
            let status = match verdict.status.as_str() {
                "confirmed" => VerificationStatus::Confirmed,
                "false_positive" => VerificationStatus::FalsePositive,
                _ => VerificationStatus::NeedsReview,
            };
            let notes = verdict.notes.unwrap_or_default();
            (status, notes)
        }
        Err(_) => {
            // Salvage path: try to parse as JSON array and take element 0
            match serde_json::from_str::<serde_json::Value>(cleaned) {
                Ok(val) => {
                    if let Some(arr) = val.as_array() {
                        if let Some(first_elem) = arr.first().and_then(|v| v.as_object()) {
                            // Extract verification_notes
                            let notes = first_elem
                                .get("verification_notes")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_default();

                            // Extract status from verification_status or triage_verdict
                            let status_str = first_elem
                                .get("verification_status")
                                .or_else(|| first_elem.get("triage_verdict"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let status = match status_str {
                                "confirmed" => VerificationStatus::Confirmed,
                                "false_positive" => VerificationStatus::FalsePositive,
                                _ => VerificationStatus::NeedsReview,
                            };

                            (status, notes)
                        } else {
                            // Salvage failed - empty array or first element not an object
                            (VerificationStatus::NeedsReview, content.to_string())
                        }
                    } else {
                        // Not an array - fall back to raw content
                        (VerificationStatus::NeedsReview, content.to_string())
                    }
                }
                Err(_) => {
                    // Strict parse and salvage both failed - return raw content
                    (VerificationStatus::NeedsReview, content.to_string())
                }
            }
        }
    }
}
