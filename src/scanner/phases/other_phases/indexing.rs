use std::path::PathBuf;

use crate::config::knowledge::HookRegistryLanguageConfig;
use crate::error::ScanResult;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::scanner::phases::PhaseConfig;

/// Record a file's hook registrations and flag entry points that cannot reach
/// any security primitive.
///
/// Both halves read the file, so they belong together: the content is already
/// in memory and the primitive check needs it for the handler bodies.
pub fn register_hooks_and_check_primitives(
    path: &std::path::Path,
    content: &str,
    lang_cfg: &HookRegistryLanguageConfig,
    primitives: &[String],
    hook_map: &mut std::collections::HashMap<String, Vec<crate::hook_registry::HookRegistration>>,
    findings: &mut Vec<VulnerabilityFinding>,
) {
    let registrations = crate::hook_registry::extract_hooks(content, lang_cfg);
    if registrations.is_empty() {
        return;
    }

    let path_str = path.to_string_lossy().to_string();
    hook_map.insert(path_str.clone(), registrations.clone());

    for unprotected in
        crate::hook_registry::find_unprotected_hooks(content, &registrations, primitives)
    {
        findings.push(unprotected_hook_finding(
            &path_str,
            &unprotected,
            primitives,
        ));
    }
}

/// Turn a hook with no reachable primitive into a finding.
///
/// The severity follows from what the hook exposes, not from the missing
/// primitive itself. A `wp_ajax_nopriv_` hook is reachable with no session at
/// all, so an absent authorisation check is missing authentication on a
/// critical function. The authenticated `wp_ajax_` variant still needs the
/// nonce, so the same gap is a CSRF surface instead.
fn unprotected_hook_finding(
    path: &str,
    unprotected: &crate::hook_registry::UnprotectedHook,
    primitives: &[String],
) -> VulnerabilityFinding {
    let (cwe, severity, gap) = if unprotected.unauthenticated {
        (
            "CWE-306",
            Severity::High,
            "reachable without authentication and with no security primitive",
        )
    } else {
        (
            "CWE-352",
            Severity::Medium,
            "reachable by a logged-in user with no CSRF primitive",
        )
    };

    let primitive_list = primitives
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let line = unprotected.line as u32;

    VulnerabilityFinding {
        id: VulnerabilityFinding::generate_id(path, Some(line), cwe),
        title: format!(
            "Missing security primitive on request entry point {}",
            unprotected.hook
        ),
        description: format!(
            "Hook `{}` is registered against `{}` at {}:{}, and it is {}.\n\n\
             None of the required security primitives ({}) appear in that \
             function's body or in the bodies of the functions it calls.",
            unprotected.hook, unprotected.handler, path, unprotected.line, gap, primitive_list,
        ),
        severity,
        confidence_score: 0.9,
        cwe_id: Some(cwe.to_string()),
        file_path: path.to_string(),
        line_number: Some(line),
        code_snippet: None,
        diff_hunk: None,
        recommendation: Some(format!(
            "Call one of the required primitives ({}) in `{}` before acting on the request.",
            primitive_list, unprotected.handler
        )),
        code_location: Some(format!("{}:{}", path, line)),
        already_reported: false,
        sources: vec!["hook_primitive_check".to_string()],
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
        evidence: Vec::new(),
        verification_tier: None,
    }
}

/// Run indexing phase (phase 1 of 23).
pub async fn run_indexing(
    scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    // Index the project with incremental scanning
    tracing::info!("Running indexing phase on {:?}", target_path);

    // Run incremental indexing
    let (index, _hash_store) = match crate::indexer::FileIndex::index_project_incremental(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
        Some(pb),
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Indexing failed: {}. Skipping phase.", e);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    // Extract framework hooks from language-matched files and save hook map
    // Skip entirely if no hook_registry config is provided
    let mut findings = findings;
    let _hook_map = if !config.knowledge.hook_registry.is_empty() {
        let mut hook_map: std::collections::HashMap<
            String,
            Vec<crate::hook_registry::HookRegistration>,
        > = std::collections::HashMap::new();

        for file_info in &index.files {
            // Only process files whose language has a hook_registry config entry
            let lang = file_info.language.to_lowercase();
            if let Some(lang_cfg) = config.knowledge.hook_registry.get(&lang) {
                if let Ok(content) = std::fs::read_to_string(&file_info.path) {
                    let primitives = config
                        .knowledge
                        .required_security_primitives
                        .get(&lang)
                        .cloned()
                        .unwrap_or_default();
                    register_hooks_and_check_primitives(
                        &file_info.path,
                        &content,
                        lang_cfg,
                        &primitives,
                        &mut hook_map,
                        &mut findings,
                    );
                }
            }
            // Also check .phtml extension as PHP alias
            if file_info
                .path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                == Some("phtml".to_string())
            {
                if let Some(lang_cfg) = config.knowledge.hook_registry.get("php") {
                    if let Ok(content) = std::fs::read_to_string(&file_info.path) {
                        let primitives = config
                            .knowledge
                            .required_security_primitives
                            .get("php")
                            .cloned()
                            .unwrap_or_default();
                        register_hooks_and_check_primitives(
                            &file_info.path,
                            &content,
                            lang_cfg,
                            &primitives,
                            &mut hook_map,
                            &mut findings,
                        );
                    }
                }
            }
        }

        // Save hook map if non-empty
        if !hook_map.is_empty() {
            let hook_map_path =
                crate::hook_registry::hook_map_path(PathBuf::from(&config.output.dir).as_path());
            if let Some(parent) = hook_map_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = crate::hook_registry::save_hook_map(&hook_map_path, &hook_map) {
                tracing::warn!("Failed to save hook map: {}", e);
            } else {
                tracing::info!("Saved hook map with {} entries", hook_map.len());
            }
        }

        hook_map
    } else {
        std::collections::HashMap::new()
    };

    // Record what the indexer actually matched. The summary reports this as
    // "indexed", and the field existed but nothing ever wrote it, so the line
    // always read 0.
    scanner
        .state
        .send_modify(|s| s.files_scanned = index.files.len());

    Ok((findings, analyzed_files.to_vec()))
}
