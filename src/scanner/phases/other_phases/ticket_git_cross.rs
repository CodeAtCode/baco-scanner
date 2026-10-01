use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::git_analysis::GitAnalyzer;
use crate::scanner::phases::PhaseConfig;

/// Run ticket cross-reference phase (phase 11 of 23).
pub async fn run_ticket_cross_ref(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    tracing::info!("Running ticket cross-reference phase...");

    let mut systems = Vec::new();
    for cfg in &config.tickets.systems {
        let ticket_system = crate::tickets::TicketSystem {
            name: format!("{} ({})", cfg.system_type, cfg.url),
            system_type: cfg.system_type.clone(),
            url: cfg.url.clone(),
            credentials: cfg.api_key.clone(),
        };
        systems.push(ticket_system);
    }

    if !systems.is_empty() {
        let searcher = crate::tickets::TicketSearcher::new(systems);
        for finding in &mut findings {
            let _references = searcher
                .search_for_finding(&finding.title)
                .await
                .unwrap_or_default();
            // Map to ticket_reference string (first match or None)
            if let Some(refs) = _references.first() {
                finding.ticket_reference = Some(format!(
                    "{}:{}:{}", // system:id:title
                    refs.system, refs.ticket_id, refs.title
                ));
            }
        }
    }
    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Whether `path` sits inside a git repository.
///
/// Walks up from `path` looking for `.git`, which is how git itself decides
/// whether it is in a work tree. Cheap, and it does not need git to work.
///
/// Public for tests: the warning it decides between is otherwise only reachable
/// through an async phase that needs a whole scanner.
pub fn looks_like_a_repository(path: &std::path::Path) -> bool {
    path.ancestors()
        .take(64)
        .any(|dir| dir.join(".git").exists())
}

/// Run Git analysis phase (phase 12 of 23).
pub async fn run_git_analysis(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::info!("Running Git analysis phase...");

    match GitAnalyzer::new(target_path.to_str().unwrap_or(".")) {
        Ok(analysis) => {
            let remote_url =
                crate::scanner::Scanner::get_git_remote_url(target_path.to_str().unwrap_or("."));
            for finding in &mut findings {
                #[allow(deprecated)]
                let _commits = analysis
                    .find_related_commits(&finding.file_path, finding.line_number)
                    .unwrap_or_default();
                if let Some(commit) = _commits.first() {
                    let commit_ref = if let Some(ref url) = remote_url {
                        let owner_repo = crate::scanner::Scanner::extract_owner_repo_from_url(url);
                        if let Some((owner, repo)) = owner_repo {
                            let short_hash = if commit.commit_hash.len() > 7 {
                                &commit.commit_hash[..7]
                            } else {
                                &commit.commit_hash
                            };
                            Some(format!(
                                "https://github.com/{}/{}/commit/{}",
                                owner, repo, short_hash
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(ref_url) = commit_ref {
                        finding.commit_reference = Some(ref_url);
                    } else {
                        finding.commit_reference = Some(format!(
                            "{}:{}:{}",
                            commit.commit_hash, commit.author, commit.commit_message
                        ));
                    }
                }
            }
        }
        Err(git_err) => {
            // Scanning an extracted archive is normal, and this fired on every
            // such run. A channel that shouts every time is a channel nobody
            // reads, which is how the triage fallback going silent went
            // unnoticed twice. Only a real repository failing is a warning.
            if looks_like_a_repository(target_path) {
                tracing::warn!("Git analysis failed in a git repository: {git_err}");
            } else {
                tracing::debug!("No git repository at {}: {git_err}", target_path.display());
            }
        }
    }
    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run cross-file analysis phase (phase 13 of 23).
pub async fn run_cross_file_analysis(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::info!("Running cross-file analysis phase...");
    findings = crate::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);

    let chains = crate::chain_analysis::ChainAnalyzer::analyze_chains(&findings);
    if !chains.is_empty() {
        tracing::info!(
            "Cross-file analysis detected {} attack chain(s); applying chain verdicts",
            chains.len()
        );
        crate::chain_analysis::apply_chain_verdicts(&mut findings, &chains);
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}
