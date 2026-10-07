use git2::{DiffFormat, DiffOptions, Repository};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DiffAnalysisInput {
    pub file_path: String,
    pub repo_path: Option<String>,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiffAnalysisOutput {
    pub diff_output: String,
    pub files_changed: u32,
    pub insertions: u32,
    pub deletions: u32,
}

pub fn analyze_diff(
    input: DiffAnalysisInput,
) -> Result<DiffAnalysisOutput, Box<dyn std::error::Error>> {
    let base = match (&input.base_commit, &input.head_commit) {
        (Some(b), None) => b.clone(),
        (None, Some(h)) => {
            return run_diff(
                &input.file_path,
                input.repo_path.as_deref(),
                Some("HEAD~1"),
                h,
            );
        }
        (Some(b), Some(_h)) => b.clone(),
        (None, None) => return Err("Either base_commit or head_commit must be provided".into()),
    };
    let head = input.head_commit.unwrap_or_else(|| "HEAD".to_string());
    run_diff(
        &input.file_path,
        input.repo_path.as_deref(),
        Some(&base),
        &head,
    )
}

fn run_diff(
    file_path: &str,
    repo_path: Option<&str>,
    base: Option<&str>,
    head: &str,
) -> Result<DiffAnalysisOutput, Box<dyn std::error::Error>> {
    let range = base
        .map(|b| format!("{}..{}", b, head))
        .unwrap_or_else(|| head.to_string());
    validate_revspec(&range)?;

    let repo = Repository::open(repo_path.unwrap_or("."))?;

    let base_commit = if let Some(b) = base {
        let obj = repo.revparse_single(b)?;
        obj.peel_to_commit()?
    } else {
        repo.head()?.peel_to_commit()?
    };

    // The head revspec must resolve even though the diff is taken against the
    // working tree. Dropping this check made an unresolvable head succeed with an
    // empty result, which is the failure mode this file is meant to avoid.
    repo.revparse_single(head)?.peel_to_commit()?;

    let base_tree = base_commit.tree()?;

    let mut opts = DiffOptions::new();
    // Against the WORKING TREE, not HEAD. `git diff <base>` means "what changed
    // since base, including changes not yet committed" -- and an uncommitted fix
    // is the normal case for analysing a change before committing it. Diffing
    // base against HEAD's tree made every uncommitted change invisible and
    // returned an empty result that read as "nothing to see here".
    let diff = repo.diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut opts))?;

    // Check if file exists in diff
    let mut matched_path: Option<String> = None;
    diff.foreach(
        &mut |delta, _| {
            if matched_path.is_none() {
                if let Some(p) = delta.new_file().path() {
                    if path_matches(file_path, p) {
                        matched_path = Some(p.to_string_lossy().to_string());
                    }
                }
            }
            true
        },
        None,
        None,
        None,
    )?;

    if matched_path.is_none() {
        return Ok(DiffAnalysisOutput {
            diff_output: String::new(),
            files_changed: 0,
            insertions: 0,
            deletions: 0,
        });
    }

    // Single pass: collect diff output and count files
    let mut output = String::new();
    let mut files_changed = 0u32;
    let file_path_clone = file_path.to_string();

    diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        let content = std::str::from_utf8(line.content()).unwrap_or("");
        match line.origin() {
            '@' => {
                output.push_str(content);
            }
            ' ' | '+' | '-' => {
                output.push(line.origin());
                output.push_str(content);
            }
            _ => {
                // Same body as the '@' arm above. Git emits '@' for hunk headers,
                // and this branch already handled them, so the explicit arm was
                // redundant: a mutation run reported "delete match arm '@'" as a
                // survivor, and it is not observable either way. Kept separate
                // only to mark that this was checked rather than overlooked.
                output.push_str(content);
            }
        }
        true
    })?;

    diff.foreach(
        &mut |delta, _| {
            if let Some(p) = delta.new_file().path() {
                if path_matches(&file_path_clone, p) {
                    files_changed += 1;
                }
            }
            true
        },
        None,
        None,
        None,
    )?;

    let (mut insertions, mut deletions) = (0u32, 0u32);
    for line in output.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            insertions += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            deletions += 1;
        }
    }

    Ok(DiffAnalysisOutput {
        diff_output: output,
        files_changed,
        insertions,
        deletions,
    })
}

pub fn changed_files(repo_path: &str, revspec: &str) -> Result<Vec<PathBuf>, String> {
    let repo =
        Repository::open(repo_path).map_err(|e| format!("Failed to open repository: {}", e))?;
    validate_revspec(revspec)?;

    let mut opts = DiffOptions::new();
    opts.context_lines(0);

    // A revspec names either one side (the other being the working tree) or both
    // sides (a range). `HEAD~1...HEAD` is the form the CLI passes, and
    // revparse_single cannot parse it at all; treating a range as a single rev
    // made every ranged invocation fail to resolve.
    let diff = if revspec.contains("..") {
        let range = repo
            .revparse(revspec)
            .map_err(|e| format!("invalid revspec '{}': {}", revspec, e))?;
        let from = range
            .from()
            .and_then(|o| o.peel_to_commit().ok())
            .ok_or_else(|| format!("Could not resolve the left side of '{}'", revspec))?;
        let to = range
            .to()
            .and_then(|o| o.peel_to_commit().ok())
            .ok_or_else(|| format!("Could not resolve the right side of '{}'", revspec))?;
        repo.diff_tree_to_tree(
            Some(&from.tree().map_err(|e| e.to_string())?),
            Some(&to.tree().map_err(|e| e.to_string())?),
            Some(&mut opts),
        )
        .map_err(|e| format!("Failed to create diff: {}", e))?
    } else {
        let base_commit = repo
            .revparse_single(revspec)
            .map_err(|e| format!("invalid revspec '{}': {}", revspec, e))?
            .peel_to_commit()
            .map_err(|e| format!("Could not resolve '{}' in revspec: {}", revspec, e))?;
        let base_tree = base_commit
            .tree()
            .map_err(|e| format!("Failed to get tree for '{}': {}", revspec, e))?;
        repo.diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut opts))
            .map_err(|e| format!("Failed to create diff: {}", e))?
    };

    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(p) = delta.new_file().path() {
                files.push(p.to_path_buf());
            }
            true
        },
        None,
        None,
        None,
    )
    .map_err(|e| format!("Failed to process diff: {}", e))?;
    Ok(files)
}

/// Whether a path reported by git refers to `file_path`.
///
/// This was written twice: once inline in `run_diff` and once here. Only this
/// copy was reachable from a test, so a mutation run found `run_diff`'s copy
/// alive — changing `||` to `&&` there left the suite green. The two copies had
/// also drifted apart, so they are now one predicate.
///
/// The suffix rule anchors on `/`, which the inline copy did not: without the
/// anchor, file_path "foo.rs" matched "myfoo.rs" and a finding was reported as
/// touched by a commit that never touched it.
pub fn path_matches(file_path: &str, candidate: &Path) -> bool {
    let normalized = file_path.replace('\\', "/");
    let entry = candidate.to_string_lossy().replace('\\', "/");

    if normalized == entry {
        return true;
    }
    if entry.ends_with(&format!("/{normalized}")) {
        return true;
    }
    // A bare filename has no directory to anchor on, so compare basenames. This
    // is what the inline copy's third disjunct did.
    match (Path::new(file_path).file_name(), candidate.file_name()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

pub fn matches_changed_set(file_path: &str, changed: &[PathBuf]) -> bool {
    changed.iter().any(|p| path_matches(file_path, p))
}

pub fn validate_revspec(revspec: &str) -> Result<(), String> {
    if revspec.starts_with('-') {
        return Err(format!(
            "invalid revspec '{}': cannot start with '-' (would be interpreted as git option)",
            revspec
        ));
    }
    Ok(())
}
