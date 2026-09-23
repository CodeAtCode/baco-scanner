use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct DiffAnalysisInput {
    pub file_path: String,
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
    let base_provided = input.base_commit.is_some();
    let head_provided = input.head_commit.is_some();

    if !base_provided && !head_provided {
        return Err("Either base_commit or head_commit must be provided".into());
    }

    if base_provided && !head_provided {
        let base = input.base_commit.unwrap();
        let head = "HEAD".to_string();
        return run_diff(&input.file_path, Some(&base), &head);
    }

    if !base_provided && head_provided {
        let head = input.head_commit.unwrap();
        let base = "HEAD~1".to_string();
        return run_diff(&input.file_path, Some(&base), &head);
    }

    let base = input.base_commit.unwrap_or_else(|| "HEAD~1".to_string());
    let head = input.head_commit.unwrap_or_else(|| "HEAD".to_string());
    run_diff(&input.file_path, Some(&base), &head)
}

fn run_diff(
    file_path: &str,
    base: Option<&str>,
    head: &str,
) -> Result<DiffAnalysisOutput, Box<dyn std::error::Error>> {
    let base_str = base
        .map(|s| format!("{}..{}", s, head))
        .unwrap_or_else(|| head.to_string());

    let output = Command::new("git")
        .args(["diff", &base_str, "--", file_path])
        .current_dir(
            PathBuf::from(file_path)
                .parent()
                .unwrap_or(&PathBuf::from(".")),
        )
        .output()
        .map_err(|e| format!("Failed to execute git diff: {}", e))?;

    let diff_output = String::from_utf8_lossy(&output.stdout).to_string();
    let (files_changed, insertions, deletions) = parse_diff(&diff_output);

    Ok(DiffAnalysisOutput {
        diff_output,
        files_changed,
        insertions,
        deletions,
    })
}

pub fn parse_diff(diff_output: &str) -> (u32, u32, u32) {
    let lines: Vec<&str> = diff_output.lines().collect();

    let mut files_changed = 1u32;
    let mut insertions = 0u32;
    let mut deletions = 0u32;

    for line in &lines {
        if line.starts_with("+++ ") && !line.starts_with("+++++") {
            files_changed += 1;
        } else if line.starts_with("+") && !line.starts_with("+++") {
            insertions += 1;
        } else if line.starts_with("-") && !line.starts_with("---") {
            deletions += 1;
        }
    }

    if lines.is_empty() {
        return (0, 0, 0);
    }

    (files_changed, insertions, deletions)
}
/// List files changed in a git revspec (`git diff --name-only`), repo-relative.
/// `repo_path` should be the repository root or a directory inside it.
pub fn changed_files(repo_path: &str, revspec: &str) -> Result<Vec<std::path::PathBuf>, String> {
    let output = std::process::Command::new("git")
        .args(["-C", repo_path, "diff", "--name-only", revspec, "--"])
        .output()
        .map_err(|e| format!("Failed to run git diff: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(std::path::PathBuf::from)
        .collect())
}

/// Keep findings whose path matches the changed set. Compares exact paths
/// plus suffix matches on normalized separators, covering absolute finding
/// paths against repo-relative changed entries (and vice versa).
pub fn matches_changed_set(file_path: &str, changed: &[std::path::PathBuf]) -> bool {
    let normalized = file_path.replace('\\', "/");
    changed.iter().any(|p| {
        let entry = p.to_string_lossy().replace('\\', "/");
        normalized == entry
            || normalized.ends_with(format!("/{entry}").as_str())
            || entry.ends_with(format!("/{normalized}").as_str())
    })
}
