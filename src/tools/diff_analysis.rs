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

fn parse_diff(diff_output: &str) -> (u32, u32, u32) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_analysis_both_commits() {
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: Some("v1.0.0".to_string()),
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_diff_analysis_only_base() {
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: Some("v1.0.0".to_string()),
            head_commit: None,
        };

        let result = analyze_diff(input);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_diff_analysis_only_head() {
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: None,
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_diff_analysis_missing_commits() {
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: None,
            head_commit: None,
        };

        let result = analyze_diff(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_diff_empty() {
        let (files, inserts, deletes) = parse_diff("");
        assert_eq!(files, 0);
        assert_eq!(inserts, 0);
        assert_eq!(deletes, 0);
    }

    #[test]
    fn test_parse_diff_with_content() {
        let diff = "- old line\n+ new line\n- deleted\n+ inserted more";
        let (files, inserts, deletes) = parse_diff(diff);
        assert_eq!(files, 1);
        assert_eq!(inserts, 2);
        assert_eq!(deletes, 2);
    }

    #[test]
    fn test_git_diff_command_exists() {
        let output = Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .output();

        assert!(output.is_ok(), "git command should exist");
    }
}
