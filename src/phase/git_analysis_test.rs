#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::create_ctx;
    use crate::findings::Severity;
    use crate::phase::git_analysis::GitAnalysisPhase;
    use crate::phase::helpers::create_test_finding;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_git_analysis_phase_name_and_order() {
        let phase = GitAnalysisPhase;
        assert_eq!(phase.name(), "GitAnalysis");
        assert_eq!(phase.order(), 7);
    }

    #[tokio::test]
    async fn test_git_analysis_phase_with_no_findings() {
        let (_temp_dir, mut ctx) = create_ctx!();

        let phase = GitAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_git_analysis_phase_with_findings() {
        let temp_dir = TempDir::new().unwrap();

        std::process::Command::new("git")
            .arg("init")
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to init git repo");

        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git email");

        std::process::Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git name");

        let test_file = temp_dir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").expect("Failed to write test file");

        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to add file");

        std::process::Command::new("git")
            .args(["commit", "-m", "security fix: initial commit"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to commit");

        let config = ScannerConfig::default();
        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Git test vulnerability", "test.rs", 1, Severity::Medium);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = GitAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_git_analysis_phase_with_cve_commit() {
        let temp_dir = TempDir::new().unwrap();

        std::process::Command::new("git")
            .arg("init")
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to init git repo");

        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git email");

        std::process::Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git name");

        let test_file = temp_dir.path().join("vuln.rs");
        std::fs::write(&test_file, "fn main() {}").expect("Failed to write test file");

        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to add file");

        std::process::Command::new("git")
            .args(["commit", "-m", "Fix CVE-2024-1234 vulnerability"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to commit");

        let config = ScannerConfig::default();
        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("CVE test", "vuln.rs", 1, Severity::High);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = GitAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_git_analysis_phase_without_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Non-git test", "test.rs", 1, Severity::Low);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = GitAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].commit_reference.is_none());
    }

    #[tokio::test]
    async fn test_git_analysis_phase_is_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = GitAnalysisPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_git_analysis_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();

        std::process::Command::new("git")
            .arg("init")
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to init git repo");

        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git email");

        std::process::Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to configure git name");

        for i in 1..=3 {
            let test_file = temp_dir.path().join(format!("file{}.rs", i));
            std::fs::write(&test_file, "fn main() {}").expect("Failed to write test file");
        }

        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to add files");

        std::process::Command::new("git")
            .args(["commit", "-m", "patch: initial files"])
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to commit");

        let config = ScannerConfig::default();
        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("Finding 1", "file1.rs", 1, Severity::High),
            create_test_finding("Finding 2", "file2.rs", 1, Severity::Medium),
            create_test_finding("Finding 3", "file3.rs", 1, Severity::Low),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = GitAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 3);
    }
}
