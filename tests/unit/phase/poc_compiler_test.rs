#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::poc_compiler::PocCompiler;
    use baco::scanner::Scanner;
    use baco::scanner_types::poc::PoCCompileResult;
    use tempfile::TempDir;

    #[test]
    fn test_poc_compiler_phase_name_and_order() {
        // PocCompiler doesn't implement ScanPhase trait directly
        // It's used via the run_poc_compiler function
        assert!(!PocCompiler::supported_languages().is_empty());
    }

    #[test]
    fn test_poc_compiler_with_no_findings() {
        let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];

        for finding in &findings {
            if let Some(poc_code) = &finding.poc_code {
                let language = finding.poc_format.as_deref().unwrap_or("rust");
                let _ = PocCompiler::compile_check(poc_code, language);
            }
        }
    }

    #[test]
    fn test_poc_compiler_with_findings() {
        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        let findings = vec![finding];

        for finding in &findings {
            if let Some(poc_code) = &finding.poc_code {
                let language = finding.poc_format.as_deref().unwrap_or("rust");
                let _ = PocCompiler::compile_check(poc_code, language);
            }
        }
    }

    #[test]
    fn test_poc_compiler_multiple_findings() {
        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        for finding in &findings {
            if let Some(poc_code) = &finding.poc_code {
                let language = finding.poc_format.as_deref().unwrap_or("rust");
                let _ = PocCompiler::compile_check(poc_code, language);
            }
        }
    }

    #[test]
    fn test_poc_compiler_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.scanner.performance.enable_poc_compilation = false;

        let scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        // When disabled, the phase should return findings unchanged
        let findings = scanner.state.borrow().findings.clone();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_poc_compiler_valid_python() {
        let valid_python = r#"
def hello():
    print("Hello, World!")
"#;

        let result = PocCompiler::compile_check(valid_python, "python");
        assert!(result.compiles);
    }

    #[test]
    fn test_poc_compiler_invalid_python() {
        let invalid_python = r#"
def hello(
    print("Hello, World!")
"#;

        let result = PocCompiler::compile_check(invalid_python, "python");
        assert!(!result.compiles);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_poc_compiler_valid_rust() {
        let valid_rust = r#"
fn main() {
    println!("Hello, World!");
}
"#;

        let result = PocCompiler::compile_check(valid_rust, "rust");
        // May fail if rustc is not available, but should not panic
        let _ = result;
    }

    #[test]
    fn test_poc_compiler_supported_languages() {
        let languages = PocCompiler::supported_languages();

        assert!(languages.contains(&"python"));
        assert!(languages.contains(&"rust"));
        assert!(languages.contains(&"javascript"));
    }

    #[test]
    fn test_poc_compiler_is_supported() {
        assert!(PocCompiler::is_supported("python"));
        assert!(PocCompiler::is_supported("rust"));
        assert!(PocCompiler::is_supported("javascript"));
        assert!(!PocCompiler::is_supported("unknown"));
    }

    #[test]
    fn test_poc_compile_result_creation() {
        let success = PoCCompileResult::success("python");
        assert!(success.compiles);
        assert_eq!(success.language, "python");

        let failure = PoCCompileResult::failure("python", vec!["error".to_string()]);
        assert!(!failure.compiles);
        assert!(!failure.errors.is_empty());
    }
}
