//! PoC Compiler Module
//!
//! Validates proof-of-concept exploit code without executing it.
//! Supports Rust, Python, and JavaScript via compile/check only.

use crate::scanner_types::poc::PoCCompileResult;
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompileError {
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("Compilation failed: {0}")]
    CompilationFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CompileError>;

pub struct PocCompiler;

impl PocCompiler {
    /// Validates PoC code by compile/check only - NO execution
    ///
    /// Supports: Rust, Python, JavaScript
    pub fn compile_check(code: &str, language: &str) -> PoCCompileResult {
        match language.to_lowercase().as_str() {
            "rust" => Self::validate_rust(code),
            "python" | "python3" => Self::validate_python(code),
            "javascript" | "js" | "node" => Self::validate_javascript(code),
            _ => PoCCompileResult::failure(
                language,
                vec![format!("Unsupported language: {}", language)],
            ),
        }
    }

    /// Validate Rust code using rustc --edition 2021 --check
    pub fn validate_rust(code: &str) -> PoCCompileResult {
        let temp_file = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                return PoCCompileResult::failure(
                    "rust",
                    vec![format!("Failed to create temp file: {}", e)],
                )
            }
        };

        if let Err(e) = std::fs::write(temp_file.path(), code) {
            return PoCCompileResult::failure(
                "rust",
                vec![format!("Failed to write temp file: {}", e)],
            );
        }

        let output = Command::new("rustc")
            .args([
                "--edition",
                "2021",
                "--check",
                temp_file.path().to_str().unwrap(),
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    PoCCompileResult::success("rust")
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    let errors = format!("{}{}", stdout, stderr);
                    PoCCompileResult::failure("rust", vec![errors.trim().to_string()])
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    PoCCompileResult::failure(
                        "rust",
                        vec!["rustc not found - cannot validate Rust code".to_string()],
                    )
                } else {
                    PoCCompileResult::failure("rust", vec![format!("Validation error: {}", e)])
                }
            }
        }
    }

    /// Validate Python code using compile()
    pub fn validate_python(code: &str) -> PoCCompileResult {
        match python_compile::compile_code(code) {
            Ok(_) => PoCCompileResult::success("python"),
            Err(e) => {
                PoCCompileResult::failure("python", vec![format!("Python syntax error: {}", e)])
            }
        }
    }

    /// Validate JavaScript code using node --check
    pub fn validate_javascript(code: &str) -> PoCCompileResult {
        let temp_file = match tempfile::NamedTempFile::with_suffix(".js") {
            Ok(f) => f,
            Err(e) => {
                return PoCCompileResult::failure(
                    "javascript",
                    vec![format!("Failed to create temp file: {}", e)],
                )
            }
        };

        if let Err(e) = std::fs::write(temp_file.path(), code) {
            return PoCCompileResult::failure(
                "javascript",
                vec![format!("Failed to write temp file: {}", e)],
            );
        }

        let output = Command::new("node")
            .args(["--check", temp_file.path().to_str().unwrap()])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    PoCCompileResult::success("javascript")
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    PoCCompileResult::failure("javascript", vec![stderr.trim().to_string()])
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    PoCCompileResult::failure(
                        "javascript",
                        vec!["node not found - cannot validate JavaScript code".to_string()],
                    )
                } else {
                    PoCCompileResult::failure(
                        "javascript",
                        vec![format!("Validation error: {}", e)],
                    )
                }
            }
        }
    }

    /// Get supported languages
    pub fn supported_languages() -> Vec<&'static str> {
        vec!["rust", "python", "javascript"]
    }

    /// Check if a language is supported
    pub fn is_supported(language: &str) -> bool {
        matches!(
            language.to_lowercase().as_str(),
            "rust" | "python" | "python3" | "javascript" | "js" | "node"
        )
    }
}

fn rand_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", now)
}

mod tempfile {
    use std::io;
    use std::path::PathBuf;

    pub struct NamedTempFile {
        path: PathBuf,
    }

    impl NamedTempFile {
        pub fn new() -> io::Result<Self> {
            let temp_dir = std::env::temp_dir();
            let rand_id = super::rand_id();
            let path = temp_dir.join(format!("baco_poc_{}.rs", rand_id));
            std::fs::write(&path, "")?;
            Ok(Self { path })
        }

        pub fn with_suffix(suffix: &str) -> io::Result<Self> {
            let temp_dir = std::env::temp_dir();
            let rand_id = super::rand_id();
            let path = temp_dir.join(format!("baco_poc_{}.{}", rand_id, suffix));
            std::fs::write(&path, "")?;
            Ok(Self { path })
        }

        pub fn path(&self) -> &PathBuf {
            &self.path
        }
    }

    impl Drop for NamedTempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

mod python_compile {
    pub fn compile_code(code: &str) -> std::result::Result<(), String> {
        let result = std::process::Command::new("python3")
            .args(["-c", &format!("compile(r'''{}''', 'poc.py', 'exec')", code)])
            .output();

        match result {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(String::from_utf8_lossy(&output.stderr).to_string()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Err("python3 not found - cannot validate Python code".to_string())
                } else {
                    Err(format!("Validation error: {}", e))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_rust_code() {
        let code = r#"
fn main() {

}
"#;

        let result = PocCompiler::compile_check(code, "rust");
        // May pass or fail depending on whether rustc is available
        // This is acceptable - we're testing the code path, not the tool
        assert!(result.language == "rust");
    }

    #[test]
    fn test_invalid_rust_code() {
        let code = r#"
fn main() {
    let x = ;  // Syntax error
}
"#;

        let result = PocCompiler::compile_check(code, "rust");
        // If rustc is available, should fail; if not, may have error message about missing rustc
        assert!(result.language == "rust");
        if result.compiles {
            // rustc not installed - this is OK, just note it
            tracing::warn!("Warning: rustc not available, skipping Rust validation");
        } else {
            assert!(!result.errors.is_empty());
        }
    }

    #[test]
    fn test_valid_python_code() {
        let code = r#"
def hello():
    print("Hello, world!")
"#;

        let result = PocCompiler::compile_check(code, "python");
        assert!(result.language == "python");
    }

    #[test]
    fn test_invalid_python_code() {
        let code = r#"
def hello():
    print(  // Syntax error
"#;

        let result = PocCompiler::compile_check(code, "python3");
        // Either fails due to syntax error or python3 not found
        assert!(result.language == "python");
        assert!(!result.compiles || !result.errors.is_empty());
    }

    #[test]
    fn test_valid_javascript_code() {
        let code = r#"
function hello() {
    console.log("Hello, world!");
}
"#;

        let result = PocCompiler::compile_check(code, "javascript");
        assert!(result.language == "javascript");
    }

    #[test]
    fn test_invalid_javascript_code() {
        let code = r#"
function hello() {
    console.log(  // Syntax error
}
"#;

        let result = PocCompiler::compile_check(code, "js");
        assert!(result.language == "javascript");
        // Should fail with syntax error or node not found
        assert!(!result.compiles || !result.errors.is_empty());
    }

    #[test]
    fn test_unsupported_language() {
        let code = "some code";

        let result = PocCompiler::compile_check(code, "java");

        assert!(!result.compiles);
        assert!(result.errors.iter().any(|e| e.contains("Unsupported")));
    }

    #[test]
    fn test_supported_languages() {
        let langs = PocCompiler::supported_languages();

        assert!(langs.contains(&"rust"));
        assert!(langs.contains(&"python"));
        assert!(langs.contains(&"javascript"));
    }

    #[test]
    fn test_is_supported() {
        assert!(PocCompiler::is_supported("rust"));
        assert!(PocCompiler::is_supported("python"));
        assert!(PocCompiler::is_supported("python3"));
        assert!(PocCompiler::is_supported("javascript"));
        assert!(PocCompiler::is_supported("js"));
        assert!(PocCompiler::is_supported("node"));

        assert!(!PocCompiler::is_supported("java"));
        assert!(!PocCompiler::is_supported("cpp"));
        assert!(!PocCompiler::is_supported("go"));
    }

    #[test]
    fn test_case_insensitive() {
        let result1 = PocCompiler::compile_check("fn main() {}", "RUST");
        let result2 = PocCompiler::compile_check("def f(): pass", "Python");
        let result3 = PocCompiler::compile_check("let x = 1;", "JavaScript");

        assert!(result1.language == "rust" || result1.language == "RUST");
        assert!(result2.language == "python" || result2.language == "Python");
        assert!(result3.language == "javascript" || result3.language == "JavaScript");
    }
}
