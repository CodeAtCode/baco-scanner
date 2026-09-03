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

    /// Check if a language is supported for PoC validation
    pub fn is_supported(language: &str) -> bool {
        matches!(
            language.to_lowercase().as_str(),
            "rust" | "python" | "python3" | "javascript" | "js" | "node"
        )
    }

    /// Return list of supported languages
    pub fn supported_languages() -> Vec<&'static str> {
        vec!["rust", "python", "python3", "javascript", "js", "node"]
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
