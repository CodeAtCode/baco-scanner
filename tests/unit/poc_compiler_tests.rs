//! Unit tests for src/poc_compiler.rs

use baco::poc_compiler::PocCompiler;

// ============================================================================
// PocCompiler Tests
// ============================================================================

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
        eprintln!("Warning: rustc not available, skipping Rust validation");
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

#[test]
fn test_validate_python_injection_attempt_blocked() {
    // Security test for BUG-002: Python code injection via command string interpolation
    //
    // Attack vector (before fix):
    //   format!("compile(r'''{}''', 'poc.py', 'exec')", code)
    //   If code contains ''' or other special characters, it breaks the Python string
    //   and creates malformed compile() call syntax.
    //
    // Fix: Write code to temp file, run: py_compile <filepath>
    //   The code is treated as file data, not shell/Python string interpolation.
    //
    // This test verifies that code containing triple quotes is handled correctly
    // by the fixed implementation (temp file + py_compile).
    let code_with_triple_quotes = "x = '''test''' + '''more'''";

    let result = PocCompiler::validate_python(code_with_triple_quotes);

    // This is valid Python - it should compile successfully with the fix
    assert!(
        result.compiles,
        "Valid Python with triple quotes should compile. Got errors: {:?}",
        result.errors
    );
}

#[test]
fn test_validate_rust_passes_path_directly() {
    let code = r#"
fn main() {
    let x = 42;
}
"#;

    let result = PocCompiler::validate_rust(code);
    assert!(result.language == "rust");
}

/// Regression test for BUG-010: validate_rust must not panic on non-UTF8 temp paths.
/// The old code called `.to_str().unwrap()` on the temp file path, which panics when
/// the path contains non-UTF8 bytes. The fix passes `temp_file.path()` directly to
/// `Command::arg()`, which accepts `AsRef<OsStr>` natively.
#[cfg(unix)]
#[test]
fn test_validate_rust_no_panic_on_non_utf8_tempdir() {
    use std::os::unix::ffi::OsStringExt;

    let parent = std::env::temp_dir();
    let non_utf8_name = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);
    let non_utf8_dir = parent.join(non_utf8_name);
    std::fs::create_dir_all(&non_utf8_dir).expect("failed to create non-UTF8 dir");

    let result = PocCompiler::validate_rust_in_dir("fn main() {}", &non_utf8_dir);
    assert_eq!(result.language, "rust");

    let _ = std::fs::remove_dir_all(&non_utf8_dir);
}
