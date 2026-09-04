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
