//! Integration test for context extraction in LLM prompts

use baco::context::{ContextExtractor, ContextSummary};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

/// Test that context extraction works correctly
#[test]
fn test_context_extractor_includes_functions() {
    let content = r#"
#include <stdio.h>

int vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow
    return 0;
}

int main() {
    char user_input[128];
    scanf("%s", user_input);
    vulnerable_function(user_input);
    return 0;
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("vuln.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    // Verify functions are extracted
    assert!(!summary.functions.is_empty());
    assert!(summary
        .functions
        .iter()
        .any(|f| f.name == "vulnerable_function"));
    assert!(summary.functions.iter().any(|f| f.name == "main"));

    // Verify imports are extracted
    assert!(!summary.imports.is_empty());
    assert!(summary.imports.contains(&"stdio.h".to_string()));

    // Verify module summary is generated
    assert!(!summary.module_summary.is_empty());
}

/// Test that context summary can be formatted for prompt injection
#[test]
fn test_context_formatting_for_prompt() {
    let summary = ContextSummary {
        file_path: Path::new("test.c").to_path_buf(),
        language: "c".to_string(),
        functions: vec![baco::context::FunctionSummary {
            name: "vulnerable_function".to_string(),
            signature: "int vulnerable_function(char *input)".to_string(),
            start_line: 3,
            end_line: 8,
        }],
        imports: vec!["stdio.h".to_string()],
        exports: vec![],
        call_relationships: vec![],
        module_summary: "Imports 1 modules, Defines 1 functions".to_string(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Functions"));
    assert!(formatted.contains("vulnerable_function"));
    assert!(formatted.contains("## Imports"));
    assert!(formatted.contains("stdio.h"));
    assert!(formatted.contains("## Module Purpose"));
}

/// Test context extraction for different languages
#[test]
fn test_context_extraction_multiple_languages() {
    // Test C
    let c_content = "#include <stdio.h>\nint main() { return 0; }";
    let tmp_dir = tempdir().unwrap();
    let c_path = tmp_dir.path().join("test.c");
    fs::write(&c_path, c_content).unwrap();
    let c_summary = ContextExtractor::extract(&c_path);
    assert_eq!(c_summary.language, "c");

    // Test Rust
    let rust_content = "fn main() { println!(\"Hello\"); }";
    let rust_path = tmp_dir.path().join("test.rs");
    fs::write(&rust_path, rust_content).unwrap();
    let rust_summary = ContextExtractor::extract(&rust_path);
    assert_eq!(rust_summary.language, "rust");

    // Test Python
    let py_content = "def main():\n    print('Hello')";
    let py_path = tmp_dir.path().join("test.py");
    fs::write(&py_path, py_content).unwrap();
    let py_summary = ContextExtractor::extract(&py_path);
    assert_eq!(py_summary.language, "python");

    // Test JavaScript
    let js_content = "function main() { console.log('Hello'); }";
    let js_path = tmp_dir.path().join("test.js");
    fs::write(&js_path, js_content).unwrap();
    let js_summary = ContextExtractor::extract(&js_path);
    assert_eq!(js_summary.language, "javascript");
}

/// Test that empty/unreadable files return empty context
#[test]
fn test_context_extraction_edge_cases() {
    let tmp_dir = tempdir().unwrap();

    // Empty file
    let empty_path = tmp_dir.path().join("empty.c");
    fs::write(&empty_path, "").unwrap();
    let empty_summary = ContextExtractor::extract(&empty_path);
    assert!(empty_summary.functions.is_empty());

    // Non-existent file
    let nonexistent_path = tmp_dir.path().join("nonexistent.c");
    let missing_summary = ContextExtractor::extract(&nonexistent_path);
    assert!(missing_summary.functions.is_empty());

    // Unrecognized extension
    let unknown_path = tmp_dir.path().join("test.unknown");
    fs::write(&unknown_path, "content").unwrap();
    let unknown_summary = ContextExtractor::extract(&unknown_path);
    assert!(unknown_summary.language.is_empty() || unknown_summary.language == "unknown");
    assert!(unknown_summary.functions.is_empty());
}

/// Test call relationship detection
#[test]
fn test_call_relationship_detection() {
    let content = r#"
void helper() {
    printf("helper\n");
}

void caller() {
    helper();
}

int main() {
    caller();
    return 0;
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    // Should detect that caller calls helper
    let has_relationship = summary
        .call_relationships
        .iter()
        .any(|rel| rel.contains("caller") && rel.contains("helper"));
    assert!(
        has_relationship,
        "Expected 'caller calls helper' relationship"
    );
}
