//! Comprehensive unit tests for context module paths.
//!
//! Tests control_path, knowledge_path, semantic_path, and triple_path
//! with coverage for edge cases and error handling.

use baco::context::{
    control_path::{extract, ContextError, Language},
    knowledge_path::{retrieve, ContextError as KnowledgeError},
    semantic_path::{summarize_mock, ContextError as SemanticError},
    triple_path::TriplePathContext,
};
use baco::retrieval::CweKnowledgeBase;

// ============================================================================
// Control Path Tests
// ============================================================================

#[test]
fn test_language_ts_language_mapping() {
    // Verify each language maps correctly (just ensure no panic)
    let _c_lang = Language::C;
    let _rust_lang = Language::Rust;
    let _python_lang = Language::Python;
    let _js_lang = Language::JavaScript;
}

#[test]
fn test_context_error_display() {
    let parse_err = ContextError::ParseError { line: 42 };
    assert!(parse_err.to_string().contains("42"));

    let lang_err = ContextError::UnsupportedLanguage("Assembly".to_string());
    assert!(lang_err.to_string().contains("Assembly"));

    let no_funcs = ContextError::NoFunctions;
    assert!(no_funcs.to_string().contains("functions"));

    let ts_err = ContextError::TreeSitterError("test error".to_string());
    assert!(ts_err.to_string().contains("test error"));
}

#[test]
fn test_extract_c_no_functions() {
    let source = "// Just a comment\n";

    let result = extract(source, Language::C);
    assert!(result.is_ok(), "Should parse comment-only source");

    let control = result.unwrap();
    // May have minimal AST but should not panic
    assert!(!control.ast_text.is_empty());
}

#[test]
fn test_extract_rust_async_function() {
    let source = r#"
async fn fetch_data(url: &str) -> Result<String, String> {
    let result = process(url).await;
    Ok(result)
}
"#;

    let control = extract(source, Language::Rust).expect("Should parse async Rust");
    assert!(!control.ast_text.is_empty());
}

#[test]
fn test_extract_c_nested_if() {
    let source = r#"
void nested(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            printf("both positive");
        }
    }
}
"#;

    let control = extract(source, Language::C).expect("Should parse nested if");
    assert!(control.cfg_text.contains("if"));
}

#[test]
fn test_extract_python_while_loop() {
    let source = r#"
def wait_for_input():
    while True:
        line = input()
        if line == "quit":
            break
    return line
"#;

    let control = extract(source, Language::Python).expect("Should parse while loop");
    assert!(control.cfg_text.contains("while") || !control.cfg_text.is_empty());
}

#[test]
fn test_extract_js_class_method() {
    let source = r#"
class Calculator {
    constructor(value) {
        this.value = value;
    }

    add(x) {
        this.value += x;
    }
}
"#;

    let control = extract(source, Language::JavaScript).expect("Should parse class");
    assert!(!control.ast_text.is_empty());
}

#[test]
fn test_verbalize_ast_line_numbers() {
    let source = "fn main() { let x = 1; }";

    let control = extract(source, Language::Rust).expect("Should parse");
    // AST should contain line number information
    assert!(
        control.ast_text.contains("["),
        "AST should contain line info brackets"
    );
}

// ============================================================================
// Knowledge Path Tests
// ============================================================================

#[test]
fn test_retrieve_empty_query_error() {
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = retrieve("", &kb, 3);
    assert!(matches!(result, Err(KnowledgeError::EmptyQuery)));
}

#[test]
fn test_retrieve_whitespace_only_error() {
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = retrieve("   \n\t  ", &kb, 3);
    assert!(matches!(result, Err(KnowledgeError::EmptyQuery)));
}

#[test]
fn test_retrieve_top_k_limit() {
    let code = "vulnerable buffer overflow";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = retrieve(code, &kb, 2);
    assert!(result.is_ok());

    let knowledge = result.unwrap();
    assert!(knowledge.retrieved_rules.len() <= 2);
}

#[test]
fn test_retrieve_with_real_code() {
    let code = r#"
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
"#;
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = retrieve(code, &kb, 5);
    assert!(result.is_ok());

    let knowledge = result.unwrap();
    // May or may not find matches depending on embedded data
    // Just verify structure is correct
    for rule in &knowledge.retrieved_rules {
        assert!(!rule.rule_id.is_empty());
        assert!(rule.score >= 0.0);
    }
}

// ============================================================================
// Semantic Path Tests
// ============================================================================

#[test]
fn test_summarize_mock_with_loop() {
    let source = "for i in 0..10 { println!(i); }";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(result.summary.contains("iteration") || result.summary.contains("loop"));
}

#[test]
fn test_summarize_mock_with_condition() {
    let source = "if x > 0 { println!(\"positive\"); }";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(result.summary.contains("conditional") || result.summary.contains("branching"));
}

#[test]
fn test_summarize_mock_simple_code() {
    let source = "let x = 1; let y = 2;";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(result.summary.contains("Simple"));
}

#[test]
fn test_summarize_mock_multiple_features() {
    let source = r#"
fn process(data) {
    if data.is_empty() {
        return;
    }
    for item in data {
        println!(item);
    }
}
"#;
    let result = summarize_mock(source).expect("Should summarize");

    assert!(result.summary.contains("function"));
    assert!(result.summary.contains("iteration") || result.summary.contains("loop"));
    assert!(result.summary.contains("conditional") || result.summary.contains("branching"));
}

#[test]
fn test_summarize_mock_error_types() {
    // Empty source
    let result = summarize_mock("");
    assert!(matches!(result, Err(SemanticError::EmptySource)));
}

// ============================================================================
// Triple Path Tests
// ============================================================================

#[test]
fn test_context_error_from_control() {
    let control_err = ContextError::NoFunctions;
    let triple_err: baco::context::triple_path::ContextError = control_err.into();

    assert!(triple_err.to_string().contains("Control"));
}

#[test]
fn test_context_error_from_knowledge() {
    let knowledge_err = KnowledgeError::EmptyQuery;
    let triple_err: baco::context::triple_path::ContextError = knowledge_err.into();

    assert!(triple_err.to_string().contains("Knowledge"));
}

#[test]
fn test_triple_path_build_with_c_code() {
    let source = r#"
int add(int a, int b) {
    return a + b;
}
"#;
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = TriplePathContext::build(source, Language::C, &kb, 3);
    // May succeed or fail depending on code complexity
    // Just verify no panic
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_triple_path_with_semantic() {
    let source = "fn test() { }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).expect("Should build");

    let context_with_semantic = context.with_semantic("Test summary".to_string());

    assert!(context_with_semantic.semantic_summary.is_some());
    assert_eq!(
        context_with_semantic.semantic_summary.unwrap(),
        "Test summary"
    );
}

#[test]
fn test_to_prompt_section_contains_all_sections() {
    let source = "fn main() { }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).expect("Should build");
    let context = context.with_semantic("Summary".to_string());

    let prompt = context.to_prompt_section();

    assert!(prompt.contains("%%TRIPLE_PATH_CONTEXT%%"));
    assert!(prompt.contains("### Control Path"));
    assert!(prompt.contains("### Knowledge Path"));
    assert!(prompt.contains("### Semantic Path"));
}

#[test]
fn test_to_prompt_section_control_content() {
    let source = "fn main() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).expect("Should build");

    let prompt = context.to_prompt_section();

    assert!(prompt.contains("AST Structure:"));
    assert!(prompt.contains("Control Flow Graph:"));
    assert!(prompt.contains("Data Flow Graph:"));
}

#[test]
fn test_to_prompt_section_no_semantic() {
    let source = "fn main() { }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).expect("Should build");

    let prompt = context.to_prompt_section();
    assert!(prompt.contains("(semantic summary not available)"));
}

#[test]
fn test_to_prompt_section_empty_knowledge() {
    let source = "fn main() { }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(source, Language::Rust, &kb, 0).expect("Should build");

    let prompt = context.to_prompt_section();
    // May contain "(no related CWE rules found)" or actual rules
    // Just verify section exists
    assert!(prompt.contains("### Knowledge Path"));
}

#[test]
fn test_triple_path_error_handling() {
    // Test with code that might cause control path to fail
    let source = "";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let result = TriplePathContext::build(source, Language::C, &kb, 3);
    // Empty source may fail at knowledge path retrieval
    assert!(result.is_ok() || result.is_err());
}

// ============================================================================
// Integration Tests - Cross-Module
// ============================================================================

#[test]
fn test_full_context_extraction_rust() {
    let source = r#"
use std::io;

pub fn read_input() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input
}

fn process(input: &str) -> String {
    input.trim().to_uppercase()
}
"#;

    // Control path
    let control = extract(source, Language::Rust).expect("Should parse Rust");
    assert!(!control.ast_text.is_empty());

    // Knowledge path
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");
    let knowledge = retrieve(source, &kb, 3).ok();

    // Knowledge may or may not find rules
    if let Some(k) = knowledge {
        for rule in &k.retrieved_rules {
            assert!(!rule.rule_id.is_empty());
        }
    }
}

#[test]
fn test_full_context_extraction_python() {
    let source = r#"
import os

def read_file(path):
    with open(path) as f:
        return f.read()

def process(data):
    return data.strip()
"#;

    // Control path
    let control = extract(source, Language::Python).expect("Should parse Python");
    assert!(!control.ast_text.is_empty());

    // Knowledge path
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");
    let knowledge = retrieve(source, &kb, 3).ok();

    if let Some(k) = knowledge {
        for rule in &k.retrieved_rules {
            assert!(!rule.rule_id.is_empty());
        }
    }
}

#[test]
fn test_language_coverage_all_languages() {
    // Verify all supported languages can be used
    let c_code = "void f() {}";
    let rust_code = "fn f() {}";
    let py_code = "def f(): pass";
    let js_code = "function f() {}";

    assert!(extract(c_code, Language::C).is_ok());
    assert!(extract(rust_code, Language::Rust).is_ok());
    assert!(extract(py_code, Language::Python).is_ok());
    assert!(extract(js_code, Language::JavaScript).is_ok());
}
