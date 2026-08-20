//! Unit tests for src/context/triple_path.rs - TriplePathContext

use baco::context::control_path::Language;
use baco::context::triple_path::{ContextError, TriplePathContext};
use baco::retrieval::CweKnowledgeBase;

// ============================================================================
// TriplePathContext::build tests
// ============================================================================

#[test]
fn test_build_c_vulnerable_code() {
    let source = r#"
void vulnerable(char *input) {
    char buffer[100];
    strcpy(buffer, input);
}
"#;

    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");
    let result = TriplePathContext::build(source, Language::C, &kb, 3);

    assert!(result.is_ok());
    let context = result.unwrap();
    assert!(!context.control.ast_text.is_empty());
}

#[test]
fn test_build_rust_simple() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let result = TriplePathContext::build(source, Language::Rust, &kb, 2);

    assert!(result.is_ok());
    let context = result.unwrap();
    assert!(!context.control.ast_text.is_empty());
}

#[test]
fn test_build_python() {
    let source = "def test():\n    x = 1";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let result = TriplePathContext::build(source, Language::Python, &kb, 2);

    assert!(result.is_ok());
    let context = result.unwrap();
    assert!(!context.control.ast_text.is_empty());
}

#[test]
fn test_build_with_zero_top_k() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let result = TriplePathContext::build(source, Language::Rust, &kb, 0);

    assert!(result.is_ok());
    let context = result.unwrap();
    // Knowledge path may be empty with top_k=0
    assert!(context.knowledge.retrieved_rules.is_empty());
}

#[test]
fn test_build_large_top_k() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let result = TriplePathContext::build(source, Language::Rust, &kb, 100);

    assert!(result.is_ok());
    let context = result.unwrap();
    // Should have up to 100 results (or fewer if KB is smaller)
    assert!(context.knowledge.retrieved_rules.len() <= 100);
}

// ============================================================================
// TriplePathContext::with_semantic tests
// ============================================================================

#[test]
fn test_with_semantic_adds_summary() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).unwrap();

    assert!(context.semantic_summary.is_none());

    let context_with_semantic = context.with_semantic("Test summary".to_string());
    assert!(context_with_semantic.semantic_summary.is_some());
    assert_eq!(
        context_with_semantic.semantic_summary.unwrap(),
        "Test summary"
    );
}

#[test]
fn test_with_semantic_preserves_other_fields() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).unwrap();

    let ast_before = context.control.ast_text.clone();
    let cfg_before = context.control.cfg_text.clone();
    let knowledge_before = context.knowledge.retrieved_rules.len();

    let context_with_semantic = context.with_semantic("Test".to_string());

    assert_eq!(context_with_semantic.control.ast_text, ast_before);
    assert_eq!(context_with_semantic.control.cfg_text, cfg_before);
    assert_eq!(
        context_with_semantic.knowledge.retrieved_rules.len(),
        knowledge_before
    );
}

#[test]
fn test_with_semantic_can_be_chained() {
    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let context = TriplePathContext::build(source, Language::Rust, &kb, 1).unwrap();

    let context = context.with_semantic("First".to_string());
    let context = context.with_semantic("Second".to_string());

    assert_eq!(context.semantic_summary.unwrap(), "Second");
}

// ============================================================================
// TriplePathContext::to_prompt_section tests
// ============================================================================

#[test]
fn test_to_prompt_section() {
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    
    let cases = vec![
        (
            "header",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec!["%%TRIPLE_PATH_CONTEXT%%"],
        ),
        (
            "control_path",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec!["### Control Path", "AST Structure:", "Control Flow Graph:", "Data Flow Graph:"],
        ),
        (
            "knowledge_path",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec!["### Knowledge Path"],
        ),
        (
            "semantic_none",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec!["### Semantic Path", "(semantic summary not available)"],
        ),
        (
            "semantic_some",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            Some("Custom summary"),
            vec!["Custom summary"],
        ),
        (
            "knowledge_empty",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec!["### Knowledge Path"],
        ),
        (
            "non_empty",
            "fn test() { let x = 1; }",
            Language::Rust,
            1,
            None,
            vec![],
        ),
        (
            "multiple_knowledge_rules",
            r#"
void vulnerable(char *input) {
    char buffer[100];
    strcpy(buffer, input);
}
"#,
            Language::C,
            5,
            Some("Vulnerable function"),
            vec![
                "%%TRIPLE_PATH_CONTEXT%%",
                "### Control Path",
                "### Knowledge Path",
                "### Semantic Path",
                "Vulnerable function",
            ],
        ),
    ];

    for (name, source, lang, top_k, semantic, expected_contents) in cases {
        let context = TriplePathContext::build(source, lang, &kb, top_k).unwrap();
        let context = if let Some(summary) = semantic {
            context.with_semantic(summary.to_string())
        } else {
            context
        };

        let prompt = context.to_prompt_section();

        for expected in expected_contents {
            assert!(
                prompt.contains(expected),
                "{}: missing '{}', got:\n{}",
                name,
                expected,
                prompt
            );
        }

        if name == "non_empty" {
            assert!(!prompt.is_empty(), "{}: prompt should not be empty", name);
            assert!(prompt.len() > 50, "{}: prompt should have substantial content", name);
        }
    }
}

// ============================================================================
// ContextError tests
// ============================================================================

#[test]
fn test_context_error_display_control() {
    use baco::context::control_path::ContextError as ControlError;
    let err = ContextError::Control(ControlError::NoFunctions);
    let displayed = format!("{}", err);

    assert!(displayed.contains("Control path error"));
}

#[test]
fn test_context_error_display_knowledge() {
    use baco::context::knowledge_path::ContextError as KnowledgeError;
    let err = ContextError::Knowledge(KnowledgeError::EmptyQuery);
    let displayed = format!("{}", err);

    assert!(displayed.contains("Knowledge path error"));
}

#[test]
fn test_context_error_display_no_semantic() {
    let err = ContextError::NoSemantic;
    let displayed = format!("{}", err);

    assert!(displayed.contains("Semantic path not available"));
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn test_full_triple_path_workflow() {
    let source = r#"
#include <stdio.h>
#include <string.h>

void process_input(char *input) {
    char buffer[256];
    strcpy(buffer, input);
    printf("%s\n", buffer);
}
"#;

    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let context = TriplePathContext::build(source, Language::C, &kb, 3).unwrap();
    let context = context.with_semantic("Function that copies and prints user input".to_string());

    let prompt = context.to_prompt_section();

    // Verify all sections are present
    assert!(prompt.contains("%%TRIPLE_PATH_CONTEXT%%"));
    assert!(prompt.contains("AST Structure:"));
    assert!(prompt.contains("Control Flow Graph:"));
    assert!(prompt.contains("Data Flow Graph:"));
    assert!(prompt.contains("### Knowledge Path"));
    assert!(prompt.contains("### Semantic Path"));
    assert!(prompt.contains("Function that copies and prints user input"));
}

#[test]
fn test_triple_path_with_various_languages() {
    let languages = vec![
        (Language::C, "int main() { return 0; }"),
        (Language::Rust, "fn main() {}"),
        (Language::Python, "def main(): pass"),
        (Language::JavaScript, "function main() {}"),
    ];

    let kb = CweKnowledgeBase::load_embedded().unwrap();

    for (lang, source) in languages {
        let result = TriplePathContext::build(source, lang, &kb, 1);
        assert!(result.is_ok(), "Failed for language {:?}", lang);
    }
}
