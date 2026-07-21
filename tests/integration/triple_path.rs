//! Integration tests for triple path context.

use baco::context::control_path::Language;
use baco::context::triple_path::TriplePathContext;
use baco::retrieval::CweKnowledgeBase;
use std::fs;

#[test]
fn test_triple_path_on_fixture_file() {
    let fixture_path = "tests/fixtures/triple_path_sample.c";

    let source = fs::read_to_string(fixture_path).expect("Should read fixture file");

    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE knowledge base");

    let context = TriplePathContext::build(&source, Language::C, &kb, 3)
        .expect("Should build triple path context");

    let prompt = context.to_prompt_section();

    assert!(!prompt.is_empty(), "Prompt section should not be empty");
    assert!(
        prompt.contains("### Control Path"),
        "Prompt should contain Control Path section"
    );
    assert!(
        prompt.contains("### Knowledge Path"),
        "Prompt should contain Knowledge Path section"
    );
    assert!(
        prompt.contains("### Semantic Path"),
        "Prompt should contain Semantic Path section"
    );
}

#[test]
fn test_triple_path_with_synthetic_kb() {
    let source = r#"
void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);
}
"#;

    // Create synthetic CWE knowledge base with 2-3 rules
    let json = r#"{
        "cwe_specifications": [
            {
                "cwe_id": "CWE-120",
                "name": "Buffer Copy without Checking Size of Input",
                "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
                "examples": ["strcpy(dest, src) without bounds checking"],
                "mitigation": "Use bounds-checking functions like strncpy"
            },
            {
                "cwe_id": "CWE-787",
                "name": "Out-of-bounds Write",
                "description": "The software writes data past the end, or before the beginning, of the intended buffer.",
                "examples": ["buffer overflow via array index"],
                "mitigation": "Validate array indices before access"
            }
        ]
    }"#;

    let kb = CweKnowledgeBase::load_from_json(json).expect("Should load synthetic knowledge base");

    assert_eq!(kb.len(), 2, "Should have 2 CWE documents");

    let context = TriplePathContext::build(source, Language::C, &kb, 2)
        .expect("Should build triple path context");

    assert!(
        !context.control.ast_text.is_empty(),
        "Control path should have AST"
    );
    assert!(
        !context.knowledge.retrieved_rules.is_empty(),
        "Knowledge path should have rules"
    );

    let prompt = context.to_prompt_section();
    assert!(
        prompt.contains("CWE-120") || prompt.contains("CWE-787"),
        "Should reference CWE rules"
    );
}

#[test]
fn test_triple_path_empty_knowledge_base() {
    let _source = "fn test() { }";

    let json = r#"{
        "cwe_specifications": []
    }"#;

    let result = CweKnowledgeBase::load_from_json(json);
    assert!(result.is_err(), "Empty KB should error");
}

#[test]
fn test_triple_path_multilanguage() {
    let python_source = r#"
def process_data(data):
    result = []
    for item in data:
        if item > 0:
            result.append(item * 2)
    return result
"#;

    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let context = TriplePathContext::build(python_source, Language::Python, &kb, 2)
        .expect("Should build triple path for Python");

    assert!(!context.control.ast_text.is_empty());
    assert!(
        context.control.dfg_text.contains("<-"),
        "DFG should show assignments"
    );
}
