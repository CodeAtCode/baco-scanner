//! Unit tests for semantic path extraction.

use baco::context::semantic_path::summarize_mock;

#[test]
fn test_summarize_mock_non_empty() {
    let source = "fn main() { println!(\"hello\"); }";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(!result.summary.is_empty(), "Summary should not be empty");
}

#[test]
fn test_summarize_mock_with_function() {
    let source = "fn main() { println!(\"hello\"); }";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(
        result.summary.contains("function"),
        "Should mention functions"
    );
}

#[test]
fn test_summarize_mock_empty_source() {
    let source = "";
    let result = summarize_mock(source);

    assert!(result.is_err(), "Should error on empty source");
}

#[test]
fn test_to_prompt_section_format() {
    use baco::context::control_path::{extract, Language};
    use baco::context::knowledge_path::retrieve;
    use baco::context::triple_path::TriplePathContext;
    use baco::retrieval::CweKnowledgeBase;

    let source = "fn test() { let x = 1; }";
    let kb = CweKnowledgeBase::load_embedded().expect("Should load CWE data");

    let control = extract(source, Language::Rust).expect("Should extract control path");
    let knowledge = retrieve(source, &kb, 2).expect("Should retrieve knowledge");

    let context = TriplePathContext {
        control,
        knowledge,
        semantic_summary: Some("Test function summary".to_string()),
    };

    let prompt = context.to_prompt_section();

    assert!(
        prompt.contains("### Control Path"),
        "Prompt should contain Control Path header"
    );
    assert!(
        prompt.contains("### Knowledge Path"),
        "Prompt should contain Knowledge Path header"
    );
    assert!(
        prompt.contains("### Semantic Path"),
        "Prompt should contain Semantic Path header"
    );
}

/// Integration test with real LLM - requires API key
#[test]
#[ignore = "requires LLM_API_KEY"]
fn test_summarize_with_real_llm() {
    // This test requires LLM_API_KEY environment variable
    // Run with: LLM_API_KEY=xxx cargo test test_summarize_with_real_llm -- --ignored

    use std::env;

    let api_key = env::var("LLM_API_KEY").ok();
    if api_key.is_none() {
        println!("Skipping real LLM test - no API key set");
        return;
    }

    let _source = "fn calculate_factorial(n: u32) -> u32 { if n <= 1 { 1 } else { n * calculate_factorial(n - 1) } }";

    // Note: This would need a proper LlmClient setup, skipped for now
    // let llm = LlmClient::new(...);
    // let result = summarize(source, &llm).await;
    // assert!(result.is_ok());

    println!("Real LLM test placeholder - needs full LlmClient setup");
}
