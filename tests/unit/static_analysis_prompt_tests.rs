//! Contract tests for LLM static analysis prompt ↔ parser alignment
//!
//! These tests ensure the prompt JSON examples match what the parser expects,
//! preventing future drift between prompt instructions and parser implementation.

use std::fs;
use std::path::Path;

// ============================================================================
// Prompt-Parser Contract Tests
// ============================================================================

#[test]
fn test_static_analysis_prompt_contains_code_snippet_object() {
    // Read the prompt file
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    assert!(
        prompt_path.exists(),
        "Prompt file should exist at prompts/phases/llm_static_analysis.md"
    );

    let prompt_content =
        fs::read_to_string(prompt_path).expect("Should be able to read the prompt file");

    // Both JSON examples should contain the code_snippet object schema
    // Look for the pattern: "code_snippet": { "before": ..., "code": ..., "after": ... }
    assert!(
        prompt_content.contains(r#""code_snippet""#),
        "Prompt JSON examples must include the code_snippet field"
    );

    // Verify all three fields of the code_snippet object are present
    assert!(
        prompt_content.contains(r#""before""#),
        "code_snippet object must include 'before' field"
    );
    assert!(
        prompt_content.contains(r#""code""#),
        "code_snippet object must include 'code' field"
    );
    assert!(
        prompt_content.contains(r#""after""#),
        "code_snippet object must include 'after' field"
    );

    // Verify both JSON examples contain code_snippet (should appear at least twice)
    let code_snippet_count = prompt_content.matches(r#""code_snippet""#).count();
    assert!(
        code_snippet_count >= 2,
        "Both JSON examples in the prompt must contain code_snippet (found {} occurrences, expected at least 2)",
        code_snippet_count
    );
}

#[test]
fn test_static_analysis_prompt_fields_match_parser_requirements() {
    // Read the prompt file
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    assert!(prompt_path.exists(), "Prompt file should exist");

    let prompt_content =
        fs::read_to_string(prompt_path).expect("Should be able to read the prompt file");

    // The parser (llm_analysis.rs) reads these required fields:
    // - severity, title, description, line, cwe_id, code_snippet
    // The prompt examples must include all of these

    let required_fields = vec![
        ("severity", "Parser requires severity field"),
        ("title", "Parser requires title field"),
        ("description", "Parser requires description field"),
        ("line", "Parser requires line field"),
        ("cwe_id", "Parser requires cwe_id field"),
        (
            "code_snippet",
            "Parser requires code_snippet field for structural dedup",
        ),
    ];

    for (field, message) in required_fields {
        assert!(
            prompt_content.contains(&format!(r#""{}""#, field)),
            "{} - field '{}' not found in prompt JSON examples",
            message,
            field
        );
    }
}

#[test]
fn test_static_analysis_prompt_has_instruction_for_code_snippet() {
    // Read the prompt file
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    assert!(prompt_path.exists(), "Prompt file should exist");

    let prompt_content =
        fs::read_to_string(prompt_path).expect("Should be able to read the prompt file");

    // The prompt should include an instruction about including vulnerable lines
    // with context before/after
    let instruction_patterns = [
        "include the exact vulnerable lines",
        "context before",
        "context after",
        "vulnerable lines",
    ];

    let has_instruction = instruction_patterns.iter().any(|pattern| {
        prompt_content
            .to_lowercase()
            .contains(&pattern.to_lowercase())
    });

    assert!(
        has_instruction,
        "Prompt should include instruction about including vulnerable lines with context"
    );
}

#[test]
fn test_static_analysis_prompt_json_examples_are_valid_structure() {
    // Read the prompt file
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    assert!(prompt_path.exists(), "Prompt file should exist");

    let prompt_content =
        fs::read_to_string(prompt_path).expect("Should be able to read the prompt file");

    // Extract JSON blocks from markdown
    let json_blocks: Vec<&str> = prompt_content
        .split("```json")
        .skip(1) // Skip content before first ```json
        .map(|block| block.split("```").next().unwrap_or(""))
        .collect();

    assert!(
        json_blocks.len() >= 2,
        "Prompt should contain at least 2 JSON examples (found {})",
        json_blocks.len()
    );

    // Verify each JSON block contains the required structure
    for (i, block) in json_blocks.iter().enumerate().take(2) {
        assert!(
            block.contains(r#""severity""#),
            "JSON example {} must contain 'severity' field",
            i + 1
        );
        assert!(
            block.contains(r#""title""#),
            "JSON example {} must contain 'title' field",
            i + 1
        );
        assert!(
            block.contains(r#""line""#),
            "JSON example {} must contain 'line' field",
            i + 1
        );
        assert!(
            block.contains(r#""code_snippet""#),
            "JSON example {} must contain 'code_snippet' field",
            i + 1
        );
    }
}
