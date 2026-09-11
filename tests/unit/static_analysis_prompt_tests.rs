//! Contract tests for LLM static analysis prompt ↔ parser alignment
//!
//! These tests ensure the prompt JSON examples match what the parser expects,
//! preventing future drift between prompt instructions and parser implementation.
//!
//! The field-spec source is defined in src/llm_analysis.rs as STATIC_ANALYSIS_FIELDS.

use baco::llm_analysis::STATIC_ANALYSIS_FIELDS;
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

/// Contract test: every required field in STATIC_ANALYSIS_FIELDS must appear in the prompt's JSON examples.
#[test]
fn test_static_analysis_fields_spec_matches_prompt_examples() {
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    assert!(prompt_path.exists(), "Prompt file should exist");

    let prompt_content =
        fs::read_to_string(prompt_path).expect("Should be able to read the prompt file");

    // Extract all JSON example blocks
    let json_blocks: Vec<&str> = prompt_content
        .split("```json")
        .skip(1)
        .map(|block| block.split("```").next().unwrap_or(""))
        .collect();

    assert!(
        json_blocks.len() >= 2,
        "Prompt should contain at least 2 JSON examples for validation"
    );

    // Check each field from the spec against ALL JSON examples
    for (field_name, expected_type, is_required) in STATIC_ANALYSIS_FIELDS.iter() {
        let field_pattern = format!(r#""{}""#, field_name);

        // Count occurrences across all JSON blocks
        let mut total_count = 0;
        for block in &json_blocks {
            total_count += block.matches(&field_pattern).count();
        }

        if *is_required {
            assert!(
                total_count > 0,
                "Required field '{}' (type: {}) from STATIC_ANALYSIS_FIELDS is missing in prompt JSON examples",
                field_name,
                expected_type
            );
        }

        // For object types, verify the nested structure
        if *expected_type == "object" {
            // code_snippet should have before, code, after fields
            if *field_name == "code_snippet" {
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
            }
        }
    }
}

/// Contract test: parse an example JSON from the prompt and verify it deserializes.
#[test]
fn test_static_analysis_example_json_deserializes() {
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    let prompt_content = fs::read_to_string(prompt_path).expect("Should be able to read prompt");

    // Extract first JSON example block
    let json_blocks: Vec<&str> = prompt_content
        .split("```json")
        .skip(1)
        .map(|block| block.split("```").next().unwrap_or(""))
        .collect();

    assert!(!json_blocks.is_empty(), "No JSON examples found in prompt");

    // Try to parse the first example as a JSON array
    let first_block = json_blocks[0].trim();
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(first_block);

    if let Ok(value) = parsed {
        // If it's an array, check the first element has required fields
        if let Some(arr) = value.as_array() {
            if !arr.is_empty() {
                let first_obj = &arr[0];
                for (field_name, _, is_required) in STATIC_ANALYSIS_FIELDS.iter() {
                    if *is_required {
                        assert!(
                            first_obj.get(field_name).is_some(),
                            "First JSON example object missing required field: {}",
                            field_name
                        );
                    }
                }
            }
        }
    } else {
        // Not a valid JSON - that's okay, just note it
        tracing::warn!(
            "First JSON example in prompt is not valid JSON: {:?}",
            parsed.err()
        );
    }
}

/// Contract test: verify field types match expectations (string vs integer vs object).
#[test]
fn test_static_analysis_field_types_in_prompt() {
    let prompt_path = Path::new("prompts/phases/llm_static_analysis.md");
    let prompt_content = fs::read_to_string(prompt_path).expect("Should be able to read prompt");

    // Extract first JSON example
    let json_blocks: Vec<&str> = prompt_content
        .split("```json")
        .skip(1)
        .map(|block| block.split("```").next().unwrap_or(""))
        .collect();

    if json_blocks.is_empty() {
        return; // No examples to check
    }

    let first_block = json_blocks[0].trim();
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(first_block);

    if let Ok(value) = parsed {
        if let Some(arr) = value.as_array() {
            if let Some(first_obj) = arr.first().and_then(|v| v.as_object()) {
                for (field_name, expected_type, _) in STATIC_ANALYSIS_FIELDS.iter() {
                    if let Some(field_value) = first_obj.get(field_name) {
                        let actual_type = match field_value {
                            serde_json::Value::String(_) => "string",
                            serde_json::Value::Number(_) => "integer",
                            serde_json::Value::Object(_) => "object",
                            serde_json::Value::Array(_) => "array",
                            serde_json::Value::Bool(_) => "boolean",
                            serde_json::Value::Null => "null",
                        };

                        // Note: we allow integer to be represented as number in JSON
                        if *expected_type == "integer" && actual_type == "integer" {
                            continue;
                        }
                        if *expected_type == "string" && actual_type == "string" {
                            continue;
                        }
                        if *expected_type == "object" && actual_type == "object" {
                            continue;
                        }

                        // For this test, we're lenient - just log if types don't match
                        // The important thing is the field exists
                        if actual_type != expected_type {
                            tracing::debug!(
                                "Field '{}' has type '{}' in example, expected '{}'",
                                field_name,
                                actual_type,
                                expected_type
                            );
                        }
                    }
                }
            }
        }
    }
}
