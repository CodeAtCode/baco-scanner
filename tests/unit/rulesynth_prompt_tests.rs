//! Unit tests for prompt module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::prompt::build_prompt;

#[test]
fn test_build_prompt_contains_cwe() {
    let prompt = build_prompt("CWE-79", "python", 3);
    assert!(prompt.contains("CWE: CWE-79"));
    assert!(prompt.contains("Language: python"));
    assert!(prompt.contains("Maximum rules to generate: 3"));
}

#[test]
fn test_build_prompt_contains_requirements() {
    let prompt = build_prompt("CWE-89", "javascript", 5);
    assert!(prompt.contains("top-level \"rules:\" key"));
    assert!(prompt.contains("id:"));
    assert!(prompt.contains("patterns:"));
    assert!(prompt.contains("message:"));
    assert!(prompt.contains("languages:"));
    assert!(prompt.contains("severity:"));
}

#[test]
fn test_build_prompt_max_rules() {
    let prompt = build_prompt("CWE-22", "go", 10);
    assert!(prompt.contains("Maximum rules to generate: 10"));
    assert!(prompt.contains("Return at most 10 rules"));
}

#[test]
fn test_build_prompt_empty_cwe() {
    let prompt = build_prompt("", "python", 3);
    assert!(prompt.contains("CWE: "));
    assert!(prompt.contains("Language: python"));
}

#[test]
fn test_build_prompt_empty_language() {
    let prompt = build_prompt("CWE-79", "", 3);
    assert!(prompt.contains("CWE: CWE-79"));
    assert!(prompt.contains("Language: "));
}

#[test]
fn test_build_prompt_zero_max_rules() {
    let prompt = build_prompt("CWE-79", "python", 0);
    assert!(prompt.contains("Maximum rules to generate: 0"));
    assert!(prompt.contains("Generate 0 rules"));
}

#[test]
fn test_build_prompt_single_rule() {
    let prompt = build_prompt("CWE-79", "python", 1);
    assert!(prompt.contains("Maximum rules to generate: 1"));
    assert!(prompt.contains("Generate 1 rules"));
}

#[test]
fn test_build_prompt_long_cwe_number() {
    let prompt = build_prompt("CWE-123456789", "python", 3);
    assert!(prompt.contains("CWE: CWE-123456789"));
    assert!(prompt.contains("Generate 3 rules for CWE-CWE-123456789"));
}

#[test]
fn test_build_prompt_special_chars_language() {
    let prompt = build_prompt("CWE-79", "c++", 3);
    assert!(prompt.contains("Language: c++"));
    assert!(prompt.contains("languages: [c++]"));

    let prompt = build_prompt("CWE-89", "c#", 3);
    assert!(prompt.contains("Language: c#"));
    assert!(prompt.contains("languages: [c#]"));
}

#[test]
fn test_build_prompt_contains_yaml_separator() {
    let prompt = build_prompt("CWE-79", "python", 3);
    assert!(
        prompt.contains("---"),
        "Prompt should contain YAML document separator"
    );
}

#[test]
fn test_build_prompt_contains_example_structure() {
    let prompt = build_prompt("CWE-79", "python", 3);
    assert!(
        prompt.contains("rules:"),
        "Prompt should contain 'rules:' in example structure"
    );
}
