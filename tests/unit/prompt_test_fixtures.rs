//! Shared test fixtures for prompt-related tests
//!
//! Used by: prompt_tests

use baco::prompt::templates::TemplateVariables;

/// Asserts that every default prompt template is non-empty
pub fn assert_all_prompts_non_empty() {
    let prompts = baco::prompt::get_all_defaults();
    assert!(!prompts.indexing.is_empty(), "indexing prompt is empty");
    assert!(!prompts.semgrep.is_empty(), "semgrep prompt is empty");
    assert!(
        !prompts.llm_static_analysis.is_empty(),
        "llm_static_analysis prompt is empty"
    );
    assert!(
        !prompts.llm_discovery.is_empty(),
        "llm_discovery prompt is empty"
    );
    assert!(
        !prompts.llm_verification.is_empty(),
        "llm_verification prompt is empty"
    );
    assert!(
        !prompts.ticket_crossref.is_empty(),
        "ticket_crossref prompt is empty"
    );
    assert!(
        !prompts.git_analysis.is_empty(),
        "git_analysis prompt is empty"
    );
    assert!(
        !prompts.cross_file_analysis.is_empty(),
        "cross_file_analysis prompt is empty"
    );
    assert!(
        !prompts.confidence_scoring.is_empty(),
        "confidence_scoring prompt is empty"
    );
    assert!(
        !prompts.ai_aggregation.is_empty(),
        "ai_aggregation prompt is empty"
    );
    assert!(!prompts.reporting.is_empty(), "reporting prompt is empty");
}

/// Default template variables used across prompt tests
#[allow(dead_code)]
pub fn default_template_variables() -> TemplateVariables {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY1".to_string(), "value1".to_string());
    vars.insert("KEY2".to_string(), "value2".to_string());
    vars
}
