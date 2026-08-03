//! Shared test fixtures for prompt-related tests
//!
//! Used by: prompt_tests.rs, prompt_templates_tests.rs

use baco::prompt::templates::TemplateVariables;

/// Default template variables used across prompt tests
pub fn default_template_variables() -> TemplateVariables {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY1".to_string(), "value1".to_string());
    vars.insert("KEY2".to_string(), "value2".to_string());
    vars
}
