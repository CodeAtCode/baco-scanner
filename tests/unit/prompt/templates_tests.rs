//! Comprehensive unit tests for prompt templates module
//!
//! Tests cover:
//! - BacoPhase enum (Display, ordering, all 14 variants)
//! - ProjectType enum (Display, ordering, all 6 variants)
//! - TemplateVariables (CRUD operations, edge cases)
//! - DefaultPrompts (all 11 phase templates, Debug)
//! - get_default_prompt (all phases including Hunt/Validate)
//! - Template variable detection and content validation

use baco::prompt::templates::{
    get_all_defaults, get_default_prompt, get_hunt_prompt, get_template_variables, render_template,
    BacoPhase, ProjectType, TemplateVariables,
};
use std::collections::HashMap;

use crate::prompt_test_fixtures::default_template_variables;

// ============================================================================
// BacoPhase Tests
// ============================================================================

#[test]
fn test_baco_phase_display_all_variants() {
    assert_eq!(BacoPhase::Indexing.to_string(), "indexing");
    assert_eq!(BacoPhase::Semgrep.to_string(), "semgrep");
    assert_eq!(
        BacoPhase::LlmStaticAnalysis.to_string(),
        "llm_static_analysis"
    );
    assert_eq!(BacoPhase::LlmDiscovery.to_string(), "llm_discovery");
    assert_eq!(BacoPhase::LlmVerification.to_string(), "llm_verification");
    assert_eq!(BacoPhase::TicketCrossRef.to_string(), "ticket_crossref");
    assert_eq!(BacoPhase::GitAnalysis.to_string(), "git_analysis");
    assert_eq!(
        BacoPhase::CrossFileAnalysis.to_string(),
        "cross_file_analysis"
    );
    assert_eq!(
        BacoPhase::ConfidenceScoring.to_string(),
        "confidence_scoring"
    );
    assert_eq!(BacoPhase::AiAggregation.to_string(), "ai_aggregation");
    assert_eq!(BacoPhase::Reporting.to_string(), "reporting");
    assert_eq!(BacoPhase::Hunt.to_string(), "hunt");
    assert_eq!(BacoPhase::Validate.to_string(), "validate");
}

#[test]
fn test_baco_phase_all_variants_non_empty() {
    let phases = vec![
        BacoPhase::Indexing,
        BacoPhase::Semgrep,
        BacoPhase::LlmStaticAnalysis,
        BacoPhase::LlmDiscovery,
        BacoPhase::LlmVerification,
        BacoPhase::TicketCrossRef,
        BacoPhase::GitAnalysis,
        BacoPhase::CrossFileAnalysis,
        BacoPhase::ConfidenceScoring,
        BacoPhase::AiAggregation,
        BacoPhase::Reporting,
        BacoPhase::Hunt,
        BacoPhase::Validate,
    ];

    for phase in phases {
        let s = phase.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_baco_phase_ordering_lexicographic() {
    let phases = vec![
        BacoPhase::Indexing,
        BacoPhase::Semgrep,
        BacoPhase::LlmStaticAnalysis,
        BacoPhase::LlmDiscovery,
    ];

    let mut sorted = phases.clone();
    sorted.sort();

    assert_eq!(phases, sorted);
}

#[test]
fn test_baco_phase_eq() {
    assert_eq!(BacoPhase::Indexing, BacoPhase::Indexing);
    assert_ne!(BacoPhase::Indexing, BacoPhase::Semgrep);
}

// ============================================================================
// ProjectType Tests
// ============================================================================

#[test]
fn test_project_type_display_all_variants() {
    assert_eq!(ProjectType::CLI.to_string(), "cli");
    assert_eq!(ProjectType::Web.to_string(), "web");
    assert_eq!(ProjectType::Library.to_string(), "library");
    assert_eq!(ProjectType::Embedded.to_string(), "embedded");
    assert_eq!(ProjectType::Firmware.to_string(), "firmware");
    assert_eq!(ProjectType::Desktop.to_string(), "desktop");
}

#[test]
fn test_project_type_all_variants_non_empty() {
    let types = vec![
        ProjectType::CLI,
        ProjectType::Web,
        ProjectType::Library,
        ProjectType::Embedded,
        ProjectType::Firmware,
        ProjectType::Desktop,
    ];

    for t in types {
        let s = t.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_project_type_ordering_lexicographic() {
    let types = vec![ProjectType::CLI, ProjectType::Web, ProjectType::Library];

    let mut sorted = types.clone();
    sorted.sort();

    assert_eq!(types, sorted);
}

#[test]
fn test_project_type_eq() {
    assert_eq!(ProjectType::CLI, ProjectType::CLI);
    assert_ne!(ProjectType::CLI, ProjectType::Web);
}

// ============================================================================
// TemplateVariables Tests
// ============================================================================

#[test]
fn test_template_variables_new_is_empty() {
    let vars = TemplateVariables::new();
    assert!(vars.is_empty());
    assert_eq!(vars.len(), 0);
}

#[test]
fn test_template_variables_default_is_empty() {
    let vars = TemplateVariables::default();
    assert!(vars.is_empty());
}

#[test]
fn test_template_variables_insert_and_get() {
    let vars = default_template_variables();

    assert_eq!(vars.len(), 2);
    assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
    assert_eq!(vars.get("KEY2"), Some(&"value2".to_string()));
    assert_eq!(vars.get("NONEXISTENT"), None);
}

#[test]
fn test_template_variables_overwrite_value() {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY".to_string(), "first".to_string());
    vars.insert("KEY".to_string(), "second".to_string());

    assert_eq!(vars.len(), 1);
    assert_eq!(vars.get("KEY"), Some(&"second".to_string()));
}

#[test]
fn test_template_variables_empty_string_value() {
    let mut vars = TemplateVariables::new();
    vars.insert("EMPTY".to_string(), "".to_string());

    assert_eq!(vars.get("EMPTY"), Some(&"".to_string()));
}

// ============================================================================
// DefaultPrompts Tests
// ============================================================================

#[test]
fn test_default_prompts_all_fields_non_empty() {
    let prompts = get_all_defaults();

    assert!(!prompts.indexing.is_empty());
    assert!(!prompts.semgrep.is_empty());
    assert!(!prompts.llm_static_analysis.is_empty());
    assert!(!prompts.llm_discovery.is_empty());
    assert!(!prompts.llm_verification.is_empty());
    assert!(!prompts.ticket_crossref.is_empty());
    assert!(!prompts.git_analysis.is_empty());
    assert!(!prompts.cross_file_analysis.is_empty());
    assert!(!prompts.confidence_scoring.is_empty());
    assert!(!prompts.ai_aggregation.is_empty());
    assert!(!prompts.reporting.is_empty());
}

#[test]
fn test_default_prompts_debug_output() {
    let prompts = get_all_defaults();
    let debug_str = format!("{:?}", prompts);

    assert!(debug_str.contains("indexing"));
    assert!(debug_str.contains("semgrep"));
}

#[test]
fn test_default_prompts_indexing_contains_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.indexing.contains("%%PROJECT_PATH%%"));
    assert!(prompts.indexing.contains("%%FILE_EXTENSIONS%%"));
    assert!(prompts.indexing.contains("%%LANGUAGES%%"));
}

#[test]
fn test_default_prompts_semgrep_contains_security_keywords() {
    let prompts = get_all_defaults();
    assert!(prompts.semgrep.contains("Buffer overflow"));
    assert!(prompts.semgrep.contains("SQL injection"));
}

#[test]
fn test_default_prompts_llm_static_analysis_contains_cwe_ids() {
    let prompts = get_all_defaults();
    assert!(prompts.llm_static_analysis.contains("CWE-22"));
    assert!(prompts.llm_static_analysis.contains("CWE-79"));
    assert!(prompts.llm_static_analysis.contains("CWE-89"));
}

#[test]
fn test_default_prompts_llm_verification_contains_status_options() {
    let prompts = get_all_defaults();
    assert!(prompts.llm_verification.contains("confirmed"));
    assert!(prompts.llm_verification.contains("false_positive"));
}

#[test]
fn test_default_prompts_git_analysis_contains_git_commands() {
    let prompts = get_all_defaults();
    assert!(prompts.git_analysis.contains("git log"));
    assert!(prompts.git_analysis.contains("git blame"));
}

#[test]
fn test_default_prompts_reporting_contains_sarif() {
    let prompts = get_all_defaults();
    assert!(prompts.reporting.contains("SARIF"));
}

// ============================================================================
// get_default_prompt Tests - All BacoPhase Variants
// ============================================================================

#[test]
fn test_get_default_prompt_all_phases() {
    let phases = vec![
        (BacoPhase::Indexing, "%%PROJECT_PATH%%"),
        (BacoPhase::Semgrep, "security"),
        (BacoPhase::LlmStaticAnalysis, "CWE-"),
        (BacoPhase::LlmDiscovery, "%%FINDING_TITLE%%"),
        (BacoPhase::LlmVerification, "false_positive"),
        (BacoPhase::TicketCrossRef, "%%TICKET_SYSTEMS%%"),
        (BacoPhase::GitAnalysis, "git log"),
        (BacoPhase::CrossFileAnalysis, "data flow"),
        (BacoPhase::ConfidenceScoring, "confidence"),
        (BacoPhase::AiAggregation, "executive summary"),
        (BacoPhase::Reporting, "SARIF"),
    ];

    for (phase, expected_content) in phases {
        let prompt = get_default_prompt(&phase, &ProjectType::CLI);
        assert!(
            !prompt.is_empty(),
            "Prompt for {:?} should not be empty",
            phase
        );
        assert!(
            prompt.contains(expected_content),
            "Prompt for {:?} should contain {}",
            phase,
            expected_content
        );
    }
}

#[test]
fn test_get_default_prompt_t25_phases() {
    // Hunt, Validate variants resolve via loaded hunt prompts
    let hunt_prompt = get_default_prompt(&BacoPhase::Hunt, &ProjectType::Web);
    let validate_prompt = get_default_prompt(&BacoPhase::Validate, &ProjectType::Web);

    assert!(!hunt_prompt.is_empty());
    assert!(!validate_prompt.is_empty());
    // Hunt uses llm_discovery default
    assert!(hunt_prompt.contains("%%FINDING_TITLE%%"));
    // Validate uses llm_verification default
    assert!(validate_prompt.contains("false_positive"));
}

#[test]
fn test_get_default_prompt_all_phases_unique() {
    let prompts = get_all_defaults();

    let all_prompts = vec![
        &prompts.indexing,
        &prompts.semgrep,
        &prompts.llm_static_analysis,
        &prompts.llm_discovery,
        &prompts.llm_verification,
        &prompts.ticket_crossref,
        &prompts.git_analysis,
        &prompts.cross_file_analysis,
        &prompts.confidence_scoring,
        &prompts.ai_aggregation,
        &prompts.reporting,
    ];

    for i in 0..all_prompts.len() {
        for j in (i + 1)..all_prompts.len() {
            assert_ne!(all_prompts[i], all_prompts[j]);
        }
    }
}

#[test]
fn test_get_default_prompt_project_type_not_used() {
    let cli_prompt = get_default_prompt(&BacoPhase::Indexing, &ProjectType::CLI);
    let web_prompt = get_default_prompt(&BacoPhase::Indexing, &ProjectType::Web);

    assert_eq!(cli_prompt, web_prompt);
}

// ============================================================================
// Hunt Prompt Loader Tests
// ============================================================================

#[test]
fn test_get_hunt_prompt_non_empty_domains() {
    let mut hunt_prompts = HashMap::new();
    hunt_prompts.insert("injection".to_string(), "Injection hunt prompt".to_string());
    hunt_prompts.insert("xss".to_string(), "XSS hunt prompt".to_string());

    let injection = get_hunt_prompt("injection", &hunt_prompts);
    let xss = get_hunt_prompt("xss", &hunt_prompts);
    let missing = get_hunt_prompt("missing", &hunt_prompts);

    assert!(injection.is_some());
    assert!(xss.is_some());
    assert!(missing.is_none());
}

#[test]
fn test_get_hunt_prompt_empty_value_returns_none() {
    let mut hunt_prompts = HashMap::new();
    hunt_prompts.insert("empty".to_string(), "".to_string());

    let result = get_hunt_prompt("empty", &hunt_prompts);
    assert!(result.is_none());
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_template_variables_with_prompt_templates() {
    let mut vars = TemplateVariables::new();
    vars.insert("PROJECT_PATH".to_string(), "/tmp/test".to_string());

    let prompts = get_all_defaults();
    assert!(prompts.indexing.contains("%%PROJECT_PATH%%"));
}

#[test]
fn test_prompt_content_length_validation() {
    let prompts = get_all_defaults();

    assert!(prompts.indexing.len() > 100);
    assert!(prompts.semgrep.len() > 100);
    assert!(prompts.llm_static_analysis.len() > 200);
}

// ============================================================================
// Template Rendering Tests
// ============================================================================

#[test]
fn test_render_template_single_variable() {
    let template = "Hello {{NAME}}, welcome to {{PLACE}}!";
    let mut vars = TemplateVariables::new();
    vars.insert("NAME".to_string(), "Alice".to_string());
    vars.insert("PLACE".to_string(), "Rustland".to_string());
    let result = render_template(template, &vars);
    assert_eq!(result, "Hello Alice, welcome to Rustland!");
}

#[test]
fn test_render_template_percent_format() {
    let template = "Project: %%PROJECT_NAME%%, Path: %%PROJECT_PATH%%";
    let mut vars = TemplateVariables::new();
    vars.insert("PROJECT_NAME".to_string(), "baco".to_string());
    vars.insert("PROJECT_PATH".to_string(), "/src/baco".to_string());
    let result = render_template(template, &vars);
    assert_eq!(result, "Project: baco, Path: /src/baco");
}

#[test]
fn test_render_template_multiple_same_name() {
    let template = "{{VAR}} appears {{VAR}} twice";
    let mut vars = TemplateVariables::new();
    vars.insert("VAR".to_string(), "X".to_string());
    let result = render_template(template, &vars);
    assert_eq!(result, "X appears X twice");
}

#[test]
fn test_render_template_empty_variables() {
    let template = "Hello {{NAME}}!";
    let vars = TemplateVariables::new();
    let result = render_template(template, &vars);
    assert_eq!(result, "Hello {{NAME}}!");
}

#[test]
fn test_render_template_missing_variable() {
    let template = "Hello {{NAME}}!";
    let mut vars = TemplateVariables::new();
    vars.insert("OTHER".to_string(), "World".to_string());
    let result = render_template(template, &vars);
    assert_eq!(result, "Hello {{NAME}}!");
}

#[test]
fn test_render_template_empty_template() {
    let result = render_template("", &TemplateVariables::new());
    assert_eq!(result, "");
}

#[test]
fn test_render_template_single_var_only() {
    let mut vars = TemplateVariables::new();
    vars.insert("ONLY".to_string(), "val".to_string());
    let result = render_template("{{ONLY}}", &vars);
    assert_eq!(result, "val");
}

#[test]
fn test_render_template_no_vars() {
    let result = render_template("Static text", &TemplateVariables::new());
    assert_eq!(result, "Static text");
}

#[test]
fn test_render_template_empty_value() {
    let mut vars = TemplateVariables::new();
    vars.insert("NAME".to_string(), "".to_string());
    let result = render_template("Hello {{NAME}}!", &vars);
    assert_eq!(result, "Hello !");
}

#[test]
fn test_get_template_variables_braces() {
    let template = "Hello {{NAME}}, welcome to {{PLACE}}!";
    let vars = get_template_variables(template);
    assert_eq!(vars.len(), 2);
    assert!(vars.contains(&"NAME".to_string()));
    assert!(vars.contains(&"PLACE".to_string()));
}

#[test]
fn test_get_template_variables_percent() {
    let template = "Project: %%PROJECT%%, Path: %%PATH%%";
    let vars = get_template_variables(template);
    assert_eq!(vars.len(), 2);
    assert!(vars.contains(&"PROJECT".to_string()));
    assert!(vars.contains(&"PATH".to_string()));
}

#[test]
fn test_get_template_variables_no_vars() {
    let vars = get_template_variables("No variables here");
    assert!(vars.is_empty());
}
