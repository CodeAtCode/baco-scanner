//! Comprehensive unit tests for prompt templates module
//!
//! Tests cover:
//! - BacoPhase enum (Display, ordering, all 14 variants)
//! - ProjectType enum (Display, ordering, all 6 variants)
//! - TemplateVariables (CRUD operations, edge cases)
//! - DefaultPrompts (all 11 phase templates, Debug)
//! - get_default_prompt (all phases including T2.5)
//! - Hunt prompts (all 7 hunt functions)
//! - Template variable detection and content validation

use baco::prompt::templates::{
    auth_hunt_prompt, crypto_hunt_prompt, deserialization_hunt_prompt, get_all_defaults,
    get_default_prompt, injection_hunt_prompt, path_traversal_hunt_prompt, resource_hunt_prompt,
    xss_hunt_prompt, BacoPhase, ProjectType, TemplateVariables,
};

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
    assert_eq!(
        BacoPhase::IndependentVerify.to_string(),
        "independent_verify"
    );
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
        BacoPhase::IndependentVerify,
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

#[test]
fn test_template_variables_special_characters_in_key() {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY-WITH-DASHES".to_string(), "value1".to_string());
    vars.insert("KEY_WITH_UNDERSCORES".to_string(), "value2".to_string());

    assert_eq!(vars.len(), 2);
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
// get_default_prompt Tests
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
    let hunt_prompt = get_default_prompt(&BacoPhase::Hunt, &ProjectType::Web);
    let validate_prompt = get_default_prompt(&BacoPhase::Validate, &ProjectType::Web);
    let verify_prompt = get_default_prompt(&BacoPhase::IndependentVerify, &ProjectType::Web);

    assert!(!hunt_prompt.is_empty());
    assert!(!validate_prompt.is_empty());
    assert!(!verify_prompt.is_empty());
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
// Hunt Prompt Tests
// ============================================================================

#[test]
fn test_injection_hunt_prompt_basic() {
    let source = "SELECT * FROM users WHERE id = $input";
    let prompt = injection_hunt_prompt(source);

    assert!(prompt.contains("INJECTION VULNERABILITIES"));
    assert!(prompt.contains(source));
    assert!(prompt.contains("CWE-XXX"));
}

#[test]
fn test_injection_hunt_prompt_contains_safe_patterns() {
    let prompt = injection_hunt_prompt("test code");
    assert!(prompt.contains("Parameterized queries"));
    assert!(prompt.contains("Prepared statements"));
}

#[test]
fn test_injection_hunt_prompt_with_empty_source() {
    let prompt = injection_hunt_prompt("");
    assert!(prompt.contains("INJECTION VULNERABILITIES"));
}

#[test]
fn test_auth_hunt_prompt_basic() {
    let source = "if (user.isAdmin) { grantAccess() }";
    let prompt = auth_hunt_prompt(source);

    assert!(prompt.contains("AUTHENTICATION/AUTHORIZATION"));
    assert!(prompt.contains(source));
}

#[test]
fn test_auth_hunt_prompt_contains_idor() {
    let prompt = auth_hunt_prompt("test");
    assert!(prompt.contains("IDOR"));
}

#[test]
fn test_xss_hunt_prompt_basic() {
    let source = "<div>{{ user_input }}</div>";
    let prompt = xss_hunt_prompt(source);

    assert!(prompt.contains("XSS VULNERABILITIES"));
    assert!(prompt.contains("CWE-79"));
    assert!(prompt.contains(source));
}

#[test]
fn test_path_traversal_hunt_prompt_basic() {
    let source = "fs.open(user_path)";
    let prompt = path_traversal_hunt_prompt(source);

    assert!(prompt.contains("PATH TRAVERSAL/SSRF"));
    assert!(prompt.contains("CWE-22"));
    assert!(prompt.contains(source));
}

#[test]
fn test_crypto_hunt_prompt_basic() {
    let source = "MD5(password)";
    let prompt = crypto_hunt_prompt(source);

    assert!(prompt.contains("CRYPTOGRAPHIC VULNERABILITIES"));
    assert!(prompt.contains(source));
}

#[test]
fn test_crypto_hunt_prompt_contains_weak_algos() {
    let prompt = crypto_hunt_prompt("test");
    assert!(prompt.contains("MD5"));
    assert!(prompt.contains("RC4"));
}

#[test]
fn test_resource_hunt_prompt_basic() {
    let source = "malloc(size)";
    let prompt = resource_hunt_prompt(source);

    assert!(prompt.contains("RESOURCE HANDLING"));
    assert!(prompt.contains(source));
}

#[test]
fn test_deserialization_hunt_prompt_basic() {
    let source = "yaml.load(user_input)";
    let prompt = deserialization_hunt_prompt(source);

    assert!(prompt.contains("DESERIALIZATION/CONFIG"));
    assert!(prompt.contains(source));
}

#[test]
fn test_all_hunt_prompts_return_non_empty() {
    let source = "test code";

    assert!(!injection_hunt_prompt(source).is_empty());
    assert!(!auth_hunt_prompt(source).is_empty());
    assert!(!xss_hunt_prompt(source).is_empty());
    assert!(!path_traversal_hunt_prompt(source).is_empty());
    assert!(!crypto_hunt_prompt(source).is_empty());
    assert!(!resource_hunt_prompt(source).is_empty());
    assert!(!deserialization_hunt_prompt(source).is_empty());
}

#[test]
fn test_hunt_prompts_with_multiline_source() {
    let source = "fn main() {\n    println!(\"hello\");\n}";
    let prompt = injection_hunt_prompt(source);

    assert!(prompt.contains(source));
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
fn test_baco_phase_hash_compatibility() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(BacoPhase::Indexing);
    set.insert(BacoPhase::Semgrep);
    set.insert(BacoPhase::Indexing); // Duplicate

    assert_eq!(set.len(), 2);
}

#[test]
fn test_project_type_hash_compatibility() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(ProjectType::CLI);
    set.insert(ProjectType::Web);
    set.insert(ProjectType::CLI); // Duplicate

    assert_eq!(set.len(), 2);
}

#[test]
fn test_prompt_content_length_validation() {
    let prompts = get_all_defaults();

    assert!(prompts.indexing.len() > 100);
    assert!(prompts.semgrep.len() > 100);
    assert!(prompts.llm_static_analysis.len() > 200);
}

#[test]
fn test_hunt_prompts_json_format_specified() {
    let prompt = injection_hunt_prompt("test");
    assert!(prompt.contains("Return JSON array"));
    assert!(prompt.contains("\"severity\""));
}
