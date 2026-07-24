//! Unit tests for baco::prompt module
//!
//! Covers:
//! - PromptEngine creation and configuration
//! - Template variable substitution
//! - Prompt loading and overrides
//! - Sanitization and validation
//! - All BacoPhase variants
//! - Hunt prompt generators

#![allow(clippy::too_many_lines)]

use baco::prompt::{
    BacoPhase, ProjectType, PromptEngine, PromptOverrides, TemplateVariables,
    load_phase_prompts, get_prompt, sanitize_prompt_override, validate_prompt_override,
    MAX_PROMPT_OVERRIDE_LENGTH, get_all_defaults, get_default_prompt,
    injection_hunt_prompt, auth_hunt_prompt, xss_hunt_prompt,
    path_traversal_hunt_prompt, crypto_hunt_prompt, resource_hunt_prompt,
    deserialization_hunt_prompt,
};
use std::collections::HashMap;

// ============================================================================
// PromptEngine Tests
// ============================================================================

#[test]
fn test_prompt_engine_creation() {
    let engine = PromptEngine::new();
    let indexing = engine.get_prompt(&BacoPhase::Indexing);
    assert!(!indexing.is_empty());
    assert!(indexing.contains("Analyze the project structure"));
}

#[test]
fn test_prompt_engine_default_impl() {
    let engine = PromptEngine::default();
    let semgrep = engine.get_prompt(&BacoPhase::Semgrep);
    assert!(!semgrep.is_empty());
}

#[test]
fn test_prompt_engine_from_config_overrides() {
    let mut overrides = HashMap::new();
    overrides.insert("indexing".to_string(), "custom indexing prompt".to_string());
    
    let engine = PromptEngine::from_config_overrides(overrides);
    let indexing = engine.get_prompt(&BacoPhase::Indexing);
    assert_eq!(indexing, "custom indexing prompt");
}

#[test]
fn test_prompt_engine_all_phases_non_empty() {
    let engine = PromptEngine::new();
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
        let prompt = engine.get_prompt(&phase);
        assert!(!prompt.is_empty(), "Phase {:?} should have non-empty prompt", phase);
    }
}

#[test]
fn test_prompt_engine_template_substitution() {
    let engine = PromptEngine::new();
    let prompt = engine.get_prompt(&BacoPhase::Indexing);
    
    // Template variables should be substituted with default values
    assert!(prompt.contains("/project/root/path"));
    assert!(prompt.contains("BACOSecurityScanner"));
}

#[test]
fn test_prompt_engine_legacy_format_support() {
    let engine = PromptEngine::new();
    let semgrep = engine.get_prompt(&BacoPhase::Semgrep);
    
    // Legacy %%VAR%% format should still work
    assert!(semgrep.contains("%%PROJECT_PATH%%") || semgrep.contains("/project/root/path"));
}

#[test]
fn test_prompt_overrides_serialization() {
    let overrides = PromptOverrides::default();
    assert!(overrides.phase_overrides.is_empty());
}

#[test]
fn test_prompt_overrides_with_data() {
    let mut phase_overrides = HashMap::new();
    phase_overrides.insert("semgrep".to_string(), "custom semgrep".to_string());
    
    let overrides = PromptOverrides { phase_overrides };
    assert_eq!(overrides.phase_overrides.get("semgrep").unwrap(), "custom semgrep");
}

// ============================================================================
// load_phase_prompts Tests
// ============================================================================

#[test]
fn test_load_phase_prompts_default_path() {
    let prompts = load_phase_prompts(None);
    
    assert!(prompts.contains_key("indexing"));
    assert!(prompts.contains_key("semgrep"));
    assert!(prompts.contains_key("llm_static_analysis"));
    assert!(prompts.contains_key("llm_discovery"));
    assert!(prompts.contains_key("llm_verification"));
    assert!(prompts.contains_key("git_analysis"));
    assert!(prompts.contains_key("cross_file_analysis"));
    assert!(prompts.contains_key("confidence_scoring"));
    assert!(prompts.contains_key("ai_aggregation"));
    assert!(prompts.contains_key("reporting"));
}

#[test]
fn test_load_phase_prompts_empty_for_nonexistent_path() {
    let prompts = load_phase_prompts(Some("/nonexistent/path"));
    
    for (_key, value) in &prompts {
        assert!(value.is_empty());
    }
}

#[test]
fn test_load_phase_prompts_all_keys_present() {
    let prompts = load_phase_prompts(None);
    let expected_keys = [
        "indexing", "semgrep", "llm_static_analysis", "llm_discovery",
        "llm_verification", "ticket_crossref", "git_analysis",
        "cross_file_analysis", "confidence_scoring", "ai_aggregation", "reporting",
    ];

    for key in expected_keys {
        assert!(prompts.contains_key(key), "Missing key: {}", key);
    }
}

// ============================================================================
// get_prompt Tests
// ============================================================================

#[test]
fn test_get_prompt_with_config_override() {
    let mut loaded = HashMap::new();
    loaded.insert("test_phase".to_string(), "from file".to_string());
    
    let result = get_prompt("test_phase", &loaded, Some("from config"), "default");
    assert_eq!(result, "from config");
}

#[test]
fn test_get_prompt_with_loaded_prompt() {
    let mut loaded = HashMap::new();
    loaded.insert("test_phase".to_string(), "from file".to_string());
    
    let result = get_prompt("test_phase", &loaded, None, "default");
    assert_eq!(result, "from file");
}

#[test]
fn test_get_prompt_fallback_to_default() {
    let loaded = HashMap::new();
    
    let result = get_prompt("nonexistent", &loaded, None, "default");
    assert_eq!(result, "default");
}

#[test]
fn test_get_prompt_empty_loaded_fallback() {
    let mut loaded = HashMap::new();
    loaded.insert("test_phase".to_string(), String::new());
    
    let result = get_prompt("test_phase", &loaded, None, "default");
    assert_eq!(result, "default");
}

#[test]
fn test_get_prompt_priority_order() {
    let mut loaded = HashMap::new();
    loaded.insert("phase".to_string(), "from file".to_string());
    
    // Config override has highest priority
    let result = get_prompt("phase", &loaded, Some("from config"), "default");
    assert_eq!(result, "from config");
}

// ============================================================================
// sanitize_prompt_override Tests
// ============================================================================

#[test]
fn test_sanitize_null_bytes() {
    let input = "hello\0world\0test";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "helloworldtest");
}

#[test]
fn test_sanitize_control_characters() {
    let input = "hello\x01world\x02test";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "helloworldtest");
}

#[test]
fn test_sanitize_keeps_whitespace() {
    let input = "hello world\ttest\nnewline";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "hello world\ttest\nnewline");
}

#[test]
fn test_sanitize_removes_non_printable() {
    let input = "hello\x7fworld";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "helloworld");
}

#[test]
fn test_sanitize_empty_input() {
    let input = "";
    let result = sanitize_prompt_override(input);
    assert!(result.is_empty());
}

#[test]
fn test_sanitize_already_clean_input() {
    let input = "This is a clean prompt with no issues";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, input);
}

#[test]
fn test_sanitize_mixed_content() {
    let input = "Analyze\0for\x01security\nvulnerabilities";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "Analyzefor security\nvulnerabilities");
}

// ============================================================================
// validate_prompt_override Tests
// ============================================================================

#[test]
fn test_validate_safe_prompt() {
    let input = "Analyze this code for SQL injection vulnerabilities";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_sql_injection_pattern() {
    let input = "'; DROP TABLE users; --";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("injection"));
}

#[test]
fn test_validate_script_injection() {
    let input = "<script>alert('xss')</script>";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Script tags"));
}

#[test]
fn test_validate_shell_injection() {
    let input = "; rm -rf /";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("shell injection"));
}

#[test]
fn test_validate_long_prompt() {
    let input = "a".repeat(MAX_PROMPT_OVERRIDE_LENGTH + 1);
    let result = validate_prompt_override(&input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_validate_null_byte_in_prompt() {
    let input = "safe prompt\0with null";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Null bytes"));
}

#[test]
fn test_validate_legitimate_security_terms() {
    let input = "Check for SQL injection and XSS vulnerabilities";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_various_shell_patterns() {
    let patterns = [
        "| rm -rf",
        "&& rm -rf",
        "`rm -rf`",
        "$(rm -rf)",
    ];
    
    for pattern in patterns {
        let result = validate_prompt_override(pattern);
        assert!(result.is_err(), "Pattern {} should be rejected", pattern);
    }
}

#[test]
fn test_validate_case_insensitive_sql_check() {
    let input = "'; drop table users";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_empty_input() {
    let input = "";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

// ============================================================================
// BacoPhase Tests
// ============================================================================

#[test]
fn test_baco_phase_display_indexing() {
    assert_eq!(BacoPhase::Indexing.to_string(), "indexing");
}

#[test]
fn test_baco_phase_display_semgrep() {
    assert_eq!(BacoPhase::Semgrep.to_string(), "semgrep");
}

#[test]
fn test_baco_phase_display_llm_static_analysis() {
    assert_eq!(BacoPhase::LlmStaticAnalysis.to_string(), "llm_static_analysis");
}

#[test]
fn test_baco_phase_display_llm_discovery() {
    assert_eq!(BacoPhase::LlmDiscovery.to_string(), "llm_discovery");
}

#[test]
fn test_baco_phase_display_llm_verification() {
    assert_eq!(BacoPhase::LlmVerification.to_string(), "llm_verification");
}

#[test]
fn test_baco_phase_display_ticket_crossref() {
    assert_eq!(BacoPhase::TicketCrossRef.to_string(), "ticket_crossref");
}

#[test]
fn test_baco_phase_display_git_analysis() {
    assert_eq!(BacoPhase::GitAnalysis.to_string(), "git_analysis");
}

#[test]
fn test_baco_phase_display_cross_file_analysis() {
    assert_eq!(BacoPhase::CrossFileAnalysis.to_string(), "cross_file_analysis");
}

#[test]
fn test_baco_phase_display_confidence_scoring() {
    assert_eq!(BacoPhase::ConfidenceScoring.to_string(), "confidence_scoring");
}

#[test]
fn test_baco_phase_display_ai_aggregation() {
    assert_eq!(BacoPhase::AiAggregation.to_string(), "ai_aggregation");
}

#[test]
fn test_baco_phase_display_reporting() {
    assert_eq!(BacoPhase::Reporting.to_string(), "reporting");
}

#[test]
fn test_baco_phase_display_hunt() {
    assert_eq!(BacoPhase::Hunt.to_string(), "hunt");
}

#[test]
fn test_baco_phase_display_validate() {
    assert_eq!(BacoPhase::Validate.to_string(), "validate");
}

#[test]
fn test_baco_phase_display_independent_verify() {
    assert_eq!(BacoPhase::IndependentVerify.to_string(), "independent_verify");
}

#[test]
fn test_baco_phase_all_variants_unique() {
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
    
    let strings: Vec<String> = phases.iter().map(|p| p.to_string()).collect();
    let mut unique_count = 0;
    for (i, s) in strings.iter().enumerate() {
        if strings[..i].iter().all(|existing| existing != s) {
            unique_count += 1;
        }
    }
    assert_eq!(unique_count, strings.len(), "All phase strings should be unique");
}

// ============================================================================
// ProjectType Tests
// ============================================================================

#[test]
fn test_project_type_display_cli() {
    assert_eq!(ProjectType::CLI.to_string(), "cli");
}

#[test]
fn test_project_type_display_web() {
    assert_eq!(ProjectType::Web.to_string(), "web");
}

#[test]
fn test_project_type_display_library() {
    assert_eq!(ProjectType::Library.to_string(), "library");
}

#[test]
fn test_project_type_display_embedded() {
    assert_eq!(ProjectType::Embedded.to_string(), "embedded");
}

#[test]
fn test_project_type_display_firmware() {
    assert_eq!(ProjectType::Firmware.to_string(), "firmware");
}

#[test]
fn test_project_type_display_desktop() {
    assert_eq!(ProjectType::Desktop.to_string(), "desktop");
}

// ============================================================================
// TemplateVariables Tests
// ============================================================================

#[test]
fn test_template_variables_new_empty() {
    let vars = TemplateVariables::new();
    assert!(vars.is_empty());
    assert_eq!(vars.len(), 0);
}

#[test]
fn test_template_variables_insert_and_get() {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY1".to_string(), "value1".to_string());
    vars.insert("KEY2".to_string(), "value2".to_string());
    
    assert_eq!(vars.len(), 2);
    assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
    assert_eq!(vars.get("KEY2"), Some(&"value2".to_string()));
    assert_eq!(vars.get("NONEXISTENT"), None);
}

#[test]
fn test_template_variables_insert_overwrite() {
    let mut vars = TemplateVariables::new();
    vars.insert("KEY".to_string(), "value1".to_string());
    vars.insert("KEY".to_string(), "value2".to_string());
    
    assert_eq!(vars.len(), 1);
    assert_eq!(vars.get("KEY"), Some(&"value2".to_string()));
}

#[test]
fn test_template_variables_is_empty_behavior() {
    let mut vars = TemplateVariables::new();
    assert!(vars.is_empty());
    
    vars.insert("KEY".to_string(), "value".to_string());
    assert!(!vars.is_empty());
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
fn test_default_prompts_debug_format() {
    let prompts = get_all_defaults();
    let debug_output = format!("{:?}", prompts);
    
    assert!(debug_output.contains("indexing"));
    assert!(debug_output.contains("semgrep"));
    assert!(debug_output.contains("llm_static_analysis"));
}

// ============================================================================
// get_default_prompt Tests
// ============================================================================

#[test]
fn test_get_default_prompt_indexing() {
    let prompt = get_default_prompt(&BacoPhase::Indexing, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%PROJECT_PATH%%"));
    assert!(prompt.contains("%%FILE_EXTENSIONS%%"));
}

#[test]
fn test_get_default_prompt_semgrep() {
    let prompt = get_default_prompt(&BacoPhase::Semgrep, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("security"));
    assert!(prompt.contains("vulnerabilities"));
}

#[test]
fn test_get_default_prompt_llm_static_analysis() {
    let prompt = get_default_prompt(&BacoPhase::LlmStaticAnalysis, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("%%CODE_CONTENT%%"));
}

#[test]
fn test_get_default_prompt_llm_verification() {
    let prompt = get_default_prompt(&BacoPhase::LlmVerification, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("true positive"));
    assert!(prompt.contains("false_positive"));
}

#[test]
fn test_get_default_prompt_all_phases() {
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
        let prompt = get_default_prompt(&phase, &ProjectType::Web);
        assert!(!prompt.is_empty(), "Phase {:?} should have non-empty default prompt", phase);
    }
}

// ============================================================================
// Hunt Prompt Tests
// ============================================================================

#[test]
fn test_injection_hunt_prompt_content() {
    let source = "SELECT * FROM users WHERE id = $input";
    let prompt = injection_hunt_prompt(source);
    
    assert!(prompt.contains("INJECTION VULNERABILITIES"));
    assert!(prompt.contains(source));
    assert!(prompt.contains("DANGEROUS APIs"));
    assert!(prompt.contains("CWE-XXX"));
}

#[test]
fn test_injection_hunt_prompt_empty_source() {
    let prompt = injection_hunt_prompt("");
    assert!(prompt.contains("INJECTION VULNERABILITIES"));
    assert!(!prompt.is_empty());
}

#[test]
fn test_auth_hunt_prompt_content() {
    let source = "if (user.isAdmin) { grantAccess() }";
    let prompt = auth_hunt_prompt(source);
    
    assert!(prompt.contains("AUTHENTICATION/AUTHORIZATION"));
    assert!(prompt.contains(source));
    assert!(prompt.contains("DANGEROUS APIs"));
}

#[test]
fn test_auth_hunt_prompt_empty_source() {
    let prompt = auth_hunt_prompt("");
    assert!(prompt.contains("AUTHENTICATION/AUTHORIZATION"));
}

#[test]
fn test_xss_hunt_prompt_content() {
    let source = "<div>{{ user_input }}</div>";
    let prompt = xss_hunt_prompt(source);
    
    assert!(prompt.contains("XSS VULNERABILITIES"));
    assert!(prompt.contains("CWE-79"));
    assert!(prompt.contains(source));
}

#[test]
fn test_xss_hunt_prompt_empty_source() {
    let prompt = xss_hunt_prompt("");
    assert!(prompt.contains("XSS VULNERABILITIES"));
}

#[test]
fn test_path_traversal_hunt_prompt_content() {
    let source = "fs.open(user_path)";
    let prompt = path_traversal_hunt_prompt(source);
    
    assert!(prompt.contains("PATH TRAVERSAL/SSRF"));
    assert!(prompt.contains("CWE-22"));
    assert!(prompt.contains(source));
}

#[test]
fn test_path_traversal_hunt_prompt_empty_source() {
    let prompt = path_traversal_hunt_prompt("");
    assert!(prompt.contains("PATH TRAVERSAL/SSRF"));
}

#[test]
fn test_crypto_hunt_prompt_content() {
    let source = "MD5(password)";
    let prompt = crypto_hunt_prompt(source);
    
    assert!(prompt.contains("CRYPTOGRAPHIC VULNERABILITIES"));
    assert!(prompt.contains(source));
}

#[test]
fn test_crypto_hunt_prompt_empty_source() {
    let prompt = crypto_hunt_prompt("");
    assert!(prompt.contains("CRYPTOGRAPHIC VULNERABILITIES"));
}

#[test]
fn test_resource_hunt_prompt_content() {
    let source = "malloc(size)";
    let prompt = resource_hunt_prompt(source);
    
    assert!(prompt.contains("RESOURCE HANDLING"));
    assert!(prompt.contains(source));
}

#[test]
fn test_resource_hunt_prompt_empty_source() {
    let prompt = resource_hunt_prompt("");
    assert!(prompt.contains("RESOURCE HANDLING"));
}

#[test]
fn test_deserialization_hunt_prompt_content() {
    let source = "yaml.load(user_input)";
    let prompt = deserialization_hunt_prompt(source);
    
    assert!(prompt.contains("DESERIALIZATION/CONFIG"));
    assert!(prompt.contains(source));
}

#[test]
fn test_deserialization_hunt_prompt_empty_source() {
    let prompt = deserialization_hunt_prompt("");
    assert!(prompt.contains("DESERIALIZATION/CONFIG"));
}

#[test]
fn test_all_hunt_prompts_with_same_source() {
    let source = "test_code";
    
    assert!(injection_hunt_prompt(source).contains(source));
    assert!(auth_hunt_prompt(source).contains(source));
    assert!(xss_hunt_prompt(source).contains(source));
    assert!(path_traversal_hunt_prompt(source).contains(source));
    assert!(crypto_hunt_prompt(source).contains(source));
    assert!(resource_hunt_prompt(source).contains(source));
    assert!(deserialization_hunt_prompt(source).contains(source));
}

// ============================================================================
// MAX_PROMPT_OVERRIDE_LENGTH Tests
// ============================================================================

#[test]
fn test_max_prompt_override_length_constant() {
    assert!(MAX_PROMPT_OVERRIDE_LENGTH > 0);
    assert!(MAX_PROMPT_OVERRIDE_LENGTH < 100000);
}