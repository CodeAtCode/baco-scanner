#![cfg(test)]

use baco::config::PromptSpec;
use baco::prompt::templates::{
    auth_hunt_prompt, crypto_hunt_prompt, deserialization_hunt_prompt, get_all_defaults,
    get_default_prompt, injection_hunt_prompt, path_traversal_hunt_prompt, resource_hunt_prompt,
    xss_hunt_prompt, BacoPhase, ProjectType, TemplateVariables,
};

#[test]
fn test_baco_phase_display() {
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
}

#[test]
fn test_project_type_display() {
    assert_eq!(ProjectType::CLI.to_string(), "cli");
    assert_eq!(ProjectType::Web.to_string(), "web");
    assert_eq!(ProjectType::Library.to_string(), "library");
    assert_eq!(ProjectType::Embedded.to_string(), "embedded");
    assert_eq!(ProjectType::Firmware.to_string(), "firmware");
    assert_eq!(ProjectType::Desktop.to_string(), "desktop");
}

#[test]
fn test_template_variables_new() {
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
fn test_template_variables_is_empty() {
    let mut vars = TemplateVariables::new();
    assert!(vars.is_empty());

    vars.insert("KEY".to_string(), "value".to_string());
    assert!(!vars.is_empty());
}

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
fn test_get_default_prompt_indexing() {
    let prompt = get_default_prompt(&BacoPhase::Indexing, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%PROJECT_PATH%%"));
    assert!(prompt.contains("%%FILE_EXTENSIONS%%"));
    assert!(prompt.contains("%%LANGUAGES%%"));
}

#[test]
fn test_get_default_prompt_semgrep() {
    let prompt = get_default_prompt(&BacoPhase::Semgrep, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%PROJECT_PATH%%"));
    assert!(prompt.contains("security"));
    assert!(prompt.contains("vulnerabilities"));
}

#[test]
fn test_get_default_prompt_llm_static_analysis() {
    let prompt = get_default_prompt(&BacoPhase::LlmStaticAnalysis, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("%%LINE_RANGE%%"));
    assert!(prompt.contains("%%CODE_CONTENT%%"));
    assert!(prompt.contains("CWE-"));
}

#[test]
fn test_get_default_prompt_llm_discovery() {
    let prompt = get_default_prompt(&BacoPhase::LlmDiscovery, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FINDING_TITLE%%"));
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("%%LINE_NUMBER%%"));
}

#[test]
fn test_get_default_prompt_llm_verification() {
    let prompt = get_default_prompt(&BacoPhase::LlmVerification, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FINDING_TITLE%%"));
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("true positive"));
    assert!(prompt.contains("false_positive"));
}

#[test]
fn test_get_default_prompt_ticket_crossref() {
    let prompt = get_default_prompt(&BacoPhase::TicketCrossRef, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%VULNERABILITY_TITLE%%"));
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("%%TICKET_SYSTEMS%%"));
}

#[test]
fn test_get_default_prompt_git_analysis() {
    let prompt = get_default_prompt(&BacoPhase::GitAnalysis, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FILE_PATH%%"));
    assert!(prompt.contains("%%LINE_NUMBER%%"));
    assert!(prompt.contains("git log"));
    assert!(prompt.contains("git blame"));
}

#[test]
fn test_get_default_prompt_cross_file_analysis() {
    let prompt = get_default_prompt(&BacoPhase::CrossFileAnalysis, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%VULNERABILITY_LIST%%"));
    assert!(prompt.contains("data flow"));
    assert!(prompt.contains("cross-file"));
}

#[test]
fn test_get_default_prompt_confidence_scoring() {
    let prompt = get_default_prompt(&BacoPhase::ConfidenceScoring, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FINDINGS_LIST%%"));
    assert!(prompt.contains("confidence"));
    assert!(prompt.contains("false positive"));
}

#[test]
fn test_get_default_prompt_ai_aggregation() {
    let prompt = get_default_prompt(&BacoPhase::AiAggregation, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%FINDINGS_LIST%%"));
    assert!(prompt.contains("%%PROJECT_TYPE%%"));
    assert!(prompt.contains("executive summary"));
    assert!(prompt.contains("risk assessment"));
}

#[test]
fn test_get_default_prompt_reporting() {
    let prompt = get_default_prompt(&BacoPhase::Reporting, &ProjectType::CLI);
    assert!(!prompt.is_empty());
    assert!(prompt.contains("%%PROJECT_NAME%%"));
    assert!(prompt.contains("%%SCAN_DATE%%"));
    assert!(prompt.contains("%%TOTAL_FINDINGS%%"));
    assert!(prompt.contains("SARIF"));
}

#[test]
fn test_all_phases_return_different_prompts() {
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
            assert_ne!(
                all_prompts[i], all_prompts[j],
                "Prompts for phase {} and {} should be different",
                i, j
            );
        }
    }
}

#[test]
fn test_default_prompts_debug() {
    let prompts = get_all_defaults();
    let debug_output = format!("{:?}", prompts);
    assert!(debug_output.contains("indexing"));
    assert!(debug_output.contains("semgrep"));
}

#[test]
fn test_template_variables_multiple_inserts() {
    let mut vars = TemplateVariables::new();

    for i in 0..10 {
        vars.insert(format!("KEY_{}", i), format!("value_{}", i));
    }

    assert_eq!(vars.len(), 10);

    for i in 0..10 {
        assert_eq!(
            vars.get(&format!("KEY_{}", i)),
            Some(&format!("value_{}", i))
        );
    }
}

#[test]
fn test_indexing_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.indexing.contains("%%PROJECT_PATH%%"));
    assert!(prompts.indexing.contains("%%FILE_EXTENSIONS%%"));
    assert!(prompts.indexing.contains("%%LANGUAGES%%"));
    assert!(prompts.indexing.contains("%%MAX_FILE_SIZE%%"));
    assert!(prompts.indexing.contains("%%EXCLUDE_PATHS%%"));
}

#[test]
fn test_semgrep_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.semgrep.contains("%%PROJECT_PATH%%"));
    assert!(prompts.semgrep.contains("Buffer overflow"));
    assert!(prompts.semgrep.contains("SQL injection"));
    assert!(prompts.semgrep.contains("XSS"));
}

#[test]
fn test_llm_static_analysis_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.llm_static_analysis.contains("%%LANGUAGE%%"));
    assert!(prompts.llm_static_analysis.contains("%%FILE_PATH%%"));
    assert!(prompts.llm_static_analysis.contains("%%LINE_RANGE%%"));
    assert!(prompts.llm_static_analysis.contains("%%CONTEXT_LINES%%"));
    assert!(prompts.llm_static_analysis.contains("%%CODE_CONTENT%%"));
    assert!(prompts.llm_static_analysis.contains("CWE-22"));
    assert!(prompts.llm_static_analysis.contains("CWE-79"));
    assert!(prompts.llm_static_analysis.contains("CWE-89"));
}

#[test]
fn test_llm_discovery_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.llm_discovery.contains("%%FINDING_TITLE%%"));
    assert!(prompts.llm_discovery.contains("%%FILE_PATH%%"));
    assert!(prompts.llm_discovery.contains("%%LINE_NUMBER%%"));
    assert!(prompts.llm_discovery.contains("%%CURRENT_DESCRIPTION%%"));
}

#[test]
fn test_llm_verification_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.llm_verification.contains("%%FINDING_TITLE%%"));
    assert!(prompts.llm_verification.contains("%%FILE_PATH%%"));
    assert!(prompts.llm_verification.contains("%%LINE_NUMBER%%"));
    assert!(prompts
        .llm_verification
        .contains("%%VULNERABILITY_DESCRIPTION%%"));
    assert!(prompts.llm_verification.contains("%%SOURCE_LIST%%"));
    assert!(prompts.llm_verification.contains("confirmed"));
    assert!(prompts.llm_verification.contains("false_positive"));
    assert!(prompts.llm_verification.contains("needs_review"));
}

#[test]
fn test_ticket_crossref_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.ticket_crossref.contains("%%VULNERABILITY_TITLE%%"));
    assert!(prompts.ticket_crossref.contains("%%FILE_PATH%%"));
    assert!(prompts
        .ticket_crossref
        .contains("%%VULNERABILITY_DESCRIPTION%%"));
    assert!(prompts.ticket_crossref.contains("%%TICKET_SYSTEMS%%"));
}

#[test]
fn test_git_analysis_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.git_analysis.contains("%%FILE_PATH%%"));
    assert!(prompts.git_analysis.contains("%%LINE_NUMBER%%"));
}

#[test]
fn test_cross_file_analysis_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts
        .cross_file_analysis
        .contains("%%VULNERABILITY_LIST%%"));
}

#[test]
fn test_confidence_scoring_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.confidence_scoring.contains("%%FINDINGS_LIST%%"));
}

#[test]
fn test_ai_aggregation_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.ai_aggregation.contains("%%FINDINGS_LIST%%"));
    assert!(prompts.ai_aggregation.contains("%%PROJECT_TYPE%%"));
    assert!(prompts.ai_aggregation.contains("%%LANGUAGES%%"));
    assert!(prompts.ai_aggregation.contains("%%TOTAL_FILES%%"));
    assert!(prompts.ai_aggregation.contains("%%SCAN_DATE%%"));
}

#[test]
fn test_reporting_template_variables() {
    let prompts = get_all_defaults();
    assert!(prompts.reporting.contains("%%PROJECT_NAME%%"));
    assert!(prompts.reporting.contains("%%SCAN_DATE%%"));
    assert!(prompts.reporting.contains("%%FILES_COUNT%%"));
    assert!(prompts.reporting.contains("%%TOTAL_FINDINGS%%"));
    assert!(prompts.reporting.contains("%%TOOLS_USED%%"));
    assert!(prompts.reporting.contains("%%SCAN_DURATION%%"));
}

#[test]
fn test_baco_phase_ordering() {
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
fn test_project_type_ordering() {
    let types = vec![ProjectType::CLI, ProjectType::Web, ProjectType::Library];

    let mut sorted = types.clone();
    sorted.sort();

    assert_eq!(types, sorted);
}

#[test]
fn test_injection_hunt_prompt() {
    let source = "SELECT * FROM users WHERE id = $input";
    let prompt = injection_hunt_prompt(source);

    assert!(prompt.contains("INJECTION VULNERABILITIES"));
    assert!(prompt.contains(source));
    assert!(prompt.contains("CWE-XXX"));
}

#[test]
fn test_auth_hunt_prompt() {
    let source = "if (user.isAdmin) { grantAccess() }";
    let prompt = auth_hunt_prompt(source);

    assert!(prompt.contains("AUTHENTICATION/AUTHORIZATION"));
    assert!(prompt.contains(source));
}

#[test]
fn test_xss_hunt_prompt() {
    let source = "<div>{{ user_input }}</div>";
    let prompt = xss_hunt_prompt(source);

    assert!(prompt.contains("XSS VULNERABILITIES"));
    assert!(prompt.contains("CWE-79"));
    assert!(prompt.contains(source));
}

#[test]
fn test_path_traversal_hunt_prompt() {
    let source = "fs.open(user_path)";
    let prompt = path_traversal_hunt_prompt(source);

    assert!(prompt.contains("PATH TRAVERSAL/SSRF"));
    assert!(prompt.contains("CWE-22"));
    assert!(prompt.contains(source));
}

#[test]
fn test_crypto_hunt_prompt() {
    let source = "MD5(password)";
    let prompt = crypto_hunt_prompt(source);

    assert!(prompt.contains("CRYPTOGRAPHIC VULNERABILITIES"));
    assert!(prompt.contains(source));
}

#[test]
fn test_resource_hunt_prompt() {
    let source = "malloc(size)";
    let prompt = resource_hunt_prompt(source);

    assert!(prompt.contains("RESOURCE HANDLING"));
    assert!(prompt.contains(source));
}

#[test]
fn test_deserialization_hunt_prompt() {
    let source = "yaml.load(user_input)";
    let prompt = deserialization_hunt_prompt(source);

    assert!(prompt.contains("DESERIALIZATION/CONFIG"));
    assert!(prompt.contains(source));
}

#[test]
fn test_hunt_prompts_with_empty_source() {
    let prompt = injection_hunt_prompt("");
    assert!(prompt.contains("INJECTION VULNERABILITIES"));
}

#[test]
fn test_all_baco_phase_variants() {
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
fn test_all_project_type_variants() {
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
fn test_template_variables_operations() {
    let mut vars = TemplateVariables::new();

    vars.insert("KEY1".to_string(), "value1".to_string());
    assert_eq!(vars.len(), 1);

    assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
    assert_eq!(vars.get("NONEXISTENT"), None);

    vars.insert("KEY2".to_string(), "value2".to_string());
    vars.insert("KEY3".to_string(), "value3".to_string());
    assert_eq!(vars.len(), 3);
}

#[test]
fn test_get_default_prompt_t25_phases() {
    let project_type = ProjectType::Web;

    let hunt_prompt = get_default_prompt(&BacoPhase::Hunt, &project_type);
    assert!(!hunt_prompt.is_empty());

    let validate_prompt = get_default_prompt(&BacoPhase::Validate, &project_type);
    assert!(!validate_prompt.is_empty());

    let independent_verify_prompt =
        get_default_prompt(&BacoPhase::IndependentVerify, &project_type);
    assert!(!independent_verify_prompt.is_empty());
}

#[test]
fn test_default_prompts_debug_output() {
    let prompts = get_all_defaults();
    let debug_str = format!("{:?}", prompts);

    assert!(debug_str.contains("indexing"));
    assert!(debug_str.contains("semgrep"));
    assert!(debug_str.contains("llm_static_analysis"));
}

#[test]
fn test_prompt_spec_default() {
    let spec = PromptSpec::default();
    assert_eq!(spec.prompt_template, "llm_static_analysis");
    assert!(spec.model_override.is_none());
}
