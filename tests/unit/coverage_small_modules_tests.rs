//! Coverage tests for small modules: eval, error, config/knowledge, agent_flow/executor, rulesynth/proposer

use baco::config::knowledge::KnowledgeConfig;
use baco::error::ScanError;
use baco::eval::{
    eval_floor, parse_oracle, score_findings, ExpectedFinding, ExpectedSuppressed, OracleFile,
    DEFAULT_EVAL_FLOOR,
};
use baco::findings::{Severity, VulnerabilityFinding};

fn make_finding(
    file_path: &str,
    line_number: Option<u32>,
    cwe_id: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test".to_string(),
        description: "test".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.8,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

// ============================================================================
// eval.rs tests
// ============================================================================

#[test]
fn test_parse_oracle_valid() {
    let json = r#"{
        "target": "test-target",
        "description": "Test oracle",
        "expected_findings": [
            {"file_path": "src/vuln.php", "line": 42, "cwe_id": "CWE-79", "class": "XSS"}
        ],
        "expected_suppressed": []
    }"#;

    let oracle = parse_oracle(json).expect("Failed to parse valid oracle");
    assert_eq!(oracle.target, "test-target");
    assert_eq!(oracle.description, "Test oracle");
    assert_eq!(oracle.expected_findings.len(), 1);
    assert_eq!(oracle.expected_findings[0].file_path, "src/vuln.php");
    assert_eq!(oracle.expected_findings[0].line, 42);
    assert_eq!(oracle.expected_findings[0].cwe_id, "CWE-79");
}

#[test]
fn test_parse_oracle_invalid_json() {
    let json = r#"{"invalid json"#;
    let result = parse_oracle(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse oracle JSON"));
}

#[test]
fn test_parse_oracle_missing_fields_uses_defaults() {
    let json = r#"{"target": "test", "description": "test"}"#;
    let oracle = parse_oracle(json).expect("Failed to parse oracle with missing optional fields");
    assert!(oracle.expected_findings.is_empty());
    assert!(oracle.expected_suppressed.is_empty());
}

#[test]
fn test_score_findings_perfect_match() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.php".to_string(),
            line: 42,
            cwe_id: "CWE-79".to_string(),
            class: "XSS".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let findings = vec![make_finding("src/vuln.php", Some(42), Some("CWE-79"))];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 1);
    assert_eq!(report.matched, 1);
    assert!(report.missed.is_empty());
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_findings_empty_findings() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.php".to_string(),
            line: 42,
            cwe_id: "CWE-79".to_string(),
            class: "XSS".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let report = score_findings(&oracle, &[]);
    assert_eq!(report.expected, 1);
    assert_eq!(report.matched, 0);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_findings_partial_match() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln1.php".to_string(),
                line: 10,
                cwe_id: "CWE-79".to_string(),
                class: "XSS".to_string(),
            },
            ExpectedFinding {
                file_path: "src/vuln2.php".to_string(),
                line: 20,
                cwe_id: "CWE-89".to_string(),
                class: "SQLi".to_string(),
            },
        ],
        expected_suppressed: vec![],
    };

    let findings = vec![make_finding("src/vuln1.php", Some(12), Some("CWE-79"))];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 2);
    assert_eq!(report.matched, 1);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.5);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_findings_false_flags() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.php".to_string(),
            line: 42,
            cwe_id: "CWE-79".to_string(),
            class: "XSS".to_string(),
        }],
        expected_suppressed: vec![ExpectedSuppressed {
            file_path: "src/secure.php".to_string(),
            reason: "known safe pattern".to_string(),
        }],
    };

    let findings = vec![
        make_finding("src/vuln.php", Some(42), Some("CWE-79")),
        make_finding("src/secure.php", Some(10), Some("CWE-79")),
    ];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 1);
    assert_eq!(report.matched, 1);
    assert_eq!(report.false_flags, 1);
    assert_eq!(report.precision, 0.5);
}

#[test]
fn test_score_findings_line_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.php".to_string(),
            line: 100,
            cwe_id: "CWE-79".to_string(),
            class: "XSS".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let findings = vec![make_finding("src/vuln.php", Some(105), Some("CWE-79"))];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);

    let findings = vec![make_finding("src/vuln.php", Some(106), Some("CWE-79"))];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
}

#[test]
fn test_eval_floor_from_env() {
    std::env::set_var("BACO_EVAL_FLOOR", "0.85");
    let result = eval_floor(0.70).expect("Valid floor from env");
    assert_eq!(result.0, 0.85);
    assert_eq!(result.1, "BACO_EVAL_FLOOR");
    std::env::remove_var("BACO_EVAL_FLOOR");
}

#[test]
fn test_eval_floor_from_config() {
    std::env::remove_var("BACO_EVAL_FLOOR");
    let result = eval_floor(0.75).expect("Valid floor from config");
    assert_eq!(result.0, 0.75);
    assert_eq!(result.1, "eval.floor");
}

#[test]
fn test_eval_floor_invalid_env() {
    std::env::set_var("BACO_EVAL_FLOOR", "invalid");
    let result = eval_floor(0.70);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid BACO_EVAL_FLOOR"));
    std::env::remove_var("BACO_EVAL_FLOOR");
}

#[test]
fn test_eval_floor_out_of_range() {
    let result = eval_floor(1.5);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must be between 0.0 and 1.0"));
}

#[test]
fn test_default_eval_floor_constant() {
    assert_eq!(DEFAULT_EVAL_FLOOR, 0.70);
}

// ============================================================================
// error.rs tests
// ============================================================================

#[test]
fn test_scan_error_auth_display() {
    let err = ScanError::Auth {
        message: "Invalid token".to_string(),
        source: None,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("Authentication failed"));
    assert!(msg.contains("Invalid token"));
}

#[test]
fn test_scan_error_config_display() {
    let err = ScanError::Config {
        message: "Missing API key".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Configuration error"));
}

#[test]
fn test_scan_error_parse_display() {
    let err = ScanError::Parse {
        message: "Invalid JSON".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Parse error"));
}

#[test]
fn test_scan_error_network_display() {
    let err = ScanError::Network {
        message: "Connection failed".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Network error"));
}

#[test]
fn test_scan_error_timeout_display() {
    let err = ScanError::Timeout {
        message: "Request timed out".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Timeout error"));
}

#[test]
fn test_scan_error_ratelimit_display() {
    let err = ScanError::RateLimit {
        message: "Rate limit exceeded".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Rate limit exceeded"));
}

#[test]
fn test_scan_error_server_display() {
    let err = ScanError::Server {
        message: "Internal server error".to_string(),
        source: None,
    };
    assert!(format!("{}", err).contains("Server error"));
}

#[test]
fn test_scan_error_phase_display() {
    let err = ScanError::Phase {
        message: "Something went wrong".to_string(),
        phase: "discovery".to_string(),
        source: None,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("Phase 'discovery' failed"));
    assert!(msg.contains("Something went wrong"));
}

#[test]
fn test_scan_error_missing_env_display() {
    let err = ScanError::MissingEnvVar("API_KEY".to_string());
    assert!(format!("{}", err).contains("Missing required environment variable"));
    assert!(format!("{}", err).contains("API_KEY"));
}

#[test]
fn test_scan_error_is_retryable_network() {
    let err = ScanError::Network {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_timeout() {
    let err = ScanError::Timeout {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_ratelimit() {
    let err = ScanError::RateLimit {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_server() {
    let err = ScanError::Server {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_auth() {
    let err = ScanError::Auth {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_config() {
    let err = ScanError::Config {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
}

#[test]
fn test_scan_error_is_retryable_parse() {
    let err = ScanError::Parse {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
}

#[test]
fn test_scan_error_with_phase() {
    let err = ScanError::Network {
        message: "test".to_string(),
        source: None,
    };
    let wrapped = err.with_phase("discovery");

    match wrapped {
        ScanError::Phase { message, phase, .. } => {
            assert_eq!(phase, "discovery");
            assert!(message.contains("Network error"));
        }
        _ => panic!("Expected Phase variant"),
    }
}

#[test]
fn test_scan_error_phase_extractor() {
    let err = ScanError::Phase {
        message: "test".to_string(),
        phase: "hunting".to_string(),
        source: None,
    };
    assert_eq!(err.phase(), Some("hunting"));

    let non_phase = ScanError::Network {
        message: "test".to_string(),
        source: None,
    };
    assert_eq!(non_phase.phase(), None);
}

#[test]
fn test_scan_error_from_string() {
    let err: ScanError = "test error".to_string().into();
    match err {
        ScanError::Unknown(s) => assert_eq!(s, "test error"),
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn test_scan_error_from_str() {
    let err: ScanError = "test error".into();
    match err {
        ScanError::Unknown(s) => assert_eq!(s, "test error"),
        _ => panic!("Expected Unknown variant"),
    }
}

// ============================================================================
// config/knowledge.rs tests
// ============================================================================

#[test]
fn test_knowledge_config_default() {
    let config = KnowledgeConfig::default();
    assert!(config.fp_patterns.is_empty());
    assert!(config.required_security_primitives.is_empty());
    assert!(config.hook_registry.is_empty());
}

#[test]
fn test_knowledge_config_clone() {
    let mut config = KnowledgeConfig::default();
    config
        .fp_patterns
        .insert("CWE-79".to_string(), vec!["safe".to_string()]);

    let cloned = config.clone();
    assert_eq!(
        cloned.fp_patterns.get("CWE-79").unwrap(),
        &vec!["safe".to_string()]
    );
}

#[test]
fn test_knowledge_config_serialization_roundtrip() {
    use serde_json;

    let mut config = KnowledgeConfig::default();
    config.fp_patterns.insert(
        "CWE-79".to_string(),
        vec!["sanitize".to_string(), "escape".to_string()],
    );
    config
        .required_security_primitives
        .insert("php".to_string(), vec!["mysqli_prepare".to_string()]);

    let json = serde_json::to_string(&config).expect("Failed to serialize");
    let restored: KnowledgeConfig = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(
        restored.fp_patterns.get("CWE-79").unwrap(),
        &vec!["sanitize".to_string(), "escape".to_string()]
    );
    assert_eq!(
        restored.required_security_primitives.get("php").unwrap(),
        &vec!["mysqli_prepare".to_string()]
    );
}

#[test]
fn test_knowledge_config_field_access() {
    let mut config = KnowledgeConfig::default();
    config
        .fp_patterns
        .insert("CWE-89".to_string(), vec!["prepared_statement".to_string()]);

    assert!(config.fp_patterns.contains_key("CWE-89"));
    assert!(!config.fp_patterns.contains_key("CWE-79"));
}

// ============================================================================
// agent_flow/executor tests
// ============================================================================

#[test]
fn test_topological_sort_empty_harness() {
    use baco::agent_flow::dsl::AgentFlowHarness;

    let harness = AgentFlowHarness::new();
    let order = baco::agent_flow::executor::topological_sort(&harness);

    assert!(order.is_some());
    assert!(order.unwrap().is_empty());
}

#[test]
fn test_topological_sort_single_node() {
    use baco::agent_flow::dsl::{Agent, AgentFlowHarness};

    let mut harness = AgentFlowHarness::new();
    harness.add_agent(Agent {
        role: "analyst".to_string(),
        prompt: "Analyze this".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });

    let order = baco::agent_flow::executor::topological_sort(&harness);

    assert!(order.is_some());
    assert_eq!(order.unwrap().len(), 1);
}

#[test]
fn test_topological_sort_two_nodes_no_edges() {
    use baco::agent_flow::dsl::{Agent, AgentFlowHarness};

    let mut harness = AgentFlowHarness::new();
    harness.add_agent(Agent {
        role: "analyst".to_string(),
        prompt: "Analyze".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });
    harness.add_agent(Agent {
        role: "reviewer".to_string(),
        prompt: "Review".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });

    let order = baco::agent_flow::executor::topological_sort(&harness);

    assert!(order.is_some());
    assert_eq!(order.unwrap().len(), 2);
}

#[test]
fn test_topological_sort_with_data_edges() {
    use baco::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind};

    let mut harness = AgentFlowHarness::new();
    let idx1 = harness.add_agent(Agent {
        role: "analyst".to_string(),
        prompt: "Analyze".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });
    let idx2 = harness.add_agent(Agent {
        role: "reviewer".to_string(),
        prompt: "Review {{ analyst.out }}".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });
    harness.add_edge(idx1, idx2, EdgeKind::Data, "{{ analyst.out }}".to_string());

    let order = baco::agent_flow::executor::topological_sort(&harness);

    assert!(order.is_some());
    let order = order.unwrap();
    assert_eq!(order.len(), 2);
    assert!(
        order.iter().position(|&x| x == idx1).unwrap()
            < order.iter().position(|&x| x == idx2).unwrap()
    );
}

#[test]
fn test_topological_sort_cycle_detection() {
    use baco::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind};

    let mut harness = AgentFlowHarness::new();
    let idx1 = harness.add_agent(Agent {
        role: "a".to_string(),
        prompt: "a".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });
    let idx2 = harness.add_agent(Agent {
        role: "b".to_string(),
        prompt: "b".to_string(),
        model: "gpt-4".to_string(),
        tools: std::collections::BTreeSet::new(),
    });

    harness.add_edge(idx1, idx2, EdgeKind::Data, "x".to_string());
    harness.add_edge(idx2, idx1, EdgeKind::Data, "x".to_string());

    let order = baco::agent_flow::executor::topological_sort(&harness);

    assert!(order.is_none());
}

#[test]
fn test_resolve_template_empty() {
    use std::collections::BTreeMap;

    let outputs = BTreeMap::new();
    let result = baco::agent_flow::executor::resolve_template("Hello world", &outputs);
    assert_eq!(result, "Hello world");
}

#[test]
fn test_resolve_template_single_variable() {
    use std::collections::BTreeMap;

    let mut outputs = BTreeMap::new();
    outputs.insert(
        "analyst".to_string(),
        baco::agent_flow::executor::AgentOutput {
            role: "analyst".to_string(),
            content: "Found vulnerability".to_string(),
            success: true,
        },
    );

    let template = "Report: {{ analyst.out }}";
    let result = baco::agent_flow::executor::resolve_template(template, &outputs);
    assert_eq!(result, "Report: Found vulnerability");
}

#[test]
fn test_resolve_template_multiple_variables() {
    use std::collections::BTreeMap;

    let mut outputs = BTreeMap::new();
    outputs.insert(
        "analyst".to_string(),
        baco::agent_flow::executor::AgentOutput {
            role: "analyst".to_string(),
            content: "Analysis data".to_string(),
            success: true,
        },
    );
    outputs.insert(
        "reviewer".to_string(),
        baco::agent_flow::executor::AgentOutput {
            role: "reviewer".to_string(),
            content: "Review notes".to_string(),
            success: true,
        },
    );

    let template = "{{ analyst.out }} followed by {{ reviewer.out }}";
    let result = baco::agent_flow::executor::resolve_template(template, &outputs);
    assert_eq!(result, "Analysis data followed by Review notes");
}

#[test]
fn test_resolve_template_no_match_unchanged() {
    use std::collections::BTreeMap;

    let outputs = BTreeMap::new();
    let template = "{{ unknown.out }}";
    let result = baco::agent_flow::executor::resolve_template(template, &outputs);
    assert_eq!(result, "{{ unknown.out }}");
}

#[test]
fn test_execution_result_is_success() {
    use baco::agent_flow::executor::{AgentOutput, ExecutionResult};

    let success_result = ExecutionResult {
        outputs: vec![
            AgentOutput {
                role: "a".to_string(),
                content: "x".to_string(),
                success: true,
            },
            AgentOutput {
                role: "b".to_string(),
                content: "y".to_string(),
                success: true,
            },
        ],
        rounds: 1,
    };
    assert!(success_result.is_success());

    let failure_result = ExecutionResult {
        outputs: vec![
            AgentOutput {
                role: "a".to_string(),
                content: "x".to_string(),
                success: true,
            },
            AgentOutput {
                role: "b".to_string(),
                content: "y".to_string(),
                success: false,
            },
        ],
        rounds: 1,
    };
    assert!(!failure_result.is_success());
}

// ============================================================================
// rulesynth/proposer tests
// ============================================================================

#[test]
fn test_extract_pattern_valid() {
    let text = r#"
Some intro text
PATTERN P001 CWE-79 return -> sanitize_html[0] MEDIUM
Some outro text
"#;

    let result = baco::rulesynth::proposer::extract_pattern(text);
    assert!(result.is_some());
}

#[test]
fn test_extract_pattern_no_pattern_line() {
    let text = "No pattern here\nJust regular text";
    let result = baco::rulesynth::proposer::extract_pattern(text);
    assert!(result.is_none());
}

#[test]
fn test_extract_pattern_invalid_syntax() {
    let text = "PATTERN invalid syntax here";
    let result = baco::rulesynth::proposer::extract_pattern(text);
    assert!(result.is_none());
}

#[test]
fn test_extract_pattern_multiple_lines_first_valid() {
    let text = r#"
PATTERN P001 CWE-79 return -> sanitize_html[0] MEDIUM
PATTERN P002 CWE-89 return -> mysql_query[0] HIGH
"#;

    let result = baco::rulesynth::proposer::extract_pattern(text);
    assert!(result.is_some());
}

#[test]
fn test_build_prompt_messages_first_round() {
    let messages = baco::rulesynth::proposer::build_prompt_messages("CWE-79", "", 0);

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].role, "system");
    assert!(messages[0].content.contains("CWE-79"));
    assert!(messages[0].content.contains("PATTERN"));
    assert_eq!(messages[1].role, "user");
    assert!(messages[1].content.contains("Propose a pattern for CWE-79"));
}

#[test]
fn test_build_prompt_messages_subsequent_round() {
    let feedback = "F1 score too low, need better precision";
    let messages = baco::rulesynth::proposer::build_prompt_messages("CWE-89", feedback, 1);

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].role, "user");
    assert!(messages[1].content.contains("Previous attempt feedback"));
    assert!(messages[1].content.contains("F1 score too low"));
    assert!(messages[1].content.contains("Rewrite the pattern"));
}

#[test]
fn test_build_prompt_messages_system_format() {
    let messages = baco::rulesynth::proposer::build_prompt_messages("CWE-79", "", 0);

    let system = &messages[0].content;
    assert!(system.contains("PATTERN"));
    assert!(system.contains("CWE-"));
    assert!(system.contains("return"));
    assert!(system.contains("param["));
    assert!(system.contains("LOW/MEDIUM/HIGH/CRITICAL"));
}

#[test]
fn test_extract_pattern_with_whitespace() {
    let text = "PATTERN P001 CWE-79 return -> sink[0] HIGH";
    let result = baco::rulesynth::proposer::extract_pattern(text);
    assert!(result.is_some());
}
