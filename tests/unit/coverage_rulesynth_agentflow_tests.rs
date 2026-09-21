//! Coverage tests for rulesynth and agent_flow pure functions.

use baco::rulesynth::{
    extract_pattern, extract_rule_id, format_feedback, load_corpus, parse_yaml_rules,
    pattern_matches_code, persist_rules, validate, build_prompt_messages as build_proposer_messages,
    Pattern, Severity, TaintSink, TaintSource, ValidationOutcome, TraceResult, LabelledTrace,
    SemgrepRule,
};
use baco::agent_flow::executor::{topological_sort, resolve_template, AgentOutput};
use baco::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind, NodeKind};
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// rulesynth/mod.rs tests
// ============================================================================

#[test]
fn test_parse_yaml_rules_valid_single_rule() {
    let yaml = r#"---
rules:
  - id: test.rule
    patterns:
      - pattern: $X
"#;
    let result = parse_yaml_rules(yaml, "php");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("id: test.rule"));
}

#[test]
fn test_parse_yaml_rules_valid_multiple_rules() {
    let yaml = r#"---
rules:
  - id: rule.one
    patterns:
      - pattern: $X
---
rules:
  - id: rule.two
    patterns:
      - pattern: $Y
"#;
    let result = parse_yaml_rules(yaml, "php");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_parse_yaml_rules_empty() {
    let result = parse_yaml_rules("", "php");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_parse_yaml_rules_whitespace_only() {
    let result = parse_yaml_rules("   \n\n   ", "php");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert!(rules.is_empty() || rules.iter().all(|r| r.trim().is_empty()));
}

#[test]
fn test_parse_yaml_rules_missing_fields() {
    let yaml = r#"---
rules:
  - invalid: structure
"#;
    let result = parse_yaml_rules(yaml, "php");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert!(!rules.is_empty());
}

#[test]
fn test_persist_rules_success() {
    let temp_dir = TempDir::new().unwrap();
    let rules = vec![
        SemgrepRule {
            id: "test.rule.1".to_string(),
            language: "php".to_string(),
            yaml: "rules:\n  - id: test.rule.1\n".to_string(),
        },
        SemgrepRule {
            id: "test.rule.2".to_string(),
            language: "php".to_string(),
            yaml: "rules:\n  - id: test.rule.2\n".to_string(),
        },
    ];

    let result = persist_rules(&rules, "cwe-89", "php", temp_dir.path().to_str().unwrap());
    assert!(result.is_ok());

    let files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 2);
}

#[test]
fn test_persist_rules_invalid_dir() {
    let rules = vec![SemgrepRule {
        id: "test.rule".to_string(),
        language: "php".to_string(),
        yaml: "rules:".to_string(),
    }];

    let result = persist_rules(&rules, "cwe-89", "php", "/nonexistent/path/that/doesnt/exist");
    assert!(result.is_err());
}

#[test]
fn test_extract_rule_id_present() {
    let yaml = r#"rules:
  - id: com.example.security.sql-injection
    patterns:
      - pattern: mysql_query($X)
"#;
    let result = extract_rule_id(yaml);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "com.example.security.sql-injection");
}

#[test]
fn test_extract_rule_id_missing() {
    let yaml = r#"rules:
  - patterns:
      - pattern: mysql_query($X)
"#;
    let result = extract_rule_id(yaml);
    assert!(result.is_none());
}

#[test]
fn test_extract_rule_id_empty_value() {
    let yaml = r#"rules:
  - id:
    patterns:
      - pattern: mysql_query($X)
"#;
    let result = extract_rule_id(yaml);
    assert!(result.is_none());
}

#[test]
fn test_extract_rule_id_with_quotes() {
    let yaml = r#"rules:
  - id: "quoted.rule.id"
    patterns:
      - pattern: mysql_query($X)
"#;
    let result = extract_rule_id(yaml);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "quoted.rule.id");
}

// ============================================================================
// rulesynth/proposer.rs tests
// ============================================================================

#[test]
fn test_extract_pattern_with_marker() {
    let text = r#"Some explanation
PATTERN p1 CWE-89 return -> mysql_query[0] HIGH
More text"#;
    let result = extract_pattern(text);
    assert!(result.is_some());
    let pattern = result.unwrap();
    assert_eq!(pattern.id, "p1");
    assert_eq!(pattern.cwe, "CWE-89");
    assert!(matches!(pattern.source, TaintSource::Return));
    assert_eq!(pattern.sink.function, "mysql_query");
    assert_eq!(pattern.sink.arg_position, 0);
    assert!(matches!(pattern.severity, Severity::High));
}

#[test]
fn test_extract_pattern_without_marker() {
    let text = r#"Just some text
No pattern here
Nothing useful"#;
    let result = extract_pattern(text);
    assert!(result.is_none());
}

#[test]
fn test_extract_pattern_malformed() {
    let text = "PATTERN invalid syntax here";
    let result = extract_pattern(text);
    assert!(result.is_none());
}

#[test]
fn test_extract_pattern_multiple_returns_first() {
    let text = r#"PATTERN p1 CWE-89 return -> mysql_query[0] HIGH
PATTERN p2 CWE-79 param[0] -> htmlspecialchars[1] MEDIUM"#;
    let result = extract_pattern(text);
    assert!(result.is_some());
    assert_eq!(result.unwrap().id, "p1");
}

#[test]
fn test_build_prompt_messages_round_one_no_feedback() {
    let messages = build_proposer_messages("CWE-89", "", 0);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].role, "system");
    assert_eq!(messages[1].role, "user");
    assert!(messages[1].content.contains("Propose a pattern"));
}

#[test]
fn test_build_prompt_messages_round_two_with_feedback() {
    let feedback = "Pattern is too broad. Tighten the matcher.";
    let messages = build_proposer_messages("CWE-89", feedback, 1);
    assert_eq!(messages.len(), 2);
    assert!(messages[1].content.contains("Previous attempt feedback"));
    assert!(messages[1].content.contains("Rewrite the pattern"));
}

// ============================================================================
// rulesynth/symbolic_validator.rs tests
// ============================================================================

#[test]
fn test_validate_matching_trace() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let traces = vec![LabelledTrace {
        code: "mysql_query(user_input);".to_string(),
        is_vulnerable: true,
        cwe: "CWE-89".to_string(),
    }];

    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 1);
    assert!(matches!(outcome.results[0], TraceResult::TruePositive));
    assert_eq!(outcome.f1, 1.0);
}

#[test]
fn test_validate_non_matching_trace() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let traces = vec![LabelledTrace {
        code: "safe_query(data);".to_string(),
        is_vulnerable: true,
        cwe: "CWE-89".to_string(),
    }];

    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 1);
    assert!(matches!(outcome.results[0], TraceResult::FalseNegative));
    assert_eq!(outcome.f1, 0.0);
}

#[test]
fn test_validate_mixed_corpus() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let traces = vec![
        LabelledTrace {
            code: "mysql_query(user_input);".to_string(),
            is_vulnerable: true,
            cwe: "CWE-89".to_string(),
        },
        LabelledTrace {
            code: "mysql_query(sanitized);".to_string(),
            is_vulnerable: false,
            cwe: "".to_string(),
        },
    ];

    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 2);
    assert!(matches!(outcome.results[0], TraceResult::TruePositive));
    assert!(matches!(outcome.results[1], TraceResult::TrueNegative));
}

#[test]
fn test_pattern_matches_code_exact_match() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let code = "result = mysql_query(query);";
    assert!(pattern_matches_code(&pattern, code));
}

#[test]
fn test_pattern_matches_code_no_match() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let code = "result = postgres_query(query);";
    assert!(!pattern_matches_code(&pattern, code));
}

#[test]
fn test_pattern_matches_code_param_source_with_args() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Param(1),
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let code = "mysql_query(arg0, arg1, arg2);";
    assert!(pattern_matches_code(&pattern, code));
}

#[test]
fn test_pattern_matches_code_param_source_insufficient_args() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Param(2),
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let code = "mysql_query(arg0);";
    assert!(!pattern_matches_code(&pattern, code));
}

#[test]
fn test_pattern_matches_code_empty() {
    let pattern = Pattern {
        id: "test".to_string(),
        cwe: "CWE-89".to_string(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    assert!(!pattern_matches_code(&pattern, ""));
}

#[test]
fn test_load_corpus_valid_files() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("vuln_CWE-89_001.txt"),
        "mysql_query($input);",
    )
    .unwrap();
    std::fs::write(temp_dir.path().join("benign_001.txt"), "safe_query($input);")
        .unwrap();

    let traces = load_corpus(temp_dir.path());
    assert_eq!(traces.len(), 2);

    let vuln_traces: Vec<_> = traces.iter().filter(|t| t.is_vulnerable).collect();
    assert_eq!(vuln_traces.len(), 1);
    assert_eq!(vuln_traces[0].cwe, "CWE-89");
}

#[test]
fn test_load_corpus_missing_path() {
    let traces = load_corpus(Path::new("/nonexistent/path"));
    assert!(traces.is_empty());
}

#[test]
fn test_load_corpus_empty_dir() {
    let temp_dir = TempDir::new().unwrap();
    let traces = load_corpus(temp_dir.path());
    assert!(traces.is_empty());
}

#[test]
fn test_load_corpus_ignores_non_txt_files() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(temp_dir.path().join("vuln_CWE-89_001.txt"), "code").unwrap();
    std::fs::write(temp_dir.path().join("benign_001.md"), "markdown").unwrap();

    let traces = load_corpus(temp_dir.path());
    assert_eq!(traces.len(), 1);
}

#[test]
fn test_format_feedback_includes_context() {
    let outcome = ValidationOutcome {
        results: vec![
            TraceResult::TruePositive,
            TraceResult::TruePositive,
            TraceResult::FalsePositive,
            TraceResult::TrueNegative,
        ],
        precision: 0.667,
        recall: 1.0,
        f1: 0.8,
    };

    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("TP=2"));
    assert!(feedback.contains("FP=1"));
    assert!(feedback.contains("TN=1"));
    assert!(feedback.contains("FN=0"));
    assert!(feedback.contains("F1="));
}

#[test]
fn test_format_feedback_converged_message() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::TruePositive],
        precision: 1.0,
        recall: 1.0,
        f1: 1.0,
    };

    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("Pattern converged"));
}

#[test]
fn test_format_feedback_precision_low_message() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::FalsePositive],
        precision: 0.0,
        recall: 0.0,
        f1: 0.0,
    };

    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("Pattern is too broad"));
}

// ============================================================================
// agent_flow/executor.rs tests
// ============================================================================

#[test]
fn test_topological_sort_linear_chain() {
    let mut harness = AgentFlowHarness::new();
    let n0 = harness.add_agent(Agent {
        role: "a".to_string(),
        prompt: "p0".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n1 = harness.add_agent(Agent {
        role: "b".to_string(),
        prompt: "p1".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n2 = harness.add_agent(Agent {
        role: "c".to_string(),
        prompt: "p2".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });

    harness.add_edge(n0, n1, EdgeKind::Data, "{{ a.out }}".to_string());
    harness.add_edge(n1, n2, EdgeKind::Data, "{{ b.out }}".to_string());

    let order = topological_sort(&harness);
    assert!(order.is_some());
    let order = order.unwrap();
    assert_eq!(order.len(), 3);
    let p0 = order.iter().position(|&x| x == n0).unwrap();
    let p1 = order.iter().position(|&x| x == n1).unwrap();
    let p2 = order.iter().position(|&x| x == n2).unwrap();
    assert!(p0 < p1);
    assert!(p1 < p2);
}

#[test]
fn test_topological_sort_diamond_deps() {
    let mut harness = AgentFlowHarness::new();
    let n0 = harness.add_agent(Agent {
        role: "start".to_string(),
        prompt: "p0".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n1 = harness.add_agent(Agent {
        role: "mid1".to_string(),
        prompt: "p1".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n2 = harness.add_agent(Agent {
        role: "mid2".to_string(),
        prompt: "p2".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n3 = harness.add_agent(Agent {
        role: "end".to_string(),
        prompt: "p3".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });

    harness.add_edge(n0, n1, EdgeKind::Data, "{{ start.out }}".to_string());
    harness.add_edge(n0, n2, EdgeKind::Data, "{{ start.out }}".to_string());
    harness.add_edge(n1, n3, EdgeKind::Data, "{{ mid1.out }}".to_string());
    harness.add_edge(n2, n3, EdgeKind::Data, "{{ mid2.out }}".to_string());

    let order = topological_sort(&harness);
    assert!(order.is_some());
    let order = order.unwrap();
    assert_eq!(order.len(), 4);
    assert_eq!(order[0], n0);
    assert_eq!(order[3], n3);
}

#[test]
fn test_topological_sort_independent_nodes() {
    let mut harness = AgentFlowHarness::new();
    let n0 = harness.add_agent(Agent {
        role: "a".to_string(),
        prompt: "p0".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n1 = harness.add_agent(Agent {
        role: "b".to_string(),
        prompt: "p1".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });

    let order = topological_sort(&harness);
    assert!(order.is_some());
    let order = order.unwrap();
    assert_eq!(order.len(), 2);
}

#[test]
fn test_topological_sort_cycle_detection() {
    let mut harness = AgentFlowHarness::new();
    let n0 = harness.add_agent(Agent {
        role: "a".to_string(),
        prompt: "p0".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });
    let n1 = harness.add_agent(Agent {
        role: "b".to_string(),
        prompt: "p1".to_string(),
        model: "m".to_string(),
        tools: Default::default(),
    });

    harness.add_edge(n0, n1, EdgeKind::Data, "{{ a.out }}".to_string());
    harness.add_edge(n1, n0, EdgeKind::Data, "{{ b.out }}".to_string());

    let order = topological_sort(&harness);
    assert!(order.is_none());
}

#[test]
fn test_topological_sort_empty_harness() {
    let harness = AgentFlowHarness::new();
    let order = topological_sort(&harness);
    assert!(order.is_some());
    assert!(order.unwrap().is_empty());
}

#[test]
fn test_resolve_template_placeholder_substitution() {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "analyst".to_string(),
        AgentOutput {
            role: "analyst".to_string(),
            content: "Found vulnerability in line 42".to_string(),
            success: true,
        },
    );

    let template = "Review: {{ analyst.out }}";
    let resolved = resolve_template(template, &outputs);
    assert_eq!(resolved, "Review: Found vulnerability in line 42");
}

#[test]
fn test_resolve_template_missing_key_unchanged() {
    let outputs = BTreeMap::new();
    let template = "Review: {{ missing.out }}";
    let resolved = resolve_template(template, &outputs);
    assert_eq!(resolved, "Review: {{ missing.out }}");
}

#[test]
fn test_resolve_template_empty_outputs() {
    let outputs = BTreeMap::new();
    let template = "Static text without placeholders";
    let resolved = resolve_template(template, &outputs);
    assert_eq!(resolved, template);
}

#[test]
fn test_resolve_template_multiple_placeholders() {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "analyst".to_string(),
        AgentOutput {
            role: "analyst".to_string(),
            content: "analysis result".to_string(),
            success: true,
        },
    );
    outputs.insert(
        "verifier".to_string(),
        AgentOutput {
            role: "verifier".to_string(),
            content: "verification passed".to_string(),
            success: true,
        },
    );

    let template = "{{ analyst.out }} -> {{ verifier.out }}";
    let resolved = resolve_template(template, &outputs);
    assert_eq!(resolved, "analysis result -> verification passed");
}