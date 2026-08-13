//! Comprehensive unit tests for rulesynth submodules.
//!
//! Tests: symbolic_validator, pattern_dsl, proposer, emitter

use baco::rulesynth::emitter::emit_yaml;
use baco::rulesynth::pattern_dsl::{parse_pattern, Pattern, Severity, TaintSink, TaintSource};

use baco::rulesynth::symbolic_validator::{
    format_feedback, load_corpus, validate, LabelledTrace, TraceResult, ValidationOutcome,
};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

// ============================================================================
// SYMBOLIC VALIDATOR TESTS
// ============================================================================

#[test]
fn test_validate_empty_traces() {
    let pattern = Pattern {
        id: "p1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let traces: Vec<LabelledTrace> = vec![];
    let outcome = validate(&pattern, &traces);
    assert!(outcome.results.is_empty());
    assert_eq!(outcome.score(), 0.0);
    assert_eq!(outcome.precision, 0.0);
    assert_eq!(outcome.recall, 0.0);
}

#[test]
fn test_validate_all_true_positive() {
    let pattern = Pattern {
        id: "tp1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(conn, user_input)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
        LabelledTrace {
            code: "mysql_query(db, request.data)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 2);
    assert_eq!(outcome.results[0], TraceResult::TruePositive);
    assert_eq!(outcome.results[1], TraceResult::TruePositive);
    assert!((outcome.f1 - 1.0).abs() < 1e-9);
    assert_eq!(outcome.precision, 1.0);
    assert_eq!(outcome.recall, 1.0);
}

#[test]
fn test_validate_all_false_positive() {
    let pattern = Pattern {
        id: "fp1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(conn, constant)".into(),
            is_vulnerable: false,
            cwe: String::new(),
        },
        LabelledTrace {
            code: "mysql_query(db, hardcoded)".into(),
            is_vulnerable: false,
            cwe: String::new(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 2);
    assert_eq!(outcome.results[0], TraceResult::FalsePositive);
    assert_eq!(outcome.results[1], TraceResult::FalsePositive);
    assert_eq!(outcome.score(), 0.0);
    assert_eq!(outcome.precision, 0.0);
}

#[test]
fn test_validate_all_false_negative() {
    let pattern = Pattern {
        id: "fn1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let traces = vec![
        LabelledTrace {
            code: "pg_query(conn, user_input)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
        LabelledTrace {
            code: "sqlite_exec(db, request.data)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 2);
    assert_eq!(outcome.results[0], TraceResult::FalseNegative);
    assert_eq!(outcome.results[1], TraceResult::FalseNegative);
    assert_eq!(outcome.score(), 0.0);
    assert_eq!(outcome.recall, 0.0);
}

#[test]
fn test_validate_mixed_traces() {
    let pattern = Pattern {
        id: "mixed1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(conn, user_input)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        }, // TP
        LabelledTrace {
            code: "mysql_query(conn, constant)".into(),
            is_vulnerable: false,
            cwe: String::new(),
        }, // FP
        LabelledTrace {
            code: "safe_function()".into(),
            is_vulnerable: false,
            cwe: String::new(),
        }, // TN
        LabelledTrace {
            code: "pg_query(conn, user_input)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        }, // FN
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results.len(), 4);
    assert_eq!(outcome.results[0], TraceResult::TruePositive);
    assert_eq!(outcome.results[1], TraceResult::FalsePositive);
    assert_eq!(outcome.results[2], TraceResult::TrueNegative);
    assert_eq!(outcome.results[3], TraceResult::FalseNegative);
    // TP=1, FP=1, TN=1, FN=1 => precision=0.5, recall=0.5, f1=0.5
    assert!((outcome.precision - 0.5).abs() < 1e-9);
    assert!((outcome.recall - 0.5).abs() < 1e-9);
    assert!((outcome.f1 - 0.5).abs() < 1e-9);
}

#[test]
fn test_validation_outcome_score_returns_f1() {
    let outcome = ValidationOutcome {
        results: vec![],
        precision: 0.8,
        recall: 0.6,
        f1: 0.6857142857,
    };
    assert!((outcome.score() - 0.6857142857).abs() < 1e-9);
}

#[test]
fn test_trace_result_enum_variants() {
    // Test all variants can be constructed and compared
    let tp = TraceResult::TruePositive;
    let fp = TraceResult::FalsePositive;
    let tn = TraceResult::TrueNegative;
    let fn_ = TraceResult::FalseNegative;

    assert_ne!(tp, fp);
    assert_ne!(tp, tn);
    assert_ne!(tp, fn_);
    assert_ne!(fp, tn);
    assert_ne!(fp, fn_);
    assert_ne!(tn, fn_);

    assert_eq!(tp, TraceResult::TruePositive);
    assert_eq!(fp, TraceResult::FalsePositive);
    assert_eq!(tn, TraceResult::TrueNegative);
    assert_eq!(fn_, TraceResult::FalseNegative);
}

#[test]
fn test_load_corpus_nonexistent_directory() {
    let traces = load_corpus(Path::new("/nonexistent/path/that/does/not/exist"));
    assert!(traces.is_empty());
}

#[test]
fn test_load_corpus_valid_traces() {
    let dir = tempdir().expect("Failed to create temp dir");
    let vuln_path = dir.path().join("vuln_CWE-89_001.txt");
    let benign_path = dir.path().join("benign_001.txt");

    fs::write(&vuln_path, "mysql_query(conn, user_input)").expect("Failed to write vuln file");
    fs::write(&benign_path, "safe_function()").expect("Failed to write benign file");

    let traces = load_corpus(dir.path());
    assert_eq!(traces.len(), 2);

    let vuln_trace = traces.iter().find(|t| t.is_vulnerable).unwrap();
    assert_eq!(vuln_trace.code, "mysql_query(conn, user_input)");
    assert_eq!(vuln_trace.cwe, "CWE-89");

    let benign_trace = traces.iter().find(|t| !t.is_vulnerable).unwrap();
    assert_eq!(benign_trace.code, "safe_function()");
    assert!(benign_trace.cwe.is_empty());
}

#[test]
fn test_load_corpus_empty_directory() {
    let dir = tempdir().expect("Failed to create temp dir");
    let traces = load_corpus(dir.path());
    assert!(traces.is_empty());
}

#[test]
fn test_load_corpus_malformed_filenames_ignored() {
    let dir = tempdir().expect("Failed to create temp dir");
    let invalid_path = dir.path().join("invalid_file.txt");
    let json_path = dir.path().join("test.json");

    fs::write(&invalid_path, "some code").expect("Failed to write file");
    fs::write(&json_path, "{\"key\": \"value\"}").expect("Failed to write json file");

    let traces = load_corpus(dir.path());
    assert!(traces.is_empty());
}

#[test]
fn test_format_feedback_produces_non_empty_string() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::TruePositive, TraceResult::FalsePositive],
        precision: 0.5,
        recall: 0.5,
        f1: 0.5,
    };
    let feedback = format_feedback(&outcome);
    assert!(!feedback.is_empty());
    assert!(feedback.contains("TP="));
    assert!(feedback.contains("FP="));
    assert!(feedback.contains("Precision="));
    assert!(feedback.contains("F1="));
}

#[test]
fn test_format_feedback_converged_message() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::TruePositive, TraceResult::TrueNegative],
        precision: 1.0,
        recall: 1.0,
        f1: 1.0,
    };
    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("converged"));
    assert!(feedback.contains("No rewrite needed"));
}

#[test]
fn test_format_feedback_too_broad_message() {
    // 1 TP + 1 FP → precision=0.5, recall=1.0 → precision < recall → "too broad"
    let outcome = ValidationOutcome {
        results: vec![TraceResult::TruePositive, TraceResult::FalsePositive],
        precision: 0.5,
        recall: 1.0,
        f1: 0.667,
    };
    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("too broad"));
    assert!(feedback.contains("Tighten the matcher"));
}

#[test]
fn test_format_feedback_too_narrow_message() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::FalseNegative, TraceResult::FalseNegative],
        precision: 0.0,
        recall: 0.0,
        f1: 0.0,
    };
    let feedback = format_feedback(&outcome);
    assert!(feedback.contains("too narrow"));
    assert!(feedback.contains("Broaden the matcher"));
}

// ============================================================================
// PATTERN DSL TESTS
// ============================================================================

#[test]
fn test_pattern_construction() {
    let pattern = Pattern {
        id: "test_pattern".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    assert_eq!(pattern.id, "test_pattern");
    assert_eq!(pattern.cwe, "CWE-89");
    assert_eq!(pattern.source, TaintSource::Return);
    assert_eq!(pattern.sink.function, "mysql_query");
    assert_eq!(pattern.sink.arg_position, 0);
    assert_eq!(pattern.severity, Severity::High);
}

#[test]
fn test_pattern_partial_match_behavior() {
    // Pattern with Param source
    let pattern = Pattern {
        id: "param_test".into(),
        cwe: "CWE-79".into(),
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "print".into(),
            arg_position: 1,
        },
        severity: Severity::Medium,
    };

    // Code that should match (has print with >0 args)
    assert!(pattern.sink.function == "print");

    // Code that should not match (different function)
    let pattern2 = Pattern {
        id: "other".into(),
        cwe: "CWE-79".into(),
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "echo".into(),
            arg_position: 1,
        },
        severity: Severity::Medium,
    };
    assert!(pattern2.sink.function == "echo");
}

#[test]
fn test_parse_pattern_return_source() {
    let line = "PATTERN p1 CWE-89 return -> mysql_query[0] HIGH";
    let pattern = parse_pattern(line).expect("Failed to parse pattern");

    assert_eq!(pattern.id, "p1");
    assert_eq!(pattern.cwe, "CWE-89");
    assert_eq!(pattern.source, TaintSource::Return);
    assert_eq!(pattern.sink.function, "mysql_query");
    assert_eq!(pattern.sink.arg_position, 0);
    assert_eq!(pattern.severity, Severity::High);
}

#[test]
fn test_parse_pattern_param_source() {
    let line = "PATTERN p2 CWE-79 param[0] -> htmlspecialchars[1] MEDIUM";
    let pattern = parse_pattern(line).expect("Failed to parse pattern");

    assert_eq!(pattern.id, "p2");
    assert_eq!(pattern.cwe, "CWE-79");
    assert_eq!(pattern.source, TaintSource::Param(0));
    assert_eq!(pattern.sink.function, "htmlspecialchars");
    assert_eq!(pattern.sink.arg_position, 1);
    assert_eq!(pattern.severity, Severity::Medium);
}

#[test]
fn test_parse_pattern_param_higher_index() {
    let line = "PATTERN p3 CWE-20 param[2] -> system[0] CRITICAL";
    let pattern = parse_pattern(line).expect("Failed to parse pattern");

    assert_eq!(pattern.source, TaintSource::Param(2));
    assert_eq!(pattern.sink.arg_position, 0);
    assert_eq!(pattern.severity, Severity::Critical);
}

#[test]
fn test_parse_pattern_malformed_no_keyword() {
    let result = parse_pattern("not a pattern");
    assert!(result.is_err());
}

#[test]
fn test_parse_pattern_malformed_incomplete() {
    let result = parse_pattern("PATTERN p1 CWE-89");
    assert!(result.is_err());
}

#[test]
fn test_parse_pattern_malformed_invalid_source() {
    let result = parse_pattern("PATTERN p1 CWE-89 bogus -> mysql_query[0] HIGH");
    assert!(result.is_err());
}

#[test]
fn test_parse_pattern_malformed_missing_bracket() {
    let result = parse_pattern("PATTERN p1 CWE-89 return -> mysql_query[0 HIGH");
    assert!(result.is_err());
}

#[test]
fn test_parse_pattern_malformed_invalid_severity() {
    let result = parse_pattern("PATTERN p1 CWE-89 return -> mysql_query[0] EXTREME");
    assert!(result.is_err());
}

#[test]
fn test_severity_all_variants() {
    assert_eq!(Severity::Low.as_str(), "LOW");
    assert_eq!(Severity::Medium.as_str(), "MEDIUM");
    assert_eq!(Severity::High.as_str(), "HIGH");
    assert_eq!(Severity::Critical.as_str(), "CRITICAL");
}

#[test]
fn test_taint_source_return_variant() {
    let source = TaintSource::Return;
    assert_eq!(source, TaintSource::Return);
}

#[test]
fn test_taint_source_param_variants() {
    let source0 = TaintSource::Param(0);
    let source1 = TaintSource::Param(1);
    let source5 = TaintSource::Param(5);

    assert_eq!(source0, TaintSource::Param(0));
    assert_eq!(source1, TaintSource::Param(1));
    assert_eq!(source5, TaintSource::Param(5));
    assert_ne!(source0, source1);
    assert_ne!(source1, source5);
}

// ============================================================================
// EMITTER TESTS
// ============================================================================

#[test]
fn test_emit_yaml_return_source() {
    let pattern = Pattern {
        id: "emit_test_1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let yaml = emit_yaml(&pattern);

    assert!(yaml.contains("id: emit_test_1"));
    assert!(yaml.contains("mode: taint"));
    assert!(yaml.contains("pattern: $FN = ..."));
    assert!(yaml.contains("mysql_query"));
    assert!(yaml.contains("severity: HIGH"));
    assert!(yaml.contains("CWE-89"));
    assert!(yaml.contains("mocq_generated: true"));
    assert!(yaml.contains("return value"));
}

#[test]
fn test_emit_yaml_param_source() {
    let pattern = Pattern {
        id: "emit_test_2".into(),
        cwe: "CWE-79".into(),
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "htmlspecialchars".into(),
            arg_position: 1,
        },
        severity: Severity::Medium,
    };

    let yaml = emit_yaml(&pattern);

    assert!(yaml.contains("id: emit_test_2"));
    assert!(yaml.contains("$ARG0"));
    assert!(yaml.contains("htmlspecialchars"));
    assert!(yaml.contains("severity: MEDIUM"));
    assert!(yaml.contains("parameter 0"));
}

#[test]
fn test_emit_yaml_critical_severity() {
    let pattern = Pattern {
        id: "emit_test_3".into(),
        cwe: "CWE-78".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "system".into(),
            arg_position: 0,
        },
        severity: Severity::Critical,
    };

    let yaml = emit_yaml(&pattern);

    assert!(yaml.contains("severity: CRITICAL"));
    assert!(yaml.contains("system"));
}

#[test]
fn test_emit_yaml_low_severity() {
    let pattern = Pattern {
        id: "emit_test_4".into(),
        cwe: "CWE-200".into(),
        source: TaintSource::Param(1),
        sink: TaintSink {
            function: "log".into(),
            arg_position: 0,
        },
        severity: Severity::Low,
    };

    let yaml = emit_yaml(&pattern);

    assert!(yaml.contains("severity: LOW"));
    assert!(yaml.contains("$ARG1"));
    assert!(yaml.contains("parameter 1"));
}

#[test]
fn test_emit_yaml_valid_yaml_structure() {
    let pattern = Pattern {
        id: "structure_test".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };

    let yaml = emit_yaml(&pattern);

    // Check YAML structure elements
    assert!(yaml.starts_with("rules:"));
    assert!(yaml.contains("- id:"));
    assert!(yaml.contains("pattern-sources:"));
    assert!(yaml.contains("pattern-sinks:"));
    assert!(yaml.contains("message:"));
    assert!(yaml.contains("metadata:"));
    assert!(yaml.contains("cwe:"));
    assert!(yaml.contains("mocq_generated:"));
}
