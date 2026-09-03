//! Unit tests for symbolic_validator module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::pattern_dsl::{Pattern, Severity, TaintSink, TaintSource};
use baco::rulesynth::symbolic_validator::{load_corpus, pattern_matches_code, TraceResult};
use baco::rulesynth::{format_feedback, validate, LabelledTrace, ValidationOutcome};

fn make_pattern() -> Pattern {
    Pattern {
        id: "p1".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    }
}

#[test]
fn test_validate_all_correct() {
    let pattern = make_pattern();
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(conn, q)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
        LabelledTrace {
            code: "safe_function()".into(),
            is_vulnerable: false,
            cwe: String::new(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results[0], TraceResult::TruePositive);
    assert_eq!(outcome.results[1], TraceResult::TrueNegative);
    assert!((outcome.f1 - 1.0).abs() < 1e-9);
}

#[test]
fn test_validate_false_positive() {
    let pattern = make_pattern();
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(x)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
        LabelledTrace {
            code: "mysql_query(benign)".into(),
            is_vulnerable: false,
            cwe: String::new(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results[1], TraceResult::FalsePositive);
    assert!(outcome.precision < 1.0);
}

#[test]
fn test_validate_false_negative() {
    let pattern = make_pattern();
    let traces = vec![
        LabelledTrace {
            code: "mysql_query(x)".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
        LabelledTrace {
            code: "other_fn()".into(),
            is_vulnerable: true,
            cwe: "CWE-89".into(),
        },
    ];
    let outcome = validate(&pattern, &traces);
    assert_eq!(outcome.results[1], TraceResult::FalseNegative);
    assert!(outcome.recall < 1.0);
}

#[test]
fn test_param_source_matches() {
    let pattern = Pattern {
        id: "p2".into(),
        cwe: "CWE-79".into(),
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "print".into(),
            arg_position: 1,
        },
        severity: Severity::Medium,
    };
    assert!(pattern_matches_code(&pattern, "print(user_input, opts)"));
    assert!(!pattern_matches_code(&pattern, "print()"));
}

#[test]
fn test_format_feedback_converged() {
    let outcome = ValidationOutcome {
        results: vec![TraceResult::TruePositive, TraceResult::TrueNegative],
        precision: 1.0,
        recall: 1.0,
        f1: 1.0,
    };
    let fb = format_feedback(&outcome);
    assert!(fb.contains("converged"));
}

#[test]
fn test_load_corpus_missing_dir() {
    let traces = load_corpus(std::path::Path::new("/nonexistent/path"));
    assert!(traces.is_empty());
}
