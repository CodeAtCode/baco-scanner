//! Symbolic validator for MoCQ pattern checking (P3.2).
//!
//! Checks a proposed Pattern against a labelled trace corpus.
//! Returns precise feedback (true/false per trace + aggregated score)
//! that the proposer uses to rewrite the pattern.

use super::pattern_dsl::{Pattern, TaintSource};
use std::path::Path;

/// A single labelled trace: code snippet + vulnerable flag.
#[derive(Debug, Clone)]
pub struct LabelledTrace {
    pub code: String,
    pub is_vulnerable: bool,
    pub cwe: String,
}

/// Validation result for a single trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceResult {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
}

/// Aggregated validation outcome.
#[derive(Debug, Clone)]
pub struct ValidationOutcome {
    pub results: Vec<TraceResult>,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

impl ValidationOutcome {
    pub fn score(&self) -> f64 {
        self.f1
    }
}

/// Validate a pattern against a corpus of labelled traces.
///
/// Matching is syntactic: the pattern's sink function must appear in the code,
/// and the taint source must be consistent with the call structure.
pub fn validate(pattern: &Pattern, traces: &[LabelledTrace]) -> ValidationOutcome {
    let mut results = Vec::with_capacity(traces.len());
    let mut tp = 0u32;
    let mut fp = 0u32;
    let mut _tn = 0u32;
    let mut fn_ = 0u32;

    for trace in traces {
        let matches = pattern_matches_code(pattern, &trace.code);
        let result = match (matches, trace.is_vulnerable) {
            (true, true) => {
                tp += 1;
                TraceResult::TruePositive
            }
            (true, false) => {
                fp += 1;
                TraceResult::FalsePositive
            }
            (false, false) => {
                _tn += 1;
                TraceResult::TrueNegative
            }
            (false, true) => {
                fn_ += 1;
                TraceResult::FalseNegative
            }
        };
        results.push(result);
    }

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    ValidationOutcome {
        results,
        precision,
        recall,
        f1,
    }
}

/// Check whether a pattern matches a code snippet.
///
/// Syntactic check: the sink function name appears in the code,
/// and if the source is `Param(n)`, the code contains a call to the
/// sink function with at least `n+1` arguments.
fn pattern_matches_code(pattern: &Pattern, code: &str) -> bool {
    if !code.contains(&pattern.sink.function) {
        return false;
    }

    match &pattern.source {
        TaintSource::Return => true,
        TaintSource::Param(n) => {
            let search = format!("{}(", pattern.sink.function);
            if let Some(call_start) = code.find(&search) {
                let after_call = &code[call_start + search.len()..];
                if let Some(close) = after_call.find(')') {
                    let args = &after_call[..close].trim();
                    let arg_count = if args.is_empty() {
                        0
                    } else {
                        args.split(',').count()
                    };
                    return arg_count > *n;
                }
            }
            false
        }
    }
}

/// Load a trace corpus from a directory.
///
/// Each `.txt` file in the directory is a trace. The filename convention:
/// `vuln_<cwe>_<id>.txt` for vulnerable traces, `benign_<id>.txt` for benign.
/// Returns an empty vec if the path does not exist or is not a directory.
pub fn load_corpus(path: &Path) -> Vec<LabelledTrace> {
    let mut traces = Vec::new();
    if !path.is_dir() {
        return traces;
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_none_or(|ext| ext != "txt") {
                continue;
            }
            let filename = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let (is_vulnerable, cwe) = if let Some(rest) = filename.strip_prefix("vuln_") {
                let cwe = rest.split('_').next().unwrap_or("").to_string();
                (true, cwe)
            } else if filename.starts_with("benign_") {
                (false, String::new())
            } else {
                continue;
            };
            if let Ok(code) = std::fs::read_to_string(&p) {
                traces.push(LabelledTrace {
                    code,
                    is_vulnerable,
                    cwe,
                });
            }
        }
    }
    traces
}

/// Format validation feedback for the LLM proposer.
pub fn format_feedback(outcome: &ValidationOutcome) -> String {
    let tp = outcome
        .results
        .iter()
        .filter(|r| **r == TraceResult::TruePositive)
        .count();
    let fp = outcome
        .results
        .iter()
        .filter(|r| **r == TraceResult::FalsePositive)
        .count();
    let tn = outcome
        .results
        .iter()
        .filter(|r| **r == TraceResult::TrueNegative)
        .count();
    let fn_ = outcome
        .results
        .iter()
        .filter(|r| **r == TraceResult::FalseNegative)
        .count();

    format!(
        "Validation results: TP={} FP={} TN={} FN={}\nPrecision={:.3} Recall={:.3} F1={:.3}\n{}",
        tp,
        fp,
        tn,
        fn_,
        outcome.precision,
        outcome.recall,
        outcome.f1,
        if outcome.f1 >= 0.8 {
            "Pattern converged. No rewrite needed."
        } else if outcome.precision < outcome.recall {
            "Pattern is too broad. Tighten the matcher to reduce false positives."
        } else {
            "Pattern is too narrow. Broaden the matcher to catch more true positives."
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rulesynth::pattern_dsl::{TaintSink, TaintSource};

    fn make_pattern() -> Pattern {
        Pattern {
            id: "p1".into(),
            cwe: "CWE-89".into(),
            source: TaintSource::Return,
            sink: TaintSink {
                function: "mysql_query".into(),
                arg_position: 0,
            },
            severity: crate::rulesynth::pattern_dsl::Severity::High,
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
            severity: crate::rulesynth::pattern_dsl::Severity::Medium,
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
}
