//! Semgrep YAML emitter for MoCQ patterns (P3.4).
//!
//! Lowers a DSL Pattern to a Semgrep rule YAML string.

use super::pattern_dsl::{Pattern, TaintSource};

/// Emit a single Pattern as a Semgrep YAML rule.
pub fn emit_yaml(pattern: &Pattern) -> String {
    let severity = pattern.severity.as_str();
    let (source_pattern, sink_pattern) = build_patterns(pattern);

    format!(
        r#"rules:
  - id: {id}
    mode: taint
    pattern-sources:
      - patterns:
          - {source_pattern}
    pattern-sinks:
      - patterns:
          - {sink_pattern}
    message: "Potential {cwe} vulnerability: taint flows from {src} to {sink}"
    severity: {severity}
    metadata:
      cwe: {cwe}
      mocq_generated: true
"#,
        id = pattern.id,
        source_pattern = source_pattern,
        sink_pattern = sink_pattern,
        cwe = pattern.cwe,
        src = source_label(&pattern.source),
        sink = pattern.sink.function,
        severity = severity,
    )
}

fn build_patterns(pattern: &Pattern) -> (String, String) {
    let source = match &pattern.source {
        TaintSource::Return => "pattern: $FN = ...".to_string(),
        TaintSource::Param(n) => format!("pattern: $FN(..., $ARG{}, ...)", n),
    };

    let sink = format!("pattern: {}($X, ...)", pattern.sink.function);

    (source, sink)
}

fn source_label(source: &TaintSource) -> String {
    match source {
        TaintSource::Return => "return value".to_string(),
        TaintSource::Param(n) => format!("parameter {}", n),
    }
}
