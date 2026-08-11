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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rulesynth::pattern_dsl::{Pattern, Severity, TaintSink, TaintSource};

    #[test]
    fn test_emit_return_source() {
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
        let yaml = emit_yaml(&pattern);
        assert!(yaml.contains("id: p1"));
        assert!(yaml.contains("mode: taint"));
        assert!(yaml.contains("mysql_query"));
        assert!(yaml.contains("severity: HIGH"));
        assert!(yaml.contains("mocq_generated: true"));
    }

    #[test]
    fn test_emit_param_source() {
        let pattern = Pattern {
            id: "p2".into(),
            cwe: "CWE-79".into(),
            source: TaintSource::Param(0),
            sink: TaintSink {
                function: "echo".into(),
                arg_position: 0,
            },
            severity: Severity::Medium,
        };
        let yaml = emit_yaml(&pattern);
        assert!(yaml.contains("$ARG0"));
        assert!(yaml.contains("severity: MEDIUM"));
    }

    #[test]
    fn test_source_label() {
        assert_eq!(source_label(&TaintSource::Return), "return value");
        assert_eq!(source_label(&TaintSource::Param(2)), "parameter 2");
    }
}
