//! Unit tests for emitter module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::emit_yaml;
use baco::rulesynth::pattern_dsl::{Pattern, Severity, TaintSink, TaintSource};

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
    // source_label is private, so we test it indirectly through emit_yaml
    let pattern_return = Pattern {
        id: "p3".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Return,
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let yaml_return = emit_yaml(&pattern_return);
    assert!(yaml_return.contains("return value"));

    let pattern_param = Pattern {
        id: "p4".into(),
        cwe: "CWE-89".into(),
        source: TaintSource::Param(2),
        sink: TaintSink {
            function: "mysql_query".into(),
            arg_position: 0,
        },
        severity: Severity::High,
    };
    let yaml_param = emit_yaml(&pattern_param);
    assert!(yaml_param.contains("parameter 2"));
}
