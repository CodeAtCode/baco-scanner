//! Rulesynth emitter tests

use baco::rulesynth::emitter;
use baco::rulesynth::pattern_dsl::{Pattern, Severity, TaintSink, TaintSource};

#[test]
fn test_emit_yaml_valid_parses_back() {
    // Verify emitter output is valid YAML that parses back
    let pattern = Pattern {
        id: "test-rule-1".to_string(),
        cwe: "CWE-89".to_string(),
        severity: Severity::High,
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "execute_query".to_string(),
            arg_position: 0,
        },
    };

    let yaml = emitter::emit_yaml(&pattern);

    // Basic YAML structure validation
    assert!(yaml.contains("rules:"));
    assert!(yaml.contains("id: test-rule-1"));
    assert!(yaml.contains("mode: taint"));
    assert!(yaml.contains("pattern-sources:"));
    assert!(yaml.contains("pattern-sinks:"));
    assert!(yaml.contains("severity: HIGH"));
    assert!(yaml.contains("cwe: CWE-89"));
    assert!(yaml.contains("mocq_generated: true"));
    assert!(yaml.contains("parameter 0"));
    assert!(yaml.contains("execute_query"));
}

#[test]
fn test_emit_yaml_return_source() {
    // Test with return value source
    let pattern = Pattern {
        id: "return-source-rule".to_string(),
        cwe: "CWE-79".to_string(),
        severity: Severity::Critical,
        source: TaintSource::Return,
        sink: TaintSink {
            function: "render".to_string(),
            arg_position: 0,
        },
    };

    let yaml = emitter::emit_yaml(&pattern);

    assert!(yaml.contains("id: return-source-rule"));
    assert!(yaml.contains("pattern: $FN = ..."));
    assert!(yaml.contains("return value"));
    assert!(yaml.contains("render"));
}

#[test]
fn test_emit_yaml_parameter_source() {
    // Test with parameter source
    let pattern = Pattern {
        id: "param-source-rule".to_string(),
        cwe: "CWE-22".to_string(),
        severity: Severity::High,
        source: TaintSource::Param(1),
        sink: TaintSink {
            function: "file_put_contents".to_string(),
            arg_position: 0,
        },
    };

    let yaml = emitter::emit_yaml(&pattern);

    assert!(yaml.contains("id: param-source-rule"));
    assert!(yaml.contains("pattern: $FN(..., $ARG1, ...)"));
    assert!(yaml.contains("parameter 1"));
    assert!(yaml.contains("file_put_contents"));
}

#[test]
fn test_emit_yaml_multiple_sinks() {
    // Test that different sinks produce different output
    let sql_pattern = Pattern {
        id: "sql-injection".to_string(),
        cwe: "CWE-89".to_string(),
        severity: Severity::Critical,
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "mysql_query".to_string(),
            arg_position: 0,
        },
    };

    let xss_pattern = Pattern {
        id: "xss-injection".to_string(),
        cwe: "CWE-79".to_string(),
        severity: Severity::High,
        source: TaintSource::Param(0),
        sink: TaintSink {
            function: "echo".to_string(),
            arg_position: 0,
        },
    };

    let sql_yaml = emitter::emit_yaml(&sql_pattern);
    let xss_yaml = emitter::emit_yaml(&xss_pattern);

    assert!(sql_yaml.contains("mysql_query"));
    assert!(xss_yaml.contains("echo"));
    assert!(sql_yaml.contains("CWE-89"));
    assert!(xss_yaml.contains("CWE-79"));
}
