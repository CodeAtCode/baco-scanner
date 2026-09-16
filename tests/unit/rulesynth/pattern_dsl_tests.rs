//! Unit tests for pattern_dsl module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::pattern_dsl::{parse_pattern, Severity, TaintSource};

#[test]
fn test_parse_return_source() {
    let p = parse_pattern("PATTERN p1 CWE-89 return -> mysql_query[0] HIGH").unwrap();
    assert_eq!(p.id, "p1");
    assert_eq!(p.cwe, "CWE-89");
    assert_eq!(p.source, TaintSource::Return);
    assert_eq!(p.sink.function, "mysql_query");
    assert_eq!(p.sink.arg_position, 0);
    assert_eq!(p.severity, Severity::High);
}

#[test]
fn test_parse_param_source() {
    let p = parse_pattern("PATTERN p2 CWE-79 param[0] -> htmlspecialchars[1] MEDIUM").unwrap();
    assert_eq!(p.source, TaintSource::Param(0));
    assert_eq!(p.sink.arg_position, 1);
}

#[test]
fn test_parse_critical() {
    let p = parse_pattern("PATTERN p3 CWE-78 return -> system[0] CRITICAL").unwrap();
    assert_eq!(p.severity, Severity::Critical);
}

#[test]
fn test_parse_malformed() {
    assert!(parse_pattern("not a pattern").is_err());
    assert!(parse_pattern("PATTERN p1 CWE-89").is_err());
    assert!(parse_pattern("PATTERN p1 CWE-89 bogus -> mysql_query[0] HIGH").is_err());
}

#[test]
fn test_severity_as_str() {
    assert_eq!(Severity::Low.as_str(), "LOW");
    assert_eq!(Severity::Critical.as_str(), "CRITICAL");
}
