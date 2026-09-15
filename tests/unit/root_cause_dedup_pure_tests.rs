use baco::findings::Severity;
use baco::root_cause_dedup::{convert_severity, normalize_code_snippet};
use baco::scanner_types::V3Severity;

#[test]
fn normalize_some_snippet_strips_all_whitespace() {
    assert_eq!(
        normalize_code_snippet(Some("let x = 1;\n  let y  = 2;")),
        "letx=1;lety=2;"
    );
}

#[test]
fn normalize_none_yields_empty() {
    assert_eq!(normalize_code_snippet(None), "");
}

#[test]
fn normalize_empty_some_yields_empty() {
    assert_eq!(normalize_code_snippet(Some("")), "");
}

#[test]
fn normalize_whitespace_only_yields_empty() {
    assert_eq!(normalize_code_snippet(Some(" \n\t\r ")), "");
}

#[test]
fn normalize_preserves_non_whitespace_characters() {
    assert_eq!(normalize_code_snippet(Some("a+b*c(d)")), "a+b*c(d)");
}

#[test]
fn normalize_mixed_content() {
    assert_eq!(
        normalize_code_snippet(Some(" memcpy ( dst , src , n )")),
        "memcpy(dst,src,n)"
    );
}

#[test]
fn normalize_tabs_and_newlines_between_tokens() {
    assert_eq!(normalize_code_snippet(Some("foo\tbar\nbaz")), "foobarbaz");
}

#[test]
fn convert_critical_maps_to_critical() {
    assert!(matches!(
        convert_severity(Severity::Critical),
        V3Severity::Critical
    ));
}

#[test]
fn convert_high_maps_to_high() {
    assert!(matches!(convert_severity(Severity::High), V3Severity::High));
}

#[test]
fn convert_medium_maps_to_medium() {
    assert!(matches!(
        convert_severity(Severity::Medium),
        V3Severity::Medium
    ));
}

#[test]
fn convert_low_maps_to_low() {
    assert!(matches!(convert_severity(Severity::Low), V3Severity::Low));
}

#[test]
fn convert_info_folds_into_low() {
    // Info has no V3 equivalent; it must fold to Low, never vanish or escalate
    assert!(matches!(convert_severity(Severity::Info), V3Severity::Low));
}
