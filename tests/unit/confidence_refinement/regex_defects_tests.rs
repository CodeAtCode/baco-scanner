/// Tests for Defects 2 & 3: regex compilation errors and case-insensitive patterns
use baco::confidence_refinement::HistoricalData;

#[test]
fn test_never_submit_pattern_case_insensitive_xframe() {
    let historical_data = HistoricalData::new();

    // Test that uppercase X-Frame-Options matches (Defect 3 fix)
    let cwe_str = "CWE-693".to_string();
    let result = historical_data.check_never_submit_pattern(
        "Missing security header",
        "X-Frame-Options header not set",
        Some(&cwe_str),
    );

    // Should match because pattern is now case-insensitive
    assert!(
        result.is_some(),
        "Should match X-Frame-Options (case-insensitive)"
    );
    assert!(
        result.unwrap().contains("CWE-693"),
        "Should identify CWE-693 pattern"
    );
}

#[test]
fn test_never_submit_pattern_hsts_case_insensitive() {
    let historical_data = HistoricalData::new();

    // Test HSTS uppercase variant
    let cwe_str = "CWE-693".to_string();
    let result = historical_data.check_never_submit_pattern(
        "Missing HSTS header",
        "Strict-Transport-Security (HSTS) not configured",
        Some(&cwe_str),
    );

    assert!(result.is_some(), "Should match HSTS (case-insensitive)");
}

#[test]
fn test_never_submit_pattern_csp_lowercase() {
    let historical_data = HistoricalData::new();

    // Test content-security-policy (already lowercase in pattern)
    // Note: pattern uses \. for literal dots, so we need to match that
    let cwe_str = "CWE-693".to_string();
    let result = historical_data.check_never_submit_pattern(
        "CSP issue",
        "content.security.policy header missing",
        Some(&cwe_str),
    );

    assert!(result.is_some(), "Should match content.security.policy");
}
