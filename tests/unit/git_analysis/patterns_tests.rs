//! Tests for git_analysis patterns module

use baco::git_analysis::{
    patterns::{
        analyze_commit_message, calculate_pattern_confidence, compile_risky_patterns,
        compile_vulnerability_patterns, get_security_keywords,
    },
    RiskyPatternType, VulnerabilityPatternType,
};

#[test]
fn test_compile_vulnerability_patterns() {
    let patterns = compile_vulnerability_patterns();

    assert!(!patterns.is_empty(), "Should have vulnerability patterns");
    assert!(
        patterns.len() >= 10,
        "Should have at least 10 vulnerability patterns"
    );

    // All patterns should be valid regex
    for (regex, _, _) in &patterns {
        assert!(regex.as_str().len() > 0);
    }
}

#[test]
fn test_compile_risky_patterns() {
    let patterns = compile_risky_patterns();

    assert!(!patterns.is_empty(), "Should have risky patterns");
    assert!(patterns.len() >= 4, "Should have at least 4 risky patterns");

    // All risk scores should be in valid range
    for (_, _, risk_score) in &patterns {
        assert!(
            *risk_score >= 0.0 && *risk_score <= 1.0,
            "Risk score should be between 0 and 1"
        );
    }
}

#[test]
fn test_get_security_keywords() {
    let keywords = get_security_keywords();

    assert!(!keywords.is_empty(), "Should have security keywords");
    assert!(
        keywords.len() >= 20,
        "Should have at least 20 security keywords"
    );

    // Check for expected keywords
    let keyword_set: std::collections::HashSet<_> = keywords.iter().collect();
    assert!(keyword_set.contains(&"security"));
    assert!(keyword_set.contains(&"vulnerability"));
    assert!(keyword_set.contains(&"authentication"));
    assert!(keyword_set.contains(&"authorization"));
    assert!(keyword_set.contains(&"cwe"));
}

#[test]
fn test_analyze_commit_message_no_security() {
    let keywords = get_security_keywords();
    let message = "Add new feature";

    let (is_security_fix, cwe_refs) = analyze_commit_message(message, &keywords);

    assert!(!is_security_fix, "Should not detect security fix");
    assert!(cwe_refs.is_empty(), "Should have no CWE references");
}

#[test]
fn test_analyze_commit_message_with_security_keyword() {
    let keywords = get_security_keywords();
    let message = "Fix security vulnerability in authentication";

    let (is_security_fix, cwe_refs) = analyze_commit_message(message, &keywords);

    assert!(is_security_fix, "Should detect security fix");
    assert!(cwe_refs.is_empty(), "Should have no CWE references");
}

#[test]
fn test_analyze_commit_message_with_cwe_reference() {
    let keywords = get_security_keywords();
    let message = "Fix XSS issue - CWE-79";

    let (is_security_fix, cwe_refs) = analyze_commit_message(message, &keywords);

    assert!(is_security_fix, "Should detect security fix");
    assert!(!cwe_refs.is_empty(), "Should have CWE references");
    assert_eq!(cwe_refs.len(), 1);
    assert_eq!(cwe_refs[0], "CWE-79");
}

#[test]
fn test_analyze_commit_message_multiple_cwe_references() {
    let keywords = get_security_keywords();
    let message = "Fix vulnerabilities: CWE-79 and CWE-89";

    let (is_security_fix, cwe_refs) = analyze_commit_message(message, &keywords);

    assert!(is_security_fix, "Should detect security fix");
    assert_eq!(cwe_refs.len(), 2);
    assert!(cwe_refs.contains(&"CWE-79".to_string()));
    assert!(cwe_refs.contains(&"CWE-89".to_string()));
}

#[test]
fn test_analyze_commit_message_case_insensitive() {
    let keywords = get_security_keywords();

    let (is_security_upper, _) =
        analyze_commit_message("FIX SECURITY ISSUE", &keywords);
    let (is_security_lower, _) =
        analyze_commit_message("fix security issue", &keywords);
    let (is_security_mixed, _) =
        analyze_commit_message("Fix SecUrItY Issue", &keywords);

    assert!(is_security_upper, "Should be case insensitive (uppercase)");
    assert!(is_security_lower, "Should be case insensitive (lowercase)");
    assert!(is_security_mixed, "Should be case insensitive (mixed case)");
}

#[test]
fn test_calculate_pattern_confidence_recent_security_fix() {
    let now = chrono::Utc::now().timestamp();
    let pattern_type = VulnerabilityPatternType::SecurityFix;

    // Recent security fix with CWE reference
    let confidence = calculate_pattern_confidence(
        now - 7 * 86400, // 7 days ago
        true,            // is_security_fix
        1,               // cwe_references_count
        &pattern_type,
    );

    assert!(
        confidence >= 0.9,
        "Recent security fix should have high confidence"
    );
    assert!(confidence <= 1.0, "Confidence should not exceed 1.0");
}

#[test]
fn test_calculate_pattern_confidence_old_commit() {
    let now = chrono::Utc::now().timestamp();
    let pattern_type = VulnerabilityPatternType::SecurityTodo;

    // Old commit, not security fix
    let confidence = calculate_pattern_confidence(
        now - 200 * 86400, // 200 days ago
        false,             // not security fix
        0,                 // no CWE references
        &pattern_type,
    );

    assert!(
        confidence >= 0.4,
        "Old non-security commit should have moderate confidence"
    );
    assert!(confidence <= 0.6, "Should be close to base 0.5");
}

#[test]
fn test_calculate_pattern_confidence_security_fix_bonus() {
    let now = chrono::Utc::now().timestamp();

    // Security fix pattern type
    let confidence_fix = calculate_pattern_confidence(
        now,
        false,
        0,
        &VulnerabilityPatternType::SecurityFix,
    );

    // Non-security pattern type
    let confidence_other = calculate_pattern_confidence(
        now,
        false,
        0,
        &VulnerabilityPatternType::SecurityTodo,
    );

    assert!(
        confidence_fix > confidence_other,
        "SecurityFix pattern should have higher confidence"
    );
}

#[test]
fn test_calculate_pattern_confidence_cwe_bonus() {
    let now = chrono::Utc::now().timestamp();

    let confidence_with_cwe =
        calculate_pattern_confidence(now, false, 2, &VulnerabilityPatternType::SecurityTodo);
    let confidence_without_cwe =
        calculate_pattern_confidence(now, false, 0, &VulnerabilityPatternType::SecurityTodo);

    assert!(
        confidence_with_cwe > confidence_without_cwe,
        "CWE references should increase confidence"
    );
}

#[test]
fn test_calculate_pattern_confidence_cap_at_one() {
    let now = chrono::Utc::now().timestamp();

    // Maximum bonuses
    let confidence = calculate_pattern_confidence(
        now,       // Recent
        true,      // Security fix
        5,         // Multiple CWE refs
        &VulnerabilityPatternType::SecurityVulnerability,
    );

    assert!(
        confidence <= 1.0,
        "Confidence should be capped at 1.0"
    );
}

#[test]
fn test_vulnerability_pattern_matches_cwe() {
    let patterns = compile_vulnerability_patterns();

    let cwe_message = "Fixed CWE-79 XSS vulnerability";
    let has_match = patterns.iter().any(|(regex, _, _)| regex.is_match(cwe_message));

    assert!(has_match, "Should match CWE reference");
}

#[test]
fn test_vulnerability_pattern_matches_cve() {
    let patterns = compile_vulnerability_patterns();

    let cve_message = "Patch for CVE-2024-1234";
    let has_match = patterns.iter().any(|(regex, _, _)| regex.is_match(cve_message));

    assert!(has_match, "Should match CVE reference");
}

#[test]
fn test_vulnerability_pattern_matches_security_fix() {
    let patterns = compile_vulnerability_patterns();

    let fix_message = "Fix security vulnerability in input validation";
    let has_match = patterns.iter().any(|(regex, _, _)| regex.is_match(fix_message));

    assert!(has_match, "Should match security fix pattern");
}

#[test]
fn test_vulnerability_pattern_matches_xss() {
    let patterns = compile_vulnerability_patterns();

    let xss_message = "Prevent XSS attack";
    let has_match = patterns
        .iter()
        .any(|(regex, pattern_type, _)| regex.is_match(xss_message) && matches!(pattern_type, VulnerabilityPatternType::InjectionRisk));

    assert!(has_match, "Should match XSS pattern");
}

#[test]
fn test_risky_pattern_matches_emergency() {
    let patterns = compile_risky_patterns();

    let emergency_message = "Emergency hotfix for production";
    let has_match = patterns
        .iter()
        .any(|(regex, pattern_type, _)| regex.is_match(emergency_message) && matches!(pattern_type, RiskyPatternType::EmergencyCommit));

    assert!(has_match, "Should match emergency pattern");
}

#[test]
fn test_risky_pattern_matches_security_bypass() {
    let patterns = compile_risky_patterns();

    let bypass_message = "Bypass security check for testing";
    let has_match = patterns
        .iter()
        .any(|(regex, pattern_type, _)| regex.is_match(bypass_message) && matches!(pattern_type, RiskyPatternType::SecurityBypass));

    assert!(has_match, "Should match security bypass pattern");
}

#[test]
fn test_risky_pattern_matches_revert() {
    let patterns = compile_risky_patterns();

    let revert_message = "Revert previous changes";
    let has_match = patterns
        .iter()
        .any(|(regex, pattern_type, _)| regex.is_match(revert_message) && matches!(pattern_type, RiskyPatternType::Revert));

    assert!(has_match, "Should match revert pattern");
}
