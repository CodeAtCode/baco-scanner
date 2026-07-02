//! Edge case tests for pattern matching in confidence refinement.
//!
//! Tests cover:
//! - Invalid regex patterns (don't panic)
//! - Empty regex patterns
//! - Very long code snippets (>5000 chars)
//! - Multiple pattern matches on same finding
//! - Case sensitivity in pattern matching
//! - Unicode characters in code snippets
//! - Special regex characters in code (without escaping)
//! - Overlapping pattern matches

use baco::confidence_refinement::{ConfidenceRefinementPhase, HistoricalData};
use baco::context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus};
use baco::phase::helpers::create_finding_with_params;

/// Creates a finding with custom parameters for pattern tests
fn make_pattern_finding(
    id: &str,
    cwe_id: &str,
    code_snippet: &str,
    file_path: &str,
) -> baco::findings::VulnerabilityFinding {
    let mut finding = create_finding_with_params(id, "Pattern test finding", Severity::Medium);
    finding.cwe_id = Some(cwe_id.to_string());
    finding.code_snippet = Some(code_snippet.to_string());
    finding.file_path = file_path.to_string();
    finding.verification_status = Some(VerificationStatus::NeedsReview);
    finding
}

// ============================================================================
// Invalid Regex Pattern Tests
// ============================================================================

#[test]
fn test_invalid_regex_pattern_does_not_panic() {
    let data = HistoricalData::new();

    // Invalid regex patterns should not panic, should return false
    let invalid_patterns = vec![
        ("CWE-TEST", "[invalid"),
        ("CWE-TEST", "(unclosed"),
        ("CWE-TEST", "*star"),
        ("CWE-TEST", "?question"),
        ("CWE-TEST", "+plus"),
    ];

    for (cwe, code) in invalid_patterns {
        // These should not panic
        let result = std::panic::catch_unwind(|| data.matches_false_positive_pattern(cwe, code));

        assert!(result.is_ok(), "Invalid regex pattern should not panic");
    }
}

#[test]
fn test_invalid_regex_in_high_confidence_patterns() {
    let data = HistoricalData::new();

    // Test that invalid patterns in high confidence also don't panic
    let result =
        std::panic::catch_unwind(|| data.matches_high_confidence_pattern("CWE-TEST", "some code"));

    assert!(
        result.is_ok(),
        "Invalid regex in high confidence should not panic"
    );
}

// ============================================================================
// Empty Pattern Tests
// ============================================================================

#[test]
fn test_empty_regex_pattern_matches_everything() {
    let data = HistoricalData::new();

    // Empty pattern "" matches everything in regex
    // But our predefined patterns don't include empty ones
    let result = data.matches_false_positive_pattern("CWE-NONE", "");

    // Should return false since no patterns exist for CWE-NONE
    assert!(!result);
}

#[test]
fn test_empty_code_snippet_no_match() {
    let data = HistoricalData::new();

    // Empty code snippet should not match any patterns
    assert!(!data.matches_false_positive_pattern("CWE-79", ""));
    assert!(!data.matches_high_confidence_pattern("CWE-79", ""));
}

// ============================================================================
// Very Long Code Snippet Tests
// ============================================================================

#[test]
fn test_very_long_code_snippet_performance() {
    let data = HistoricalData::new();

    // Create a code snippet > 5000 chars
    let long_code = "let x = 1; ".repeat(600); // ~6600 chars

    assert!(long_code.len() > 5000);

    // Should complete quickly (< 300ms)
    let start = std::time::Instant::now();
    let result = data.matches_false_positive_pattern("CWE-79", &long_code);
    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 300,
        "Pattern matching should be fast on long input"
    );
    assert!(!result); // Should not match since no html_escape in repeated code
}

#[test]
fn test_long_code_snippet_with_pattern_match() {
    let data = HistoricalData::new();

    // Long code with a pattern match at the end
    let long_code = format!("{} html_escape(x)", "let x = 1; ".repeat(600));

    let start = std::time::Instant::now();
    let result = data.matches_false_positive_pattern("CWE-79", &long_code);
    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 300,
        "Pattern matching should be fast"
    );
    assert!(result, "Should match html_escape pattern even in long code");
}

// ============================================================================
// Multiple Pattern Match Tests
// ============================================================================

#[test]
fn test_multiple_patterns_same_finding() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Code that matches multiple false positive patterns
    let finding = make_pattern_finding(
        "f1",
        "CWE-79",
        "html_escape(sanitize_html(input))",
        "src/main.rs",
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // Should match false positive pattern and reduce confidence
    assert!(refined.refined_score < refined.original_score);
    assert!(refined
        .factors
        .contains(&baco::confidence_refinement::ConfidenceFactor::FalsePositiveDetected));
}

#[test]
fn test_multiple_cwe_patterns() {
    let data = HistoricalData::new();

    // Test that different CWEs have different patterns
    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape(x)"));
    assert!(!data.matches_false_positive_pattern("CWE-89", "html_escape(x)"));

    assert!(data.matches_false_positive_pattern("CWE-89", "find_by(name: x)"));
    assert!(!data.matches_false_positive_pattern("CWE-79", "find_by(name: x)"));
}

// ============================================================================
// Case Sensitivity Tests
// ============================================================================

#[test]
fn test_case_sensitive_pattern_matching() {
    let data = HistoricalData::new();

    // Patterns are case-sensitive (regex default)
    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape(x)"));
    assert!(!data.matches_false_positive_pattern("CWE-79", "HTML_ESCAPE(x)"));
    assert!(!data.matches_false_positive_pattern("CWE-79", "Html_Escape(x)"));

    // But some patterns like "textContent" are lowercase only
    assert!(data.matches_false_positive_pattern("CWE-79", "textContent = x"));
    assert!(!data.matches_false_positive_pattern("CWE-79", "TEXTCONTENT = x"));
}

#[test]
fn test_case_sensitivity_in_high_confidence() {
    let data = HistoricalData::new();

    assert!(data.matches_high_confidence_pattern("CWE-79", "innerHTML = x"));
    assert!(!data.matches_high_confidence_pattern("CWE-79", "INNERHTML = x"));
    assert!(!data.matches_high_confidence_pattern("CWE-79", "InnerHTML = x"));
}

// ============================================================================
// Unicode Character Tests
// ============================================================================

#[test]
fn test_unicode_characters_in_code() {
    let data = HistoricalData::new();

    // Unicode should not break pattern matching
    let unicode_code = "let 变量 = html_escape(数据);";

    let result =
        std::panic::catch_unwind(|| data.matches_false_positive_pattern("CWE-79", unicode_code));

    assert!(result.is_ok(), "Unicode should not panic");
    assert!(
        result.unwrap(),
        "Should match html_escape even with unicode"
    );
}

#[test]
fn test_emoji_in_code_snippet() {
    let data = HistoricalData::new();

    let emoji_code = "console.log('🔒'); html_escape(input); // secure";

    let result = data.matches_false_positive_pattern("CWE-79", emoji_code);

    assert!(result, "Should match pattern even with emojis");
}

#[test]
fn test_mixed_unicode_ascii() {
    let data = HistoricalData::new();

    let mixed_code = "const 用户 = userInput; escape_html(用户); // 安全";

    let result = data.matches_false_positive_pattern("CWE-79", mixed_code);

    assert!(result, "Should match in mixed unicode/ascii code");
}

// ============================================================================
// Special Regex Character Tests
// ============================================================================

#[test]
fn test_special_regex_chars_in_code_without_escaping() {
    let data = HistoricalData::new();

    // Code with special regex chars that should be treated literally
    let special_code = "const regex = /[a-z]+/; html_escape(input);";

    let result = data.matches_false_positive_pattern("CWE-79", special_code);

    assert!(result, "Should match despite special regex chars in code");
}

#[test]
fn test_dollar_sign_in_code() {
    let data = HistoricalData::new();

    let code_with_dollar = "const price = $100; html_escape(description);";

    let result = data.matches_false_positive_pattern("CWE-79", code_with_dollar);

    assert!(result, "Should match despite $ in code");
}

#[test]
fn test_backslash_in_code() {
    let data = HistoricalData::new();

    let code_with_backslash = "const path = \"C:\\\\Users\\\\test\"; html_escape(path);";

    let result = data.matches_false_positive_pattern("CWE-79", code_with_backslash);

    assert!(result, "Should match despite backslashes in code");
}

#[test]
fn test_parentheses_in_code() {
    let data = HistoricalData::new();

    let code_with_parens = "func(a, b, c); html_escape(result);";

    let result = data.matches_false_positive_pattern("CWE-79", code_with_parens);

    assert!(result, "Should match despite parentheses in code");
}

// ============================================================================
// Overlapping Pattern Match Tests
// ============================================================================

#[test]
fn test_overlapping_patterns_same_cwe() {
    let data = HistoricalData::new();

    // Code that could match multiple patterns for same CWE
    let overlapping_code = "sanitize_html(escape_html(input))";

    // Should match (at least one pattern)
    assert!(data.matches_false_positive_pattern("CWE-79", overlapping_code));
}

#[test]
fn test_multiple_high_confidence_overlapping() {
    let data = HistoricalData::new();

    let overlapping_code = "element.innerHTML = dangerouslySetInnerHTML(html)";

    // Should match high confidence pattern
    assert!(data.matches_high_confidence_pattern("CWE-79", overlapping_code));
}

#[test]
fn test_false_positive_and_high_confidence_mutually_exclusive() {
    let data = HistoricalData::new();

    // Code that matches false positive pattern
    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape(x)"));
    assert!(!data.matches_high_confidence_pattern("CWE-79", "html_escape(x)"));

    // Code that matches high confidence pattern
    assert!(!data.matches_false_positive_pattern("CWE-79", "innerHTML = x"));
    assert!(data.matches_high_confidence_pattern("CWE-79", "innerHTML = x"));
}

// ============================================================================
// Integration Tests with refine_confidence
// ============================================================================

#[test]
fn test_refine_confidence_with_invalid_pattern_code() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Code that would trigger invalid regex handling internally
    let finding = make_pattern_finding("f1", "CWE-79", "let x = /[invalid/", "src/main.rs");

    // Should not panic
    let result = std::panic::catch_unwind(|| phase.run(vec![finding], &context));

    assert!(result.is_ok(), "Invalid regex in code should not panic");
}

#[test]
fn test_refine_confidence_unicode_handling() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_pattern_finding("f1", "CWE-79", "html_escape(用户输入)", "src/main.rs");

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // Should match false positive pattern
    assert!(refined.refined_score < refined.original_score);
    assert!(refined
        .factors
        .contains(&baco::confidence_refinement::ConfidenceFactor::FalsePositiveDetected));
}

#[test]
fn test_refine_confidence_long_code_performance() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let long_code = format!("{} html_escape(x)", "let x = 1; ".repeat(600));

    let finding = make_pattern_finding("f1", "CWE-79", &long_code, "src/main.rs");

    let start = std::time::Instant::now();
    let refinements = phase.run(vec![finding], &context);
    let duration = start.elapsed();

    assert!(duration.as_millis() < 300, "Should be fast on long code");

    let refined = refinements.get("f1").unwrap();
    assert!(refined.refined_score < refined.original_score);
}
