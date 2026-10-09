//! Boundary and mutation-sensitivity tests for confidence_refinement.rs
//!
//! These tests target 12 specific mutation survivors from the sweep:
//! - Lines 191, 203, 207: arithmetic operations in factor computation
//! - Lines 224, 274, 279: || gating conditions
//! - Lines 381, 391: comparison thresholds (> vs >=)
//!
//! Each test is designed to fail when its target mutation is applied.

use baco::analysis_context::AnalysisContext;
use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
use baco::findings::Severity;
use baco::phase::helpers::create_finding_with_params;

// ============================================================================
// CLUSTER 1: Arithmetic operations (lines 191, 203, 207)
// These test exact numerical contributions from individual factors
// ============================================================================

/// Test line 191: +0.1 for historical high-confidence pattern match
/// Mutation: + → - or + → *
///
/// To isolate this factor, we need:
/// - A code snippet that matches high-confidence pattern
/// - No other factors contributing (no verification, no context match)
#[test]
fn test_historical_pattern_adds_exactly_0_1() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Create a finding with code that matches high-confidence pattern
    // CWE-79 high-confidence patterns: innerHTML, dangerouslySetInnerHTML, document.write
    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.cwe_id = Some("CWE-79".to_string());

    // This matches the innerHTML pattern
    // Must avoid "input" keyword which would trigger context analysis
    finding.code_snippet = Some("element.innerHTML = data".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("f1").unwrap();

    // Expected: 0.50 + 0.1 = 0.60 (no other factors apply)
    assert!(
        (refined.refined_score - 0.60).abs() < 0.001,
        "Historical high-confidence pattern should add exactly 0.1: got {}",
        refined.refined_score
    );
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::HistoricalPatternMatch),
        "Should have HistoricalPatternMatch factor"
    );
}

/// Test line 203: +0.05 for code context that supports vulnerability
/// Mutation: + → - or + → *
///
/// To isolate this, we need code with support patterns but no contradict patterns.
#[test]
fn test_supporting_context_adds_exactly_0_05() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("f2", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;

    // Code with support pattern (eval is an unsafe sink) but no contradict patterns
    finding.code_snippet = Some("dangerous eval(userInput)".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("f2").unwrap();

    // Expected: 0.50 + 0.05 = 0.55
    assert!(
        (refined.refined_score - 0.55).abs() < 0.001,
        "Supporting context should add exactly 0.05: got {}",
        refined.refined_score
    );
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::SupportsVulnerability),
        "Should have SupportsVulnerability factor"
    );
}

/// Test line 207: -0.15 for code context that contradicts vulnerability
/// Mutation: - → + or - → * (would become 0 or positive)
///
/// To isolate this, we need code with contradict patterns but no support patterns.
#[test]
fn test_contradicting_context_subtracts_exactly_0_15() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("f3", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;

    // Code with contradict pattern (validate) but no support patterns
    finding.code_snippet = Some("validate and sanitize all inputs".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("f3").unwrap();

    // Expected: 0.50 - 0.15 = 0.35
    assert!(
        (refined.refined_score - 0.35).abs() < 0.001,
        "Contradicting context should subtract exactly 0.15: got {}",
        refined.refined_score
    );
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::ContradictsVulnerability),
        "Should have ContradictsVulnerability factor"
    );
}

// ============================================================================
// CLUSTER 2: Boolean || operators (lines 224, 274, 279)
// ============================================================================

/// Test line 224: || in test code detection
/// Mutation: || → && would require ALL conditions to be true
///
/// We test each branch independently to ensure any single match triggers.
#[test]
fn test_test_code_detection_any_match() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Test "test" in path
    let mut finding1 = create_finding_with_params("f4", "Test finding", Severity::Medium);
    finding1.file_path = "src/test_utils.rs".to_string();
    finding1.confidence_score = 0.50;

    let refinements1 = phase.run(vec![finding1], &context, false, 0.1);
    let refined1 = refinements1.get("f4").unwrap();

    // Expected: 0.50 - 0.1 = 0.40
    assert!(
        (refined1.refined_score - 0.40).abs() < 0.001,
        "Path containing 'test' should reduce by 0.1: got {}",
        refined1.refined_score
    );
    assert!(
        refined1
            .factors
            .contains(&ConfidenceFactor::TestCodeRelated),
        "Should have TestCodeRelated factor"
    );

    // Test "mock" in path (different branch of ||)
    let mut finding2 = create_finding_with_params("f5", "Test finding", Severity::Medium);
    finding2.file_path = "src/mock_handler.rs".to_string();
    finding2.confidence_score = 0.50;

    let refinements2 = phase.run(vec![finding2], &context, false, 0.1);
    let refined2 = refinements2.get("f5").unwrap();

    assert!(
        (refined2.refined_score - 0.40).abs() < 0.001,
        "Path containing 'mock' should reduce by 0.1: got {}",
        refined2.refined_score
    );

    // Test "_test." in path (the line 224 branch specifically)
    let mut finding3 = create_finding_with_params("f6", "Test finding", Severity::Medium);
    finding3.file_path = "src/module_test.rs".to_string();
    finding3.confidence_score = 0.50;

    let refinements3 = phase.run(vec![finding3], &context, false, 0.1);
    let refined3 = refinements3.get("f6").unwrap();

    assert!(
        (refined3.refined_score - 0.40).abs() < 0.001,
        "Path containing '_test.' should reduce by 0.1: got {}",
        refined3.refined_score
    );
}

/// Test line 274: || in rationale validation (sound/validated)
/// Mutation: || → && would require BOTH "sound" AND "validated" to be present
#[test]
fn test_rationale_sound_or_validated_either_triggers() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Test "sound" alone
    let mut finding1 = create_finding_with_params("f7", "Test finding", Severity::Medium);
    finding1.file_path = "src/main.rs".to_string();
    finding1.confidence_score = 0.50;
    finding1.verification_notes = Some("rationale analysis: sound approach".to_string());

    let refinements1 = phase.run(vec![finding1], &context, false, 0.1);
    let refined1 = refinements1.get("f7").unwrap();

    // Expected: 0.50 + 0.10 = 0.60
    assert!(
        (refined1.refined_score - 0.60).abs() < 0.001,
        "Rationale with 'sound' should add 0.10: got {}",
        refined1.refined_score
    );
    assert!(
        refined1
            .factors
            .contains(&ConfidenceFactor::RationaleValidated),
        "Should have RationaleValidated factor"
    );

    // Test "validated" alone (different branch of ||)
    let mut finding2 = create_finding_with_params("f8", "Test finding", Severity::Medium);
    finding2.file_path = "src/main.rs".to_string();
    finding2.confidence_score = 0.50;
    finding2.verification_notes = Some("Rationale validated by review".to_string());

    let refinements2 = phase.run(vec![finding2], &context, false, 0.1);
    let refined2 = refinements2.get("f8").unwrap();

    assert!(
        (refined2.refined_score - 0.60).abs() < 0.001,
        "Rationale with 'validated' should add 0.10: got {}",
        refined2.refined_score
    );
}

/// Test line 279: || in rationale validation (flawed/invalid)
/// Mutation: || → && would require BOTH "flawed" AND "invalid" to be present
#[test]
fn test_rationale_flawed_or_invalid_either_triggers() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Test "flawed" alone
    let mut finding1 = create_finding_with_params("f9", "Test finding", Severity::Medium);
    finding1.file_path = "src/main.rs".to_string();
    finding1.confidence_score = 0.50;
    finding1.verification_notes = Some("rationale analysis: flawed reasoning".to_string());

    let refinements1 = phase.run(vec![finding1], &context, false, 0.1);
    let refined1 = refinements1.get("f9").unwrap();

    // Expected: 0.50 - 0.20 = 0.30
    assert!(
        (refined1.refined_score - 0.30).abs() < 0.001,
        "Rationale with 'flawed' should subtract 0.20: got {}",
        refined1.refined_score
    );
    assert!(
        refined1
            .factors
            .contains(&ConfidenceFactor::RationaleValidated),
        "Should have RationaleValidated factor"
    );

    // Test "invalid" alone (different branch of ||)
    let mut finding2 = create_finding_with_params("f10", "Test finding", Severity::Medium);
    finding2.file_path = "src/main.rs".to_string();
    finding2.confidence_score = 0.50;
    finding2.verification_notes = Some("Rationale invalid - missing evidence".to_string());

    let refinements2 = phase.run(vec![finding2], &context, false, 0.1);
    let refined2 = refinements2.get("f10").unwrap();

    assert!(
        (refined2.refined_score - 0.30).abs() < 0.001,
        "Rationale with 'invalid' should subtract 0.20: got {}",
        refined2.refined_score
    );
}

// ============================================================================
// CLUSTER 3: Comparison thresholds (lines 381, 391)
// ============================================================================

/// Test line 381: support_count > contradict_count && support_count > 0
/// Mutations: > → >= at positions 381:26 and 381:62
///
/// The key insight: when support_count == contradict_count, the current code
/// returns neutral (neither supports nor contradicts). If we change > to >=,
/// then equal counts would trigger "supports" (since 1 >= 1 is true).
///
/// We test the boundary case: support_count == contradict_count > 0
#[test]
fn test_equal_support_contradict_counts_are_neutral() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with exactly 1 support pattern and 1 contradict pattern
    // "eval" (support - unsafe sink) + "validate" (contradict)
    // Must avoid "input" which is also a support keyword
    let code = "validate eval(data)";

    let analysis = phase.analyze_code_context(code);

    // With equal counts (1 support, 1 contradict), should be neutral
    assert!(
        !analysis.supports,
        "Equal counts (1 support, 1 contradict) should not trigger supports: {}",
        analysis.explanation
    );
    assert!(
        !analysis.contradicts,
        "Equal counts (1 support, 1 contradict) should not trigger contradicts: {}",
        analysis.explanation
    );
    assert!(
        analysis.explanation.contains("neutral"),
        "Should explain as neutral: {}",
        analysis.explanation
    );
}

/// Test line 381 boundary: support_count just above contradict_count
/// This is the minimal case where supports becomes true
#[test]
fn test_support_one_above_contradict_triggers_supports() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 2 support patterns and 1 contradict pattern
    // "eval" + ".exec(" (2 supports) + "validate" (1 contradict)
    let code = "validate eval and .exec( userInput";

    let analysis = phase.analyze_code_context(code);

    // support_count (2) > contradict_count (1) && support_count > 0
    assert!(
        analysis.supports,
        "support_count (2) > contradict_count (1) should trigger supports"
    );
    assert!(
        !analysis.contradicts,
        "Should not contradict when support > contradict"
    );
}

/// Test line 391: contradict_count > support_count && contradict_count > 0
/// Mutations: > → >= at 391:36, && → || at 391:52, > → >= at 391:72
///
/// Same logic as line 381 but for contradicts
#[test]
fn test_equal_contradict_support_counts_are_neutral() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with exactly 1 contradict pattern and 1 support pattern
    // "validate" (contradict) + "eval" (support)
    // Must avoid "input" which is also a support keyword
    let code = "validate eval(data)";

    let analysis = phase.analyze_code_context(code);

    // With equal counts (1 contradict, 1 support), should be neutral
    assert!(
        !analysis.contradicts,
        "Equal counts (1 contradict, 1 support) should not trigger contradicts: {}",
        analysis.explanation
    );
    assert!(
        !analysis.supports,
        "Equal counts (1 contradict, 1 support) should not trigger supports: {}",
        analysis.explanation
    );
}

/// Test line 391 boundary: contradict_count just above support_count
#[test]
fn test_contradict_one_above_support_triggers_contradicts() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 2 contradict patterns and 1 support pattern
    // "validate" + "sanitize" (2 contradicts) + "eval" (1 support)
    // Must avoid "input" which is a support keyword
    let code = "validate sanitize eval(data)";

    let analysis = phase.analyze_code_context(code);

    // contradict_count (2) > support_count (1) && contradict_count > 0
    assert!(
        analysis.contradicts,
        "contradict_count (2) > support_count (1) should trigger contradicts: {}",
        analysis.explanation
    );
    assert!(
        !analysis.supports,
        "Should not support when contradict > support: {}",
        analysis.explanation
    );
}

/// Test line 391: && operator - both conditions must be true
/// If && → ||, then contradict_count > 0 alone would trigger (even if support > contradict)
#[test]
fn test_contradict_requires_both_conditions() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 3 contradict patterns and 2 support patterns
    // "validate" + "sanitize" + "check" (3 contradicts) + "eval" + ".exec(" (2 supports)
    // contradict_count (3) > support_count (2), so should contradict
    let code = "validate sanitize check eval .exec( data";

    let analysis = phase.analyze_code_context(code);

    // contradict_count (3) > support_count (2) && contradict_count > 0
    assert!(
        analysis.contradicts,
        "Should contradict when contradict_count (3) > support_count (2): {}",
        analysis.explanation
    );
    assert!(
        !analysis.supports,
        "Should not support when contradict > support: {}",
        analysis.explanation
    );
}

/// Test zero support count - should never trigger supports even with contradict = 0
#[test]
fn test_zero_support_count_never_triggers_supports() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 0 support patterns and 0 contradict patterns
    let code = "regular function without patterns";

    let analysis = phase.analyze_code_context(code);

    assert!(
        !analysis.supports,
        "Zero support count should never trigger supports"
    );
    assert!(
        !analysis.contradicts,
        "Zero contradict count should never trigger contradicts"
    );
    assert!(
        analysis.explanation.contains("neutral"),
        "Should be neutral: {}",
        analysis.explanation
    );
}

/// Test zero contradict count with positive support - should trigger supports
#[test]
fn test_positive_support_zero_contradict_triggers_supports() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 1 support pattern and 0 contradict patterns
    let code = "user_input from request";

    let analysis = phase.analyze_code_context(code);

    // support_count (1) > contradict_count (0) && support_count > 0
    assert!(
        analysis.supports,
        "support_count (1) > contradict_count (0) should trigger supports"
    );
}

/// Test zero support count with positive contradict - should trigger contradicts
#[test]
fn test_positive_contradict_zero_support_triggers_contradicts() {
    let phase = ConfidenceRefinementPhase::new();

    // Code with 0 support patterns and 1 contradict pattern
    // "escape" is a contradict keyword, no support keywords
    let code = "escape data";
    let analysis = phase.analyze_code_context(code);

    // contradict_count (1) > support_count (0) && contradict_count > 0
    assert!(
        analysis.contradicts,
        "contradict_count (1) > support_count (0) should trigger contradicts: {}",
        analysis.explanation
    );
}

// ============================================================================
// MUTATION KILLING VERIFICATION
/// These tests explicitly verify each of the 12 mutations would fail
// ============================================================================

#[test]
fn test_line_191_plus_would_fail_if_mutated_to_minus() {
    // If line 191's +0.1 were mutated to -0.1, this would fail
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m1", "Test", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.cwe_id = Some("CWE-79".to_string());
    finding.code_snippet = Some("element.innerHTML = data".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m1").unwrap();

    // If mutation applied: 0.50 - 0.1 = 0.40
    // Expected (correct): 0.50 + 0.1 = 0.60
    assert!(
        (refined.refined_score - 0.60).abs() < 0.001,
        "Line 191 should add 0.1, not subtract: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_203_plus_would_fail_if_mutated_to_minus() {
    // If line 203's +0.05 were mutated to -0.05, this would fail
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m2", "Test", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.code_snippet = Some("process user_input".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m2").unwrap();

    // If mutation applied: 0.50 - 0.05 = 0.45
    // Expected (correct): 0.50 + 0.05 = 0.55
    assert!(
        (refined.refined_score - 0.55).abs() < 0.001,
        "Line 203 should add 0.05, not subtract: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_207_minus_would_fail_if_mutated_to_plus() {
    // If line 207's -0.15 were mutated to +0.15, this would fail
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m3", "Test", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.code_snippet = Some("sanitize and validate input".to_string());

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m3").unwrap();

    // If mutation applied: 0.50 + 0.15 = 0.65
    // Expected (correct): 0.50 - 0.15 = 0.35
    assert!(
        (refined.refined_score - 0.35).abs() < 0.001,
        "Line 207 should subtract 0.15, not add: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_224_or_would_fail_if_mutated_to_and() {
    // If line 224's || were mutated to &&, path with only "_test." would not match
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m4", "Test", Severity::Medium);
    finding.file_path = "src/module_test.rs".to_string(); // Only has "_test.", not "test" or "mock"
    finding.confidence_score = 0.50;

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m4").unwrap();

    // With ||: matches "_test." → 0.50 - 0.1 = 0.40
    // With &&: requires all three → no match → 0.50
    assert!(
        (refined.refined_score - 0.40).abs() < 0.001,
        "Line 224 || should match '_test.' alone: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_274_or_would_fail_if_mutated_to_and() {
    // If line 274's || were mutated to &&, notes with only "sound" would not match
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m5", "Test", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.verification_notes = Some("rationale: sound analysis".to_string()); // Only "sound", not "validated"

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m5").unwrap();

    // With ||: matches "sound" → 0.50 + 0.10 = 0.60
    // With &&: requires both → no match → 0.50
    assert!(
        (refined.refined_score - 0.60).abs() < 0.001,
        "Line 274 || should match 'sound' alone: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_279_or_would_fail_if_mutated_to_and() {
    // If line 279's || were mutated to &&, notes with only "flawed" would not match
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("m6", "Test", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.50;
    finding.verification_notes = Some("rationale: flawed reasoning".to_string()); // Only "flawed", not "invalid"

    let refinements = phase.run(vec![finding], &context, false, 0.1);
    let refined = refinements.get("m6").unwrap();

    // With ||: matches "flawed" → 0.50 - 0.20 = 0.30
    // With &&: requires both → no match → 0.50
    assert!(
        (refined.refined_score - 0.30).abs() < 0.001,
        "Line 279 || should match 'flawed' alone: got {}",
        refined.refined_score
    );
}

#[test]
fn test_line_381_greater_would_fail_if_mutated_to_gte() {
    // If line 381's > were mutated to >=, equal counts would trigger supports
    let phase = ConfidenceRefinementPhase::new();

    // Equal counts: 1 support, 1 contradict
    let code = "validate user_input";
    let analysis = phase.analyze_code_context(code);

    // With >: 1 > 1 is false → neutral
    // With >=: 1 >= 1 is true → supports = true (wrong!)
    assert!(
        !analysis.supports,
        "Line 381 > should not trigger on equal counts"
    );
}

#[test]
fn test_line_391_greater_would_fail_if_mutated_to_gte() {
    // If line 391's > were mutated to >=, equal counts would trigger contradicts
    let phase = ConfidenceRefinementPhase::new();

    // Equal counts: 1 contradict, 1 support
    let code = "validate user_input";
    let analysis = phase.analyze_code_context(code);

    // With >: 1 > 1 is false → neutral
    // With >=: 1 >= 1 is true → contradicts = true (wrong!)
    assert!(
        !analysis.contradicts,
        "Line 391 > should not trigger on equal counts"
    );
}

#[test]
fn test_line_391_and_would_fail_if_mutated_to_or() {
    // If line 391's && were mutated to ||, contradict_count > 0 alone would trigger
    let phase = ConfidenceRefinementPhase::new();

    // support_count (3) > contradict_count (2), but contradict_count (2) > 0
    // With &&: both conditions must be true → contradicts = false (correct)
    // With ||: either condition true → contradicts = true (wrong!)
    let code = "validate sanitize check user_input request body";
    let analysis = phase.analyze_code_context(code);

    assert!(
        !analysis.contradicts,
        "Line 391 && requires both conditions, not just contradict_count > 0"
    );
}
