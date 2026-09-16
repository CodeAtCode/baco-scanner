//! Unit tests for src/context/semantic_path.rs - SemanticPathContext

// ============================================================================
// Migrated inline tests from src/context/semantic_path.rs (3 tests)
// ============================================================================

#[test]
fn test_summarize_mock_with_function_inline_migrated() {
    use baco::context::semantic_path::summarize_mock;

    let source = "fn main() { println!(\"hello\"); }";
    let result = summarize_mock(source).expect("Should summarize");

    assert!(!result.summary.is_empty(), "Summary should not be empty");
    assert!(
        result.summary.contains("function"),
        "Should mention functions"
    );
}

#[test]
fn test_summarize_mock_empty_inline_migrated() {
    use baco::context::semantic_path::summarize_mock;

    let source = "";
    let result = summarize_mock(source);

    assert!(result.is_err(), "Should error on empty source");
}

#[test]
fn test_truncation_bound_inline_migrated() {
    let long_source = "x ".repeat(3000);
    let truncated = if long_source.len() > 2000 {
        &long_source[..2000]
    } else {
        &long_source
    };

    assert_eq!(truncated.len(), 2000, "Should truncate to 2000 chars");
}
