//! Regression test for `strip_between_markers`.
//!
//! The prompt markers `[MERGE_ORDER_SECTION_START]` and `[MERGE_ORDER_SECTION_END]`
//! contain `[` and `]`, which are regex metacharacters. The original code wrapped
//! `regex::escape()` inside `\Q...\E` quoting — a PCRE construct the Rust `regex`
//! crate does not support. `Regex::new` returned `Err`, the `Option` was `None`,
//! and the function returned the content unchanged: the toggle was dead and the
//! merge-order section leaked into every prompt.
//!
//! The fix calls `regex::escape()` directly, producing a pattern like
//! `\[MERGE_ORDER_SECTION_START\][\s\S]*?\[MERGE_ORDER_SECTION_END\]` that
//! matches the literal markers.
//!
//! Teeth check: on the buggy code the regex never compiles, the section is
//! returned verbatim, and `assert!(!result.contains(...))` fails. After the fix
//! the section is stripped and the assertion holds.

use baco::llm_analysis::strip_between_markers;

const PROMPT_WITH_SECTION: &str = r#"Before section.
[MERGE_ORDER_SECTION_START]
This is the merge-order detection section.
It should be removed when the toggle is off.
[MERGE_ORDER_SECTION_END]
After section.
"#;

#[test]
fn strips_section_between_literal_markers() {
    let result = strip_between_markers(
        PROMPT_WITH_SECTION,
        "[MERGE_ORDER_SECTION_START]",
        "[MERGE_ORDER_SECTION_END]",
    );

    assert!(
        !result.contains("[MERGE_ORDER_SECTION_START]"),
        "start marker must be removed, got: {result}"
    );
    assert!(
        !result.contains("[MERGE_ORDER_SECTION_END]"),
        "end marker must be removed, got: {result}"
    );
    assert!(
        !result.contains("merge-order detection section"),
        "section body must be removed, got: {result}"
    );
    assert!(
        result.contains("Before section."),
        "content before the section must survive, got: {result}"
    );
    assert!(
        result.contains("After section."),
        "content after the section must survive, got: {result}"
    );
}

#[test]
fn no_section_leaves_content_unchanged() {
    let prompt = "No markers here at all.\nJust plain text.\n";
    let result = strip_between_markers(
        prompt,
        "[MERGE_ORDER_SECTION_START]",
        "[MERGE_ORDER_SECTION_END]",
    );

    assert_eq!(
        result, prompt,
        "when no markers are present the content must be returned unchanged"
    );
}
