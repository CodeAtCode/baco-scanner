//! Empty-prompt guard for the verification phase.
//!
//! The phase must not run without its prompt: an empty prompt sent to the model
//! produces arbitrary verdicts for every finding, and those verdicts get recorded
//! as if they were the model's reasoned answer.
//!
//! The guard used to live inside `load_verification_prompt`, which resolves the
//! packaged prompt directory, so its panic branch was unreachable from a test.
//! It now lives in `require_verification_prompt`, which these tests call directly.
//!
//! The previous version of this file asserted the guard's condition against a copy
//! of it defined in the test body, which asserted that the copy was correct rather
//! than that the production code was. Neutralising the production guard left every
//! test here passing.

use baco::scanner::phases::llm_phases::verification::require_verification_prompt;

/// A present, non-empty prompt is returned unchanged.
#[test]
fn a_present_prompt_is_returned() {
    assert_eq!(
        require_verification_prompt(Some("the seven-question gate")),
        "the seven-question gate"
    );
}

/// Surrounding whitespace does not make a prompt empty, and is not stripped: the
/// model receives exactly what the file contains.
#[test]
fn surrounding_whitespace_is_preserved() {
    assert_eq!(
        require_verification_prompt(Some("  content  ")),
        "  content  "
    );
}

/// A missing prompt panics. The panic is the behaviour — sending an empty prompt on
/// would produce confident nonsense for every finding.
#[test]
#[should_panic(expected = "prompts/phases/llm_verification.md is missing or empty")]
fn a_missing_prompt_panics() {
    let _ = require_verification_prompt(None);
}

/// An empty prompt panics, which is the case the guard's `trim` exists to catch.
#[test]
#[should_panic(expected = "prompts/phases/llm_verification.md is missing or empty")]
fn an_empty_prompt_panics() {
    let _ = require_verification_prompt(Some(""));
}

/// A whitespace-only prompt panics too. Without the `trim` this would pass the guard
/// and reach the model.
#[test]
#[should_panic(expected = "prompts/phases/llm_verification.md is missing or empty")]
fn a_whitespace_only_prompt_panics() {
    let _ = require_verification_prompt(Some("   \n\t  "));
}

/// The panic message must name the file and say why an empty prompt is fatal. A
/// generic message would leave whoever hits it unable to act.
#[test]
#[should_panic(expected = "empty prompt sent to the model produces arbitrary verdicts")]
fn the_panic_message_explains_the_consequence() {
    let _ = require_verification_prompt(None);
}

/// The packaged prompt is present and carries the gate. This is the happy path the
/// other tests depend on being real.
#[test]
fn the_packaged_prompt_carries_the_gate() {
    let prompt = baco::scanner::phases::llm_phases::verification::load_verification_prompt();
    assert!(
        prompt.contains("Gate") || prompt.contains("gate"),
        "the packaged verification prompt must carry the gate section"
    );
}
