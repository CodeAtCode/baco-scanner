//! The discovery prompt must ask for traceable findings.
//!
//! It used to instruct the model to over-report without limit, to report "ANY
//! suspicious pattern", and — for C — to assume that user input reaches any
//! function unless proven otherwise. That last instruction invites the model to
//! assert a reachability it has not established, and the evidence gate is off by
//! default, so those findings reach the report unfiltered. Discovery keeps its
//! recall bias; it just has to name what it traced.

use std::fs;
use std::path::Path;

const DISCOVERY_PROMPT: &str = "prompts/phases/llm_discovery.md";

fn read_prompt() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DISCOVERY_PROMPT);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

#[test]
fn test_discovery_prompt_does_not_mandate_unbounded_over_reporting() {
    let content = read_prompt();

    assert!(
        !content.contains("Better to over-report than miss something"),
        "the over-reporting mandate is back in {DISCOVERY_PROMPT}"
    );
    assert!(
        !content.contains("You MUST report findings even if confidence is low"),
        "the unconditional reporting mandate is back in {DISCOVERY_PROMPT}"
    );
    assert!(
        !content.contains("assume worst-case"),
        "the worst-case reachability assumption is back in {DISCOVERY_PROMPT}"
    );
    assert!(
        !content.contains("User input could reach any function unless proven otherwise"),
        "the blanket reachability assumption is back in {DISCOVERY_PROMPT}"
    );
}

#[test]
fn test_discovery_prompt_requires_naming_what_was_traced() {
    let content = read_prompt();

    // Recall is still wanted. What is required is that a finding point at
    // something: a dangerous primitive, or a source and a sink.
    assert!(
        content.contains("source to a sink"),
        "{DISCOVERY_PROMPT} must ask for a source-to-sink path as grounds for a finding"
    );
    assert!(
        content.contains("what would settle the question"),
        "{DISCOVERY_PROMPT} must ask the model to say what would confirm its finding"
    );
    assert!(
        content.contains("unsupported certainty is not"),
        "{DISCOVERY_PROMPT} must reject unsupported certainty, not low confidence itself"
    );
}
