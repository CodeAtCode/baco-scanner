//! Unit tests for proposer module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::{build_prompt_messages, extract_pattern};

#[test]
fn test_extract_pattern_finds_line() {
    let text = "Here is the pattern:\nPATTERN p1 CWE-89 return -> mysql_query[0] HIGH\nDone.";
    let p = extract_pattern(text).expect("Should extract pattern");
    assert_eq!(p.id, "p1");
    assert_eq!(p.cwe, "CWE-89");
}

#[test]
fn test_extract_pattern_none() {
    assert!(extract_pattern("no pattern here").is_none());
}

#[test]
fn test_extract_pattern_multiple_takes_first() {
    let text = "PATTERN p1 CWE-89 return -> mysql_query[0] HIGH\nPATTERN p2 CWE-79 return -> echo[0] MEDIUM";
    let p = extract_pattern(text).unwrap();
    assert_eq!(p.id, "p1");
}

#[test]
fn test_build_prompt_first_round() {
    let msgs = build_prompt_messages("CWE-89", "", 0);
    assert_eq!(msgs.len(), 2);
    assert!(msgs[1].content.contains("Propose"));
}

#[test]
fn test_build_prompt_rewrite_round() {
    let msgs = build_prompt_messages("CWE-89", "F1=0.5", 1);
    assert!(msgs[1].content.contains("Rewrite"));
}
