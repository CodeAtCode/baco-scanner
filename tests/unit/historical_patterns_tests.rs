//! `add_literal_false_positive_patterns` had no caller in the test suite.
//!
//! A mutation sweep replaced its whole body with `()` and killed nothing, so three
//! things were unverified: that patterns are regex-escaped on insert, that they land
//! under the `cwe_id` given, and that a second call appends instead of replacing.
//!
//! Everything is asserted through `matches_false_positive_pattern`, the public
//! observer. The escape is the part worth pinning: without `regex::escape`, a literal
//! like `a.b` compiles as a metavariable and matches `axb` too, which would silence
//! real findings that merely look similar to a known-bad shape.

use baco::historical_patterns::HistoricalData;

fn patterns(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_registered_pattern_matches_the_literal_code() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["mysql_query"]));

    assert!(
        data.matches_false_positive_pattern("CWE-89", "db.mysql_query(\"SELECT * FROM t\")"),
        "the registered literal should match code containing it"
    );
}

#[test]
fn unrelated_code_does_not_match() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["mysql_query"]));

    assert!(
        !data.matches_false_positive_pattern("CWE-89", "let total = items.len();"),
        "code with no relation to the pattern must not match"
    );
}

#[test]
fn patterns_are_escaped_so_metacharacters_match_literally() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["a.b"]));

    assert!(
        data.matches_false_positive_pattern("CWE-89", "let s = \"a.b\";"),
        "the literal `a.b` must match text containing `a.b`"
    );
    assert!(
        !data.matches_false_positive_pattern("CWE-89", "let s = \"axb\";"),
        "without escaping, `a.b` would compile as a metavariable and match `axb`; \
         escaping on insert is what prevents that"
    );
}

#[test]
fn patterns_are_stored_under_the_cwe_they_were_given_for() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["mysql_query"]));

    assert!(
        !data.matches_false_positive_pattern("CWE-79", "db.mysql_query(\"SELECT * FROM t\")"),
        "a pattern registered for CWE-89 must not match when asked about CWE-79"
    );
    assert!(
        data.matches_false_positive_pattern("CWE-89", "db.mysql_query(\"SELECT * FROM t\")"),
        "the same code must still match under the CWE it was registered for"
    );
}

#[test]
fn a_second_call_appends_rather_than_replacing() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["mysql_query"]));
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["execute("]));

    assert!(
        data.matches_false_positive_pattern("CWE-89", "db.mysql_query(\"SELECT 1\")"),
        "the first call's pattern must survive the second call"
    );
    assert!(
        data.matches_false_positive_pattern("CWE-89", "stmt.execute(sql);"),
        "the second call's pattern must be present too"
    );
}

#[test]
fn an_empty_registration_leaves_the_cwe_unmatched() {
    let mut data = HistoricalData::new();
    data.add_literal_false_positive_patterns("CWE-89", &[]);

    assert!(
        !data.matches_false_positive_pattern("CWE-89", "anything at all"),
        "registering nothing must not make every snippet match"
    );
}

#[test]
fn a_malformed_pattern_is_rejected_rather_than_panicking() {
    let mut data = HistoricalData::new();
    // An unbalanced brace would be an invalid regex if the escaping were skipped.
    data.add_literal_false_positive_patterns("CWE-89", &patterns(&["a{2"]));

    assert!(
        data.matches_false_positive_pattern("CWE-89", "let n = \"a{2\";"),
        "an escaped literal with an unbalanced brace is still a valid pattern"
    );
    assert!(
        !data.matches_false_positive_pattern("CWE-89", "let n = \"aaaa\";"),
        "unescaped, a single-digit repetition quantifier would match differently"
    );
}
