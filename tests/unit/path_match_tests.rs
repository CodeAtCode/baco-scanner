//! Which files a finding is reported as touched by.
//!
//! A mutation run over `src/tools/diff_analysis.rs` left this alive: changing the
//! `||` to `&&` in the path comparison that `run_diff` used to do inline passed
//! the whole suite. Nothing asserted the cases where exactly one of the three
//! disjuncts is true.
//!
//! The two copies of this rule had also drifted. Only the public one was
//! reachable from a test, and it had no bare-filename rule; the inline one had no
//! separator normalisation and no `/` anchor on the suffix, so file_path "foo.rs"
//! matched "myfoo.rs" and a finding was reported as touched by a commit that
//! never touched it. They are now one predicate.

use baco::tools::diff_analysis::path_matches;
use std::path::Path;

/// The first disjunct: the same path.
#[test]
fn an_exact_path_matches() {
    assert!(path_matches("src/auth.php", Path::new("src/auth.php")));
}

/// The second disjunct: a suffix, anchored on the separator.
#[test]
fn a_suffix_matches() {
    assert!(path_matches("auth.php", Path::new("wp-admin/auth.php")));
    assert!(path_matches(
        "src/auth.php",
        Path::new("vendor/lib/src/auth.php")
    ));
}

/// Without the `/` anchor this matched "myfoo.rs" for file_path "foo.rs", so a
/// finding was attributed to a commit that did not touch it.
#[test]
fn a_partial_filename_is_not_a_suffix_match() {
    assert!(
        !path_matches("foo.rs", Path::new("myfoo.rs")),
        "a different file whose name merely ends with the requested one is not the same file"
    );
    assert!(!path_matches("auth.php", Path::new("unauth.php")));
}

/// The third disjunct: basename equality, which is the only rule that fires when
/// the candidate carries no directory to anchor a suffix on. The old inline copy
/// had this rule and the public one did not, which is why no test found it.
///
/// The nested-path case is deliberately NOT asserted here: `path_matches("auth.php",
/// "a/b/c/auth.php")` is already satisfied by the `/auth.php` suffix, so it would
/// pass with this rule removed and would certify nothing.
#[test]
fn a_bare_filename_matches_a_path_with_directories() {
    assert!(
        path_matches("src/auth.php", Path::new("auth.php")),
        "git can report a bare filename for a path that has directories; \
         only the basename rule can match this"
    );
    assert!(path_matches("wp-admin/post.php", Path::new("post.php")));
}

/// Separators were normalised in one copy and not the other.
#[test]
fn backslash_separators_are_normalised() {
    assert!(path_matches("src/auth.php", Path::new(r"src\auth.php")));
    assert!(path_matches("auth.php", Path::new(r"deep\nested\auth.php")));
}

/// A different file in the same directory is not a match.
#[test]
fn a_different_file_does_not_match() {
    assert!(!path_matches("src/auth.php", Path::new("src/login.php")));
    assert!(!path_matches(
        "src/auth.php",
        Path::new("src/auth/handler.php")
    ));
}
