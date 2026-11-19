//! The test-code penalty is keyed on path components, not on a substring.
//!
//! A substring check for `test` also matches `latest_version.rs` and
//! `contest.rs`, so real source was penalised as if it were a fixture.

use baco::analysis_context::AnalysisContext;
use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
use baco::findings::Severity;
use baco::phase::helpers::create_finding_with_params;

fn factors_for(file_path: &str) -> Vec<ConfidenceFactor> {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
    finding.file_path = file_path.to_string();

    phase
        .run(vec![finding], &AnalysisContext::default(), true, 0.1)
        .get("f1")
        .expect("a refinement is produced for f1")
        .factors
        .clone()
}

#[test]
fn a_path_that_merely_contains_the_word_test_is_not_test_code() {
    for path in [
        "src/latest_version.rs",
        "src/contest.rs",
        "src/testimony/handler.rs",
        "src/attestation.rs",
    ] {
        assert!(
            !factors_for(path).contains(&ConfidenceFactor::TestCodeRelated),
            "{path} was penalised as test code"
        );
    }
}

#[test]
fn a_genuine_test_or_mock_path_is_penalised() {
    for path in [
        "src/test.rs",
        "tests/integration/scan.rs",
        "src/handler_test.rs",
        "src/__tests__/a.rs",
        "src/mock_user.rs",
        "src/mocks/store.rs",
    ] {
        assert!(
            factors_for(path).contains(&ConfidenceFactor::TestCodeRelated),
            "{path} was not penalised as test code"
        );
    }
}
