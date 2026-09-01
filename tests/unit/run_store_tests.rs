//! Unit tests for the cross-run prior-findings store.

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::run_store;
use std::fs::File;
use std::io::Write;

fn make_finding(
    id: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
    verification_status: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Test finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

fn make_finding_with_cwe(
    id: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
    cwe_id: Option<&str>,
    verification_status: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Test finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_stable_key_stable_across_line_number_change() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let x = 1;"), None);
    let finding2 = make_finding("2", "src/test.rs", Some(20), Some("let x = 1;"), None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(
        key1, key2,
        "Key should be stable across line number changes"
    );
}

#[test]
fn test_stable_key_stable_across_refactor() {
    // Same logical code, different formatting
    let finding1 = make_finding(
        "1",
        "src/test.rs",
        Some(10),
        Some("let x = 1;\nlet y = 2;"),
        None,
    );
    let finding2 = make_finding(
        "2",
        "src/test.rs",
        Some(15),
        Some("let x = 1; let y = 2;"),
        None,
    );

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(
        key1, key2,
        "Key should be stable across whitespace refactors"
    );
}

#[test]
fn test_stable_key_changes_when_snippet_changes() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let x = 1;"), None);
    let finding2 = make_finding("2", "src/test.rs", Some(10), Some("let x = 2;"), None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_ne!(key1, key2, "Key should change when snippet changes");
}

#[test]
fn test_stable_key_uses_title_when_snippet_none() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), None, None);
    let finding2 = make_finding("2", "src/test.rs", Some(10), None, None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(key1, key2, "Key should be stable when using title fallback");
}

#[test]
fn test_load_prior_runs_empty_dir() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();

    let findings = run_store::load_prior_runs(output_dir, 5);
    assert!(findings.is_empty(), "Should return empty vec for empty dir");
}

#[test]
fn test_save_run_then_load_prior_runs_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();

    let findings = vec![
        make_finding("1", "src/a.rs", Some(10), Some("code a"), None),
        make_finding("2", "src/b.rs", Some(20), Some("code b"), None),
    ];

    run_store::save_run(output_dir, &findings);

    // Find the run directory
    let runs_dir = output_dir.join("runs");
    let run_dirs: Vec<_> = std::fs::read_dir(&runs_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();

    assert_eq!(run_dirs.len(), 1, "Should have created one run directory");

    // Load back
    let loaded = run_store::load_prior_runs(output_dir, 5);
    assert_eq!(loaded.len(), 2, "Should load both findings");
    assert_eq!(loaded[0].id, "1");
    assert_eq!(loaded[1].id, "2");
}

#[test]
fn test_build_prior_knowledge_includes_confirmed_and_fp() {
    let findings = vec![
        make_finding(
            "1",
            "src/a.rs",
            Some(10),
            Some("code a"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "2",
            "src/b.rs",
            Some(20),
            Some("code b"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "3",
            "src/c.rs",
            Some(30),
            Some("code c"),
            Some(VerificationStatus::NeedsReview),
        ),
        make_finding("4", "src/d.rs", Some(40), Some("code d"), None),
    ];

    let prior_knowledge = run_store::build_prior_knowledge(&findings);

    assert_eq!(prior_knowledge.prior_count, 4);
    assert_eq!(
        prior_knowledge.skip_keys.len(),
        2,
        "Should include only Confirmed and FalsePositive"
    );

    // Verify the keys correspond to findings 1 and 2
    let key1 = run_store::stable_finding_key(&findings[0]);
    let key2 = run_store::stable_finding_key(&findings[1]);
    assert!(prior_knowledge.skip_keys.contains(&key1));
    assert!(prior_knowledge.skip_keys.contains(&key2));
}

#[test]
fn test_corrupt_json_skipped_other_runs_loaded() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();
    let runs_dir = output_dir.join("runs");

    // Create two run directories
    let run1_dir = runs_dir.join("run-1000");
    let run2_dir = runs_dir.join("run-2000");
    std::fs::create_dir_all(&run1_dir).unwrap();
    std::fs::create_dir_all(&run2_dir).unwrap();

    // Write valid JSON to run1
    let findings1 = vec![make_finding(
        "1",
        "src/a.rs",
        Some(10),
        Some("code a"),
        None,
    )];
    let json1 = serde_json::to_string(&findings1).unwrap();
    File::create(run1_dir.join("findings.json"))
        .unwrap()
        .write_all(json1.as_bytes())
        .unwrap();

    // Write corrupt JSON to run2
    File::create(run2_dir.join("findings.json"))
        .unwrap()
        .write_all(b"not valid json")
        .unwrap();

    // Load with max_runs=5 (should load both, but skip corrupt)
    let loaded = run_store::load_prior_runs(output_dir, 5);

    assert_eq!(loaded.len(), 1, "Should load only the valid run");
    assert_eq!(loaded[0].id, "1");
}

#[test]
fn test_load_prior_runs_respects_max_runs() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path();
    let runs_dir = output_dir.join("runs");

    // Create 5 run directories
    for i in 1..=5 {
        let run_dir = runs_dir.join(format!("run-{}", i * 1000));
        std::fs::create_dir_all(&run_dir).unwrap();
        let findings = vec![make_finding(
            &i.to_string(),
            "src/a.rs",
            Some(10),
            Some("code"),
            None,
        )];
        let json = serde_json::to_string(&findings).unwrap();
        File::create(run_dir.join("findings.json"))
            .unwrap()
            .write_all(json.as_bytes())
            .unwrap();
    }

    // Load with max_runs=3
    let loaded = run_store::load_prior_runs(output_dir, 3);
    assert_eq!(loaded.len(), 3, "Should load only 3 most recent runs");
}

#[test]
fn test_stable_key_is_12_hex_chars() {
    let finding = make_finding("1", "src/test.rs", Some(10), Some("code"), None);
    let key = run_store::stable_finding_key(&finding);

    assert_eq!(key.len(), 12, "Key should be 12 hex characters");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "Key should contain only hex digits"
    );
}

#[test]
fn test_normalize_snippet_collapses_whitespace() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let   x\t=\n1;"), None);
    let finding2 = make_finding("2", "src/test.rs", Some(10), Some("let x = 1;"), None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(key1, key2, "Whitespace should be normalized");
}

#[test]
fn test_normalize_snippet_lowercases() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), Some("LET X = 1;"), None);
    let finding2 = make_finding("2", "src/test.rs", Some(10), Some("let x = 1;"), None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(key1, key2, "Case should be normalized");
}

#[test]
fn test_taxonomy_rule_id_returns_xss_for_cwe79() {
    let finding = make_finding_with_cwe(
        "1",
        "src/test.rs",
        Some(10),
        Some("code"),
        Some("CWE-79"),
        None,
    );
    let rule_id = run_store::taxonomy_rule_id(&finding);
    assert_eq!(rule_id, "xss/CWE-79", "CWE-79 should map to xss domain");
}

#[test]
fn test_taxonomy_rule_id_returns_uncategorized_none_for_empty_cwe() {
    let finding = make_finding_with_cwe("1", "src/test.rs", Some(10), Some("code"), None, None);
    let rule_id = run_store::taxonomy_rule_id(&finding);
    assert_eq!(
        rule_id, "uncategorized/none",
        "Empty CWE should return uncategorized/none"
    );
}

#[test]
fn test_stable_key_different_for_different_taxonomy_domains() {
    // Same snippet, same file, but different CWEs mapping to different domains
    let finding_xss = make_finding_with_cwe(
        "1",
        "src/test.rs",
        Some(10),
        Some("let x = 1;"),
        Some("CWE-79"),
        None,
    );
    let finding_injection = make_finding_with_cwe(
        "2",
        "src/test.rs",
        Some(10),
        Some("let x = 1;"),
        Some("CWE-89"),
        None,
    );

    let key_xss = run_store::stable_finding_key(&finding_xss);
    let key_injection = run_store::stable_finding_key(&finding_injection);

    assert_ne!(
        key_xss, key_injection,
        "Different taxonomy domains should produce different keys"
    );
}

#[test]
fn test_stable_key_same_for_same_finding() {
    let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let x = 1;"), None);
    let finding2 = make_finding("2", "src/test.rs", Some(10), Some("let x = 1;"), None);

    let key1 = run_store::stable_finding_key(&finding1);
    let key2 = run_store::stable_finding_key(&finding2);

    assert_eq!(key1, key2, "Same finding should produce same key");
}
