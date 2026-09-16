//! Threat model file persistence tests.

use baco::analysis_context::AnalysisContext;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::threat_model::model::{ThreatModelFile, ThreatModelFrontmatter};
use tempfile::tempdir;

fn mock_context() -> AnalysisContext {
    AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Test architecture".to_string(),
        threat_model: Some("Mock threat model content".to_string()),
        invariants: vec!["test invariant".to_string()],
        findings_so_far: Vec::new(),
    }
}

fn mock_findings() -> Vec<VulnerabilityFinding> {
    vec![
        VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "SQLi in user input".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/db.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("query(user_input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use parameterized queries".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
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
        },
        VulnerabilityFinding {
            id: "test-2".to_string(),
            title: "XSS in Header".to_string(),
            description: "Cross-site scripting".to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/handler.rs".to_string(),
            line_number: Some(100),
            code_snippet: Some("header.write(unsafe)".to_string()),
            diff_hunk: None,
            recommendation: Some("Escape output".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
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
        },
    ]
}

#[test]
fn test_generate_threat_model() {
    let ctx = mock_context();
    let findings = mock_findings();

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.version, "1.0");
    assert_eq!(tm.frontmatter.project_type, "web");
    assert_eq!(tm.frontmatter.total_threats, 2);
    assert!(tm
        .frontmatter
        .high_risk_areas
        .contains(&"src/db.rs".to_string()));
    assert!(tm
        .frontmatter
        .high_risk_areas
        .contains(&"src/handler.rs".to_string()));
    assert!(tm.body.contains("SQL Injection"));
    assert!(tm.body.contains("XSS in Header"));
}

#[test]
fn test_save_load_roundtrip() {
    let tmp = tempdir().unwrap();
    let ctx = mock_context();
    let findings = mock_findings();

    let original = ThreatModelFile::generate(&ctx, &findings);
    original.save(tmp.path()).unwrap();

    let loaded = ThreatModelFile::load(tmp.path()).unwrap();

    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.frontmatter.version, original.frontmatter.version);
    assert_eq!(
        loaded.frontmatter.project_type,
        original.frontmatter.project_type
    );
    assert_eq!(
        loaded.frontmatter.total_threats,
        original.frontmatter.total_threats
    );
    assert_eq!(loaded.body.trim(), original.body.trim());
}

#[test]
fn test_load_nonexistent() {
    let tmp = tempdir().unwrap();
    let loaded = ThreatModelFile::load(tmp.path()).unwrap();
    assert!(loaded.is_none());
}

#[test]
fn test_corrupted_file_handling() {
    let tmp = tempdir().unwrap();
    let baco_dir = tmp.path().join(".baco");
    std::fs::create_dir_all(&baco_dir).unwrap();

    // Write corrupted content
    let corrupt_path = baco_dir.join("threat_model.md");
    std::fs::write(&corrupt_path, "---invalid yaml!!\n---\n\nNot valid").unwrap();

    // Should return None, not panic
    let result = ThreatModelFile::load(tmp.path()).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_merge_with_existing() {
    let ctx = mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &mock_findings()[0..1]);
    existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

    let mut new = ThreatModelFile::generate(&ctx, &mock_findings()[1..2]);
    new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    // Should have combined high risk areas
    assert!(merged
        .frontmatter
        .high_risk_areas
        .contains(&"src/db.rs".to_string()));
    assert!(merged
        .frontmatter
        .high_risk_areas
        .contains(&"src/handler.rs".to_string()));

    // Should have newer timestamp
    assert!(merged.frontmatter.generated_at.contains("2024-01-02"));

    // Should reference both scans
    assert!(merged.body.contains("Previous scan"));
}

#[test]
fn test_default_frontmatter() {
    let fm = ThreatModelFrontmatter::default();

    assert_eq!(fm.version, "1.0");
    assert_eq!(fm.project_type, "unknown");
    assert_eq!(fm.total_threats, 0);
    assert!(fm.high_risk_areas.is_empty());
}

#[test]
fn test_parse_valid_content() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 5
high_risk_areas:
  - src/auth.rs
  - src/admin.rs
---

# Threat Model

This is the body content.
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert_eq!(tm.frontmatter.version, "1.0");
    assert_eq!(tm.frontmatter.total_threats, 5);
    assert_eq!(tm.body, "# Threat Model\n\nThis is the body content.");
}

#[test]
fn test_parse_missing_frontmatter() {
    let content = "# Just markdown\nNo frontmatter";

    let result = ThreatModelFile::parse(content);
    assert!(result.is_err());
}

#[test]
fn test_parse_empty_content() {
    let result = ThreatModelFile::parse("");
    assert!(result.is_err());
}

#[test]
fn test_parse_with_empty_body() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas: []
---

"#;

    let tm = ThreatModelFile::parse(content).unwrap();
    assert_eq!(tm.frontmatter.total_threats, 0);
    assert!(tm.body.is_empty());
}

#[test]
fn test_generate_markdown_empty_findings() {
    let ctx = mock_context();
    let findings: Vec<VulnerabilityFinding> = vec![];

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(tm.body.contains("Findings Summary"));
    assert!(tm.body.contains("Total findings: 0"));
    assert!(tm.body.contains("Recommendations"));
}

#[test]
fn test_baco_dir_path() {
    let tmp_dir = tempdir().unwrap();
    let baco = ThreatModelFile::baco_dir(tmp_dir.path()).unwrap();
    assert!(baco.ends_with(".baco"));
}

#[test]
fn test_threat_model_path() {
    let tmp_dir = tempdir().unwrap();
    let tm_path = ThreatModelFile::threat_model_path(tmp_dir.path()).unwrap();
    assert!(tm_path.ends_with(".baco/threat_model.md"));
}
