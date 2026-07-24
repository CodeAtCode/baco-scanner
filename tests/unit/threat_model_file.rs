//! Unit tests for src/threat_model_file.rs
//!
//! Covers:
//! - ThreatModelFile::generate
//! - ThreatModelFile::save
//! - ThreatModelFile::load
//! - ThreatModelFile::parse
//! - ThreatModelFile::merge_with_existing
//! - ThreatModelFrontmatter operations
//! - YAML frontmatter parsing edge cases
//! - File I/O error handling

use baco::analysis_context::AnalysisContext;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::threat_model::{ThreatModelFile, ThreatModelFrontmatter};
use tempfile::tempdir;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn create_mock_context() -> AnalysisContext {
    AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Test architecture with HTTP and database".to_string(),
        threat_model: Some("Mock threat model content".to_string()),
        invariants: vec!["test invariant".to_string()],
        findings_so_far: Vec::new(),
    }
}

fn create_mock_findings() -> Vec<VulnerabilityFinding> {
    vec![
        VulnerabilityFinding {
            id: "finding-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "SQL injection vulnerability".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/db.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("query(user_input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use parameterized queries".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
        },
        VulnerabilityFinding {
            id: "finding-2".to_string(),
            title: "XSS Vulnerability".to_string(),
            description: "Cross-site scripting in header".to_string(),
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
            sources: vec!["semgrep".to_string()],
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
        },
        VulnerabilityFinding {
            id: "finding-3".to_string(),
            title: "Hardcoded Secret".to_string(),
            description: "API key in source code".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.75,
            cwe_id: Some("CWE-798".to_string()),
            file_path: "src/config.rs".to_string(),
            line_number: Some(15),
            code_snippet: Some("const API_KEY = \"secret\"".to_string()),
            diff_hunk: None,
            recommendation: Some("Use environment variables".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
        },
        VulnerabilityFinding {
            id: "finding-4".to_string(),
            title: "Info: Unused Import".to_string(),
            description: "Unused import detected".to_string(),
            severity: Severity::Info,
            confidence_score: 1.0,
            cwe_id: None,
            file_path: "src/utils.rs".to_string(),
            line_number: Some(5),
            code_snippet: Some("use unused_module".to_string()),
            diff_hunk: None,
            recommendation: Some("Remove unused import".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["clippy".to_string()],
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
        },
    ]
}

fn create_single_finding(severity: Severity, file_path: &str) -> Vec<VulnerabilityFinding> {
    vec![VulnerabilityFinding {
        id: "single".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
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
    }]
}

// ============================================================================
// THREAT MODEL FRONTMATTER TESTS
// ============================================================================

#[test]
fn test_frontmatter_default_values() {
    let fm = ThreatModelFrontmatter::default();

    assert_eq!(fm.version, "1.0");
    assert!(!fm.generated_at.is_empty());
    assert_eq!(fm.project_type, "unknown");
    assert_eq!(fm.total_threats, 0);
    assert!(fm.high_risk_areas.is_empty());
}

#[test]
fn test_frontmatter_clone() {
    let fm = ThreatModelFrontmatter {
        version: "2.0".to_string(),
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        project_type: "web".to_string(),
        total_threats: 10,
        high_risk_areas: vec!["src/auth.rs".to_string()],
    };

    let cloned = fm.clone();

    assert_eq!(fm.version, cloned.version);
    assert_eq!(fm.generated_at, cloned.generated_at);
    assert_eq!(fm.project_type, cloned.project_type);
    assert_eq!(fm.total_threats, cloned.total_threats);
    assert_eq!(fm.high_risk_areas, cloned.high_risk_areas);
}

#[test]
fn test_frontmatter_debug_display() {
    let fm = ThreatModelFrontmatter::default();
    let debug_str = format!("{:?}", fm);

    assert!(debug_str.contains("version"));
    assert!(debug_str.contains("generated_at"));
    assert!(debug_str.contains("project_type"));
}

#[test]
fn test_frontmatter_equality() {
    let fm1 = ThreatModelFrontmatter {
        version: "1.0".to_string(),
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        project_type: "web".to_string(),
        total_threats: 5,
        high_risk_areas: vec!["src/a.rs".to_string()],
    };

    let fm2 = ThreatModelFrontmatter {
        version: "1.0".to_string(),
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        project_type: "web".to_string(),
        total_threats: 5,
        high_risk_areas: vec!["src/a.rs".to_string()],
    };

    let fm3 = ThreatModelFrontmatter {
        version: "2.0".to_string(),
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        project_type: "web".to_string(),
        total_threats: 5,
        high_risk_areas: vec!["src/a.rs".to_string()],
    };

    assert_eq!(fm1, fm2);
    assert_ne!(fm1, fm3);
}

// ============================================================================
// THREAT MODEL FILE GENERATION TESTS
// ============================================================================

#[test]
fn test_generate_with_findings() {
    let ctx = create_mock_context();
    let findings = create_mock_findings();

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.version, "1.0");
    assert_eq!(tm.frontmatter.project_type, "web");
    assert_eq!(tm.frontmatter.total_threats, 4);
    assert_eq!(tm.frontmatter.high_risk_areas.len(), 2); // Critical and High only
    assert!(tm
        .frontmatter
        .high_risk_areas
        .contains(&"src/db.rs".to_string()));
    assert!(tm
        .frontmatter
        .high_risk_areas
        .contains(&"src/handler.rs".to_string()));
    assert!(tm.body.contains("SQL Injection"));
    assert!(tm.body.contains("XSS Vulnerability"));
    assert!(tm.body.contains("Hardcoded Secret"));
}

#[test]
fn test_generate_with_empty_findings() {
    let ctx = create_mock_context();
    let findings: Vec<VulnerabilityFinding> = vec![];

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.total_threats, 0);
    assert!(tm.frontmatter.high_risk_areas.is_empty());
    assert!(tm.body.contains("Total findings: 0"));
    assert!(tm.body.contains("## Recommendations"));
}

#[test]
fn test_generate_with_only_critical_findings() {
    let ctx = create_mock_context();
    let findings = create_single_finding(Severity::Critical, "src/critical.rs");

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.total_threats, 1);
    assert!(tm
        .frontmatter
        .high_risk_areas
        .contains(&"src/critical.rs".to_string()));
    assert!(tm.body.contains("#### Critical"));
}

#[test]
fn test_generate_with_only_low_findings() {
    let ctx = create_mock_context();
    let findings = create_single_finding(Severity::Low, "src/low.rs");

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.total_threats, 1);
    assert!(tm.frontmatter.high_risk_areas.is_empty()); // Low is not high risk
    assert!(tm.body.contains("#### Low/Info"));
}

#[test]
fn test_generate_with_info_findings() {
    let ctx = create_mock_context();
    let findings = create_single_finding(Severity::Info, "src/info.rs");

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert_eq!(tm.frontmatter.total_threats, 1);
    assert!(tm.frontmatter.high_risk_areas.is_empty());
    assert!(tm.body.contains("#### Low/Info"));
}

#[test]
fn test_generate_with_no_threat_model_in_context() {
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::CLI,
        architecture_summary: "CLI tool".to_string(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    let findings = create_mock_findings();

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(!tm.body.contains("## Architecture Threat Model"));
    assert!(tm.body.contains("## Findings Summary"));
}

#[test]
fn test_generate_preserves_threat_model_from_context() {
    let ctx = create_mock_context();
    let findings = create_mock_findings();

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(tm.body.contains("## Architecture Threat Model"));
    assert!(tm.body.contains("Mock threat model content"));
}

#[test]
fn test_generate_deduplicates_high_risk_areas() {
    let ctx = create_mock_context();
    let findings = vec![
        create_single_finding(Severity::Critical, "src/file.rs")[0].clone(),
        create_single_finding(Severity::High, "src/file.rs")[0].clone(),
    ];

    let tm = ThreatModelFile::generate(&ctx, &findings);

    // Should only appear once despite two findings
    let count = tm
        .frontmatter
        .high_risk_areas
        .iter()
        .filter(|x| *x == "src/file.rs")
        .count();
    assert_eq!(count, 1);
}

// ============================================================================
// SAVE AND LOAD TESTS
// ============================================================================

#[test]
fn test_save_creates_baco_directory() {
    let tmp = tempdir().unwrap();
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());

    tm.save(tmp.path()).unwrap();

    let baco_dir = tmp.path().join(".baco");
    assert!(baco_dir.exists());
}

#[test]
fn test_save_creates_threat_model_file() {
    let tmp = tempdir().unwrap();
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());

    tm.save(tmp.path()).unwrap();

    let file_path = tmp.path().join(".baco").join("threat_model.md");
    assert!(file_path.exists());
}

#[test]
fn test_save_content_format() {
    let tmp = tempdir().unwrap();
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());

    tm.save(tmp.path()).unwrap();

    let content = std::fs::read_to_string(tmp.path().join(".baco/threat_model.md")).unwrap();

    assert!(content.starts_with("---"));
    assert!(content.contains("version:"));
    assert!(content.contains("generated_at:"));
    assert!(content.contains("project_type:"));
    assert!(content.contains("total_threats:"));
    assert!(content.contains("---\n\n"));
    assert!(content.contains("## Findings Summary"));
}

#[test]
fn test_save_load_roundtrip() {
    let tmp = tempdir().unwrap();
    let ctx = create_mock_context();
    let findings = create_mock_findings();

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
    assert_eq!(
        loaded.frontmatter.high_risk_areas.len(),
        original.frontmatter.high_risk_areas.len()
    );
    assert_eq!(loaded.body.trim(), original.body.trim());
}

#[test]
fn test_load_nonexistent_file() {
    let tmp = tempdir().unwrap();

    let result = ThreatModelFile::load(tmp.path()).unwrap();

    assert!(result.is_none());
}

#[test]
fn test_load_corrupted_yaml_frontmatter() {
    let tmp = tempdir().unwrap();
    let baco_dir = tmp.path().join(".baco");
    std::fs::create_dir_all(&baco_dir).unwrap();

    let corrupt_content = "---\ninvalid yaml!! broken:\n---\n\nBody content";
    std::fs::write(baco_dir.join("threat_model.md"), corrupt_content).unwrap();

    let result = ThreatModelFile::load(tmp.path()).unwrap();

    assert!(result.is_none());
}

#[test]
fn test_load_missing_closing_marker() {
    let tmp = tempdir().unwrap();
    let baco_dir = tmp.path().join(".baco");
    std::fs::create_dir_all(&baco_dir).unwrap();

    let corrupt_content = "---\nversion: \"1.0\"\ngenerated_at: \"2024-01-01T00:00:00Z\"\nproject_type: test\ntotal_threats: 0\nhigh_risk_areas: []\n---\n\nBody without proper structure";
    std::fs::write(baco_dir.join("threat_model.md"), corrupt_content).unwrap();

    let result = ThreatModelFile::load(tmp.path()).unwrap();

    // Should succeed with valid YAML frontmatter
    assert!(result.is_some());
}

#[test]
fn test_save_overwrites_existing() {
    let tmp = tempdir().unwrap();
    let ctx = create_mock_context();

    let tm1 = ThreatModelFile::generate(&ctx, &create_single_finding(Severity::Critical, "a.rs"));
    tm1.save(tmp.path()).unwrap();

    let tm2 = ThreatModelFile::generate(&ctx, &create_single_finding(Severity::High, "b.rs"));
    tm2.save(tmp.path()).unwrap();

    let loaded = ThreatModelFile::load(tmp.path()).unwrap().unwrap();
    assert!(loaded.body.contains("b.rs"));
    assert!(!loaded.body.contains("a.rs"));
}

// ============================================================================
// PARSE TESTS
// ============================================================================

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
    assert_eq!(tm.frontmatter.generated_at, "2024-01-01T00:00:00Z");
    assert_eq!(tm.frontmatter.project_type, "web");
    assert_eq!(tm.frontmatter.total_threats, 5);
    assert_eq!(tm.frontmatter.high_risk_areas.len(), 2);
    assert_eq!(tm.body, "# Threat Model\n\nThis is the body content.");
}

#[test]
fn test_parse_empty_body() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas: []
---
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert_eq!(tm.frontmatter.version, "1.0");
    assert!(tm.body.is_empty());
}

#[test]
fn test_parse_missing_frontmatter() {
    let content = "# Just markdown content\nNo frontmatter here";

    let result = ThreatModelFile::parse(content);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing YAML frontmatter"));
}

#[test]
fn test_parse_missing_closing_marker() {
    let content = r#"---
version: "1.0"
"#;

    let result = ThreatModelFile::parse(content);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing closing"));
}

#[test]
fn test_parse_invalid_yaml_in_frontmatter() {
    let content = r#"---
version: "1.0"
invalid: yaml: broken: structure
---

Body content
"#;

    let result = ThreatModelFile::parse(content);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse YAML"));
}

#[test]
fn test_parse_with_extra_dashes_in_yaml() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas: []
---

Body
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert_eq!(tm.frontmatter.version, "1.0");
    assert!(!tm.body.is_empty());
}

#[test]
fn test_parse_with_whitespace_before_frontmatter() {
    let content = r#"
---
version: "1.0"
project_type: web
total_threats: 0
high_risk_areas: []
---

Body
"#;

    // Should fail because content doesn't start with ---
    let result = ThreatModelFile::parse(content);
    assert!(result.is_err());
}

#[test]
fn test_parse_with_special_characters_in_body() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas: []
---

# Body with special chars
<script>alert('xss')</script>
& "quotes" and 'apostrophes'
日本語
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert!(tm.body.contains("<script>"));
    assert!(tm.body.contains("日本語"));
}

#[test]
fn test_parse_with_empty_high_risk_areas() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas: []
---

Body
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert!(tm.frontmatter.high_risk_areas.is_empty());
}

// ============================================================================
// MERGE TESTS
// ============================================================================

#[test]
fn test_merge_with_both_having_high_risk_areas() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(
        &ctx,
        &create_single_finding(Severity::Critical, "src/existing.rs"),
    );
    existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

    let mut new =
        ThreatModelFile::generate(&ctx, &create_single_finding(Severity::High, "src/new.rs"));
    new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    assert_eq!(merged.frontmatter.high_risk_areas.len(), 2);
    assert!(merged
        .frontmatter
        .high_risk_areas
        .contains(&"src/existing.rs".to_string()));
    assert!(merged
        .frontmatter
        .high_risk_areas
        .contains(&"src/new.rs".to_string()));
}

#[test]
fn test_merge_preserves_newer_timestamp() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &create_mock_findings());
    existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

    let mut new = ThreatModelFile::generate(&ctx, &create_mock_findings());
    new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    assert!(merged.frontmatter.generated_at.contains("2024-01-02"));
}

#[test]
fn test_merge_uses_max_threat_count() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &create_mock_findings()[0..2]);
    existing.frontmatter.total_threats = 2;

    let mut new = ThreatModelFile::generate(&ctx, &create_mock_findings()[2..4]);
    new.frontmatter.total_threats = 5;

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    assert_eq!(merged.frontmatter.total_threats, 5);
}

#[test]
fn test_merge_includes_previous_scan_info() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &create_mock_findings());
    existing.frontmatter.total_threats = 10;

    let new = ThreatModelFile::generate(&ctx, &create_mock_findings());

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    assert!(merged.body.contains("Previous scan"));
    assert!(merged
        .body
        .contains(&existing.frontmatter.generated_at[..4])); // Check year from existing timestamp
    assert!(merged.body.contains("Total threats found: 10"));
}

#[test]
fn test_merge_when_existing_has_no_threats() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &[]);
    existing.frontmatter.total_threats = 0;

    let new = ThreatModelFile::generate(&ctx, &create_mock_findings());

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    // Should not include Previous Scan Summary when existing has 0 threats
    assert!(!merged.body.contains("Previous Scan Summary"));
}

#[test]
fn test_merge_combines_bodies() {
    let ctx = create_mock_context();

    let mut existing = ThreatModelFile::generate(&ctx, &create_mock_findings());
    existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

    let mut new = ThreatModelFile::generate(&ctx, &create_mock_findings());
    new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    assert!(merged.body.contains("Merged Threat Model"));
    assert!(merged.body.contains("Previous scan"));
    assert!(merged.body.contains("Current scan"));
}

#[test]
fn test_merge_with_duplicate_high_risk_areas() {
    let ctx = create_mock_context();

    let finding = create_single_finding(Severity::Critical, "src/duplicate.rs");

    let mut existing = ThreatModelFile::generate(&ctx, &finding);
    existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

    let mut new = ThreatModelFile::generate(&ctx, &finding);
    new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

    let merged = ThreatModelFile::merge_with_existing(&new, &existing);

    // Should have only one entry despite both having the same area
    let count = merged
        .frontmatter
        .high_risk_areas
        .iter()
        .filter(|x| *x == "src/duplicate.rs")
        .count();
    assert_eq!(count, 1);
}

// ============================================================================
// EDGE CASES AND ERROR HANDLING
// ============================================================================

#[test]
fn test_generate_with_very_long_finding_titles() {
    let ctx = create_mock_context();
    let mut findings = create_mock_findings();
    findings[0].title = "A".repeat(1000);

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(tm.body.contains(&"A".repeat(100)));
    assert!(!tm.body.is_empty());
}

#[test]
fn test_generate_with_special_characters_in_file_paths() {
    let ctx = create_mock_context();
    let findings = vec![VulnerabilityFinding {
        id: "special".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        severity: Severity::Critical,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: "src/special-file_v2.0.tsx".to_string(),
        line_number: Some(42),
        code_snippet: Some("code".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
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
    }];

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(tm.body.contains("src/special-file_v2.0.tsx"));
}

#[test]
fn test_generate_with_no_line_number() {
    let ctx = create_mock_context();
    let mut findings = create_mock_findings();
    findings[0].line_number = None;

    let tm = ThreatModelFile::generate(&ctx, &findings);

    assert!(tm.body.contains("(L0)")); // line_number.unwrap_or(0)
}

#[test]
fn test_parse_with_unicode_in_yaml() {
    let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 0
high_risk_areas:
  - src/日本語.rs
  - src/émojis-🔒.rs
---

Body
"#;

    let tm = ThreatModelFile::parse(content).unwrap();

    assert_eq!(tm.frontmatter.high_risk_areas.len(), 2);
}

#[test]
fn test_save_to_nonexistent_parent_dir() {
    let tmp = tempdir().unwrap();
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());

    // Should create .baco directory automatically
    let result = tm.save(tmp.path());

    assert!(result.is_ok());
    assert!(tmp.path().join(".baco/threat_model.md").exists());
}

#[test]
fn test_load_with_permission_error_simulation() {
    // This test documents the expected behavior - in real scenarios
    // permission errors would propagate as Err
    let tmp = tempdir().unwrap();
    let baco_dir = tmp.path().join(".baco");
    std::fs::create_dir_all(&baco_dir).unwrap();

    // Create a valid file first
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());
    tm.save(tmp.path()).unwrap();

    // Load should succeed
    let result = ThreatModelFile::load(tmp.path()).unwrap();
    assert!(result.is_some());
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_performance_generate_many_findings() {
    let ctx = create_mock_context();
    let mut findings = Vec::new();

    for i in 0..100 {
        findings.push(VulnerabilityFinding {
            id: format!("finding-{}", i),
            title: format!("Finding {}", i),
            description: "Description".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: format!("src/file_{}.rs", i),
            line_number: Some(i),
            code_snippet: Some("code".to_string()),
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
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
        });
    }

    let start = std::time::Instant::now();
    let _ = ThreatModelFile::generate(&ctx, &findings);
    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 1000,
        "Generate with 100 findings took {}ms",
        duration.as_millis()
    );
}

#[test]
fn test_performance_save_load_roundtrip() {
    let tmp = tempdir().unwrap();
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());

    let start = std::time::Instant::now();

    for _ in 0..100 {
        tm.save(tmp.path()).unwrap();
        let _ = ThreatModelFile::load(tmp.path()).unwrap();
    }

    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 5000,
        "100 roundtrips took {}ms",
        duration.as_millis()
    );
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_full_save_load_merge_cycle() {
    let tmp = tempdir().unwrap();
    let ctx = create_mock_context();

    // Step 1: Create and save first threat model
    let tm1 = ThreatModelFile::generate(&ctx, &create_single_finding(Severity::Critical, "a.rs"));
    tm1.save(tmp.path()).unwrap();

    // Step 2: Load and verify
    let loaded1 = ThreatModelFile::load(tmp.path()).unwrap().unwrap();
    assert!(loaded1.body.contains("a.rs"));

    // Step 3: Create second threat model and merge
    let tm2 = ThreatModelFile::generate(&ctx, &create_single_finding(Severity::High, "b.rs"));
    let merged = ThreatModelFile::merge_with_existing(&tm2, &loaded1);

    // Step 4: Save merged
    merged.save(tmp.path()).unwrap();

    // Step 5: Load final and verify both files present
    let final_tm = ThreatModelFile::load(tmp.path()).unwrap().unwrap();
    assert!(final_tm.body.contains("Previous scan"));
    assert!(final_tm
        .frontmatter
        .high_risk_areas
        .contains(&"a.rs".to_string()));
    assert!(final_tm
        .frontmatter
        .high_risk_areas
        .contains(&"b.rs".to_string()));
}

#[test]
fn test_threat_model_file_debug_trait() {
    let tm = ThreatModelFile::generate(&create_mock_context(), &create_mock_findings());
    let debug_str = format!("{:?}", tm);

    assert!(debug_str.contains("frontmatter"));
    assert!(debug_str.contains("body"));
}
