//! Threat generation and verification edge-case tests.
//!
//! Targets:
//! - src/threat_model/generation.rs (generation from minimal findings, empty findings, missing optional fields)
//! - src/scanner/phases/other_phases/threat_modeling.rs (no-LLM-config static template path)
//! - src/scanner/phases/llm_phases/verification.rs (parse_verification_verdict edge shapes)

use baco::analysis_context::AnalysisContext;
use baco::findings::VerificationStatus;
use baco::scanner::phases::llm_phases::parse_verification_verdict;
use baco::threat_model::generation::generate_threat_model_static;
use baco::threat_model::ThreatModelingPhase;
use tempfile::tempdir;

// ============================================================================
// THREAT MODEL GENERATION TESTS (generation.rs)
// ============================================================================

/// Test generation from minimal finding set produces expected structure
#[test]
fn test_threat_model_minimal_architecture_produces_expected_structure() {
    let architecture = "Basic application";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
    assert!(threat_model.contains("### 1. TRUST BOUNDARIES"));
    assert!(threat_model.contains("### 2. DATA FLOWS"));
    assert!(threat_model.contains("### 3. ATTACK SURFACES"));
    assert!(threat_model.contains("### 4. STRIDE THREATS"));
    assert!(threat_model.contains("#### S - Spoofing"));
    assert!(threat_model.contains("#### T - Tampering"));
    assert!(threat_model.contains("#### R - Repudiation"));
    assert!(threat_model.contains("#### I - Information Disclosure"));
    assert!(threat_model.contains("#### D - Denial of Service"));
    assert!(threat_model.contains("#### E - Elevation of Privilege"));
}

/// Test empty architecture string still produces valid threat model
#[test]
fn test_threat_model_empty_architecture_string() {
    let architecture = "";
    let threat_model = generate_threat_model_static(architecture);

    assert!(!threat_model.is_empty());
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("STRIDE"));
    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
}

/// Test architecture with only whitespace produces valid threat model
#[test]
fn test_threat_model_whitespace_only_architecture() {
    let architecture = "   \n\n   \t\t   ";
    let threat_model = generate_threat_model_static(architecture);

    assert!(!threat_model.is_empty());
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("### 4. STRIDE THREATS"));
}

/// Test findings with missing optional fields - database negation variants
#[test]
fn test_threat_model_no_database_negation_variants() {
    let variants = vec![
        "No database",
        "no database",
        "No DB",
        "no db",
        "No Database",
        "NO DATABASE",
    ];

    for architecture in variants {
        let threat_model = generate_threat_model_static(architecture);
        assert!(
            !threat_model.contains("SQL injection"),
            "SQL injection should not appear for: {}",
            architecture
        );
        assert!(
            !threat_model.contains("**Data Store**: Database connection"),
            "Data Store section should not appear for: {}",
            architecture
        );
    }
}

/// Test findings with missing optional fields - filesystem negation variants
#[test]
fn test_threat_model_no_filesystem_negation_variants() {
    let variants = vec![
        "No file system",
        "no file system",
        "No filesystem",
        "no filesystem",
    ];

    for architecture in variants {
        let threat_model = generate_threat_model_static(architecture);
        assert!(
            !threat_model.contains("Path traversal"),
            "Path traversal should not appear for: {}",
            architecture
        );
        assert!(
            !threat_model.contains("**File System**: Local storage"),
            "File System section should not appear for: {}",
            architecture
        );
    }
}

/// Test deterministic output - same architecture produces same threat model
#[test]
fn test_threat_model_deterministic_output() {
    let architecture = "HTTP API with PostgreSQL database and file uploads";

    let tm1 = generate_threat_model_static(architecture);
    let tm2 = generate_threat_model_static(architecture);
    let tm3 = generate_threat_model_static(architecture);

    assert_eq!(tm1, tm2);
    assert_eq!(tm2, tm3);
}

// ============================================================================
// THREAT MODELING PHASE TESTS (threat_modeling.rs)
// ============================================================================

/// Test no-LLM-config path produces static STRIDE template (graceful, no panic)
#[tokio::test]
async fn test_threat_modeling_phase_no_llm_produces_static_template() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext::default();

    // Run with None LLM client - should use static template
    let result = ThreatModelingPhase::run(tmp.path(), &ctx, None).await;

    assert!(result.is_ok(), "Should not panic without LLM client");
    let threat_model = result.unwrap();

    assert!(!threat_model.is_empty());
    assert!(threat_model.contains("STRIDE"));
    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
}

/// Test static template contains all expected STRIDE categories
#[tokio::test]
async fn test_threat_modeling_phase_static_template_contains_stride_categories() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext::default();

    let result = ThreatModelingPhase::run(tmp.path(), &ctx, None)
        .await
        .unwrap();

    assert!(result.contains("#### S - Spoofing"));
    assert!(result.contains("#### T - Tampering"));
    assert!(result.contains("#### R - Repudiation"));
    assert!(result.contains("#### I - Information Disclosure"));
    assert!(result.contains("#### D - Denial of Service"));
    assert!(result.contains("#### E - Elevation of Privilege"));
}

/// Test threat model persists to context after phase run
#[tokio::test]
async fn test_threat_modeling_phase_persists_to_context() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext::default();

    let _ = ThreatModelingPhase::run(tmp.path(), &ctx, None)
        .await
        .unwrap();

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert!(loaded.threat_model.is_some());
    assert!(loaded.threat_model.unwrap().contains("STRIDE"));
}

// ============================================================================
// VERIFICATION VERDICT PARSE EDGE CASES (verification.rs)
// ============================================================================

/// Test array with multiple elements uses first element
#[test]
fn test_parse_verification_array_multiple_elements_uses_first() {
    let input = r#"[
        {
            "verification_status": "confirmed",
            "verification_notes": "First element notes"
        },
        {
            "verification_status": "false_positive",
            "verification_notes": "Second element notes"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "First element notes");
}

/// Test array element missing verification_status but having triage_verdict
#[test]
fn test_parse_verification_array_triage_verdict_fallback() {
    let input = r#"[
        {
            "triage_verdict": "needs_review",
            "verification_notes": "Using triage_verdict as status"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    // triage_verdict is not a valid VerificationStatus, so defaults to NeedsReview
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Using triage_verdict as status");
}

/// Test object missing both statuses defaults to degraded
#[test]
fn test_parse_verification_object_missing_both_statuses_degraded() {
    let input = r#"{
        "some_other_field": "value"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, input); // Falls back to raw content
}

/// Test notes containing embedded braces/JSON survive verbatim on salvage success
#[test]
fn test_parse_verification_notes_with_embedded_json_survive() {
    // Strict parse fails (top-level is array, not object), salvage path extracts notes
    let input = r#"[
        {
            "verification_status": "confirmed",
            "verification_notes": "Analysis shows {attack: injection, impact: critical} pattern detected"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    // Notes should contain the JSON-like text verbatim
    assert!(
        notes.contains("attack"),
        "Notes should contain 'attack': {}",
        notes
    );
    assert!(
        notes.contains("injection"),
        "Notes should contain 'injection': {}",
        notes
    );
    assert!(
        notes.contains("pattern detected"),
        "Notes should contain 'pattern detected': {}",
        notes
    );
}

/// Test empty string input
#[test]
fn test_parse_verification_empty_string_input() {
    let input = "";

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "");
}

/// Test array with empty notes field returns empty string
#[test]
fn test_parse_verification_array_empty_notes_field() {
    let input = r#"[
        {
            "verification_status": "confirmed",
            "verification_notes": ""
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "");
}

/// Test code fence with json marker is properly stripped
#[test]
fn test_parse_verification_code_fence_with_json_marker() {
    let input = r#"```json
{
    "verification_status": "false_positive",
    "verification_notes": "Input is properly sanitized"
}
```"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "Input is properly sanitized");
}

/// Test array salvage with only triage_verdict (no verification_status)
#[test]
fn test_parse_verification_array_only_triage_verdict_no_status() {
    let input = r#"[
        {
            "triage_verdict": "kill",
            "verification_notes": "Finding should be killed"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    // triage_verdict value "kill" is not a valid VerificationStatus
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Finding should be killed");
}
