//! Coverage tests for pure functions in LLM phase modules
//!
//! Tests for:
//! - verification.rs: build_stable_verification_prefix, build_volatile_verification_tail,
//!   parse_batch_verification_verdict, parse_verification_verdict
//! - discovery.rs: build_stable_discovery_prefix, build_volatile_discovery_tail,
//!   merge_agent_severity, partition_for_discovery
//! - static_analysis.rs: should_analyze_file

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::{
    build_stable_discovery_prefix, build_stable_verification_prefix, build_volatile_discovery_tail,
    build_volatile_verification_tail, merge_agent_severity, parse_batch_verification_verdict,
    parse_verification_verdict, partition_for_discovery, should_analyze_file,
};
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Test fixtures
// ============================================================================

fn make_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: None,
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
        evidence: vec![],
        verification_tier: None,
    }
}

fn make_finding_with_evidence(
    id: &str,
    title: &str,
    file_path: &str,
    has_llm_evidence: bool,
) -> VulnerabilityFinding {
    use baco::evidence::{Evidence, EvidenceSource};
    use chrono::Utc;

    let mut finding = make_finding(id, title, file_path, Some(42), Severity::Medium);
    if has_llm_evidence {
        finding.evidence.push(Evidence {
            source: EvidenceSource::LlmAnalysis("discovery".to_string()),
            weight: 0.8,
            detail: "LLM analysis evidence".to_string(),
            timestamp: Utc::now(),
        });
    }
    finding
}

// ============================================================================
// build_stable_verification_prefix tests
// ============================================================================

#[test]
fn test_build_stable_verification_prefix_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let required_primitives: HashMap<String, Vec<String>> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);

    assert!(prefix.contains("You are a security vulnerability verifier"));
    assert!(prefix.contains("7-Question Gate Triage"));
    assert!(!prefix.is_empty());
}

#[test]
fn test_build_stable_verification_prefix_with_hunt_prompts() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let mut hunt_prompts: HashMap<String, String> = HashMap::new();
    hunt_prompts.insert("xss".to_string(), "XSS hunt guidance".to_string());

    let required_primitives: HashMap<String, Vec<String>> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);

    assert!(prefix.contains("HUNT DOMAIN GUIDANCE"));
    assert!(prefix.contains("XSS hunt guidance"));
}

#[test]
fn test_build_stable_verification_prefix_with_primitives() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let mut required_primitives: HashMap<String, Vec<String>> = HashMap::new();
    required_primitives.insert(
        "php".to_string(),
        vec!["mysqli_prepare".to_string(), "escapeshellarg".to_string()],
    );

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);

    assert!(prefix.contains("Required Security Primitives"));
    assert!(prefix.contains("php"));
    assert!(prefix.contains("mysqli_prepare"));
}

#[test]
fn test_build_stable_verification_prefix_multiple_languages() {
    let findings = vec![
        make_finding("1", "Test1", "src/test.php", Some(10), Severity::High),
        make_finding("2", "Test2", "src/test.py", Some(20), Severity::Medium),
    ];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let mut required_primitives: HashMap<String, Vec<String>> = HashMap::new();
    required_primitives.insert("php".to_string(), vec!["mysqli_prepare".to_string()]);
    required_primitives.insert("python".to_string(), vec!["escape".to_string()]);

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);

    // Only php is shown because finding has .py extension but required_primitives key is "python"
    // The filter at line 133 requires exact match between finding language and required_primitives key
    assert!(prefix.contains("language: php"));
    // "python" key doesn't match "py" finding language, so python primitives are not shown
    assert!(!prefix.contains("language: python"));
}

#[test]
fn test_build_stable_verification_prefix_byte_stable() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let required_primitives: HashMap<String, Vec<String>> = HashMap::new();

    let prefix1 = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);
    let prefix2 = build_stable_verification_prefix(&findings, &hunt_prompts, &required_primitives);

    assert_eq!(prefix1, prefix2);
}

// ============================================================================
// build_volatile_verification_tail tests
// ============================================================================

#[test]
fn test_build_volatile_verification_tail_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    assert!(tail.contains("Return JSON array now"));
    assert!(!tail.contains("Finding #"));
}

#[test]
fn test_build_volatile_verification_tail_single_finding() {
    let findings = vec![make_finding(
        "1",
        "SQL Injection",
        "src/db.php",
        Some(42),
        Severity::Critical,
    )];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    assert!(tail.contains("Finding #0"));
    assert!(tail.contains("SQL Injection"));
    assert!(tail.contains("src/db.php"));
    assert!(tail.contains("42"));
}

#[test]
fn test_build_volatile_verification_tail_with_code_snippet() {
    let mut finding = make_finding("1", "XSS", "src/view.php", Some(10), Severity::High);
    finding.code_snippet = Some("<%= user_input %>".to_string());

    let findings = vec![finding];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    assert!(tail.contains("Vulnerable code:"));
    assert!(tail.contains("<%= user_input %>"));
}

#[test]
fn test_build_volatile_verification_tail_multiple_findings() {
    let findings = vec![
        make_finding("1", "XSS", "src/view.php", Some(10), Severity::High),
        make_finding("2", "SQLi", "src/db.php", Some(20), Severity::Critical),
        make_finding("3", "RCE", "src/exec.php", Some(30), Severity::Critical),
    ];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    assert!(tail.contains("Finding #0"));
    assert!(tail.contains("Finding #1"));
    assert!(tail.contains("Finding #2"));
    assert!(tail.contains("---"));
}

#[test]
fn test_build_volatile_verification_tail_with_surrounding_context() {
    let tmp_dir = TempDir::new().unwrap();
    let test_file = tmp_dir.path().join("test.php");
    let content = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10";
    fs::write(&test_file, content).unwrap();

    let finding = make_finding(
        "1",
        "Test",
        test_file.to_str().unwrap(),
        Some(7),
        Severity::Medium,
    );
    let findings = vec![finding];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    assert!(tail.contains("Code context"));
    assert!(tail.contains("line 2"));
    assert!(tail.contains("line 10"));
}

// ============================================================================
// parse_batch_verification_verdict tests
// ============================================================================

#[test]
fn test_parse_batch_verification_verdict_valid_json_array() {
    let json = r#"[
        {"index": 0, "verification_status": "confirmed", "verification_notes": "Confirmed XSS"},
        {"index": 1, "verification_status": "false_positive", "verification_notes": "Sanitized input"},
        {"index": 2, "verification_status": "needs_review", "verification_notes": "Unclear context"}
    ]"#;

    let results = parse_batch_verification_verdict(json, 3);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[0].1, "Confirmed XSS");
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_batch_verification_verdict_malformed_json() {
    let json = r#"{"invalid json"#;

    let results = parse_batch_verification_verdict(json, 2);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, VerificationStatus::NeedsReview);
    assert!(results[0].1.contains("{"));
}

#[test]
fn test_parse_batch_verification_verdict_wrong_count() {
    let json = r#"[
        {"index": 0, "verification_status": "confirmed", "verification_notes": "First"}
    ]"#;

    let results = parse_batch_verification_verdict(json, 3);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::NeedsReview);
    assert!(results[1].1.contains("missing this item"));
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_batch_verification_verdict_empty_string() {
    let results = parse_batch_verification_verdict("", 2);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_batch_verification_verdict_partial_json() {
    let json = r#"[
        {"index": 0, "verification_status": "confirmed"
    ]"#;

    let results = parse_batch_verification_verdict(json, 2);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_batch_verification_verdict_with_extra_whitespace() {
    let json = r#"
        ```json
        [
            {"index": 0, "verification_status": "confirmed", "verification_notes": "Test"}
        ]
        ```
    "#;

    let results = parse_batch_verification_verdict(json, 1);

    assert_eq!(results.len(), 1);
    // Code fence with whitespace causes parse failure, defaults to NeedsReview
    assert_eq!(results[0].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_batch_verification_verdict_positional_fallback() {
    let json = r#"[
        {"verification_status": "confirmed", "verification_notes": "First"},
        {"verification_status": "false_positive", "verification_notes": "Second"}
    ]"#;

    let results = parse_batch_verification_verdict(json, 2);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
}

#[test]
fn test_parse_batch_verification_verdict_missing_index_fields() {
    let json = r#"[
        {"verification_status": "confirmed", "verification_notes": "No index"}
    ]"#;

    let results = parse_batch_verification_verdict(json, 1);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
}

// ============================================================================
// parse_verification_verdict tests
// ============================================================================

#[test]
fn test_parse_verification_verdict_confirmed() {
    let json = r#"{
        "verification_status": "confirmed",
        "verification_notes": "This is a real vulnerability"
    }"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "This is a real vulnerability");
}

#[test]
fn test_parse_verification_verdict_false_positive() {
    let json = r#"{
        "verification_status": "false_positive",
        "verification_notes": "Input is sanitized"
    }"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "Input is sanitized");
}

#[test]
fn test_parse_verification_verdict_needs_review() {
    let json = r#"{
        "verification_status": "needs_review",
        "verification_notes": "Need more context"
    }"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Need more context");
}

#[test]
fn test_parse_verification_verdict_malformed() {
    let json = r#"not valid json"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::NeedsReview);
    assert!(notes.contains("not valid json"));
}

#[test]
fn test_parse_verification_verdict_empty() {
    let (status, _notes) = parse_verification_verdict("");

    assert_eq!(status, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_verification_verdict_with_code_fence() {
    let json = r#"```json
{
    "verification_status": "confirmed",
    "verification_notes": "Confirmed"
}
```"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "Confirmed");
}

#[test]
fn test_parse_verification_verdict_unknown_status_defaults_to_needs_review() {
    let json = r#"{
        "verification_status": "unknown_status",
        "verification_notes": "Unknown"
    }"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Unknown");
}

#[test]
fn test_parse_verification_verdict_salvage_from_array() {
    let json = r#"[
        {
            "verification_status": "confirmed",
            "verification_notes": "Salvaged from array"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "Salvaged from array");
}

#[test]
fn test_parse_verification_verdict_empty_array() {
    let json = "[]";

    let (status, _notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::NeedsReview);
}

#[test]
fn test_parse_verification_verdict_extra_whitespace() {
    let json = r#"
        
        {
            "verification_status": "false_positive",
            "verification_notes": "Test"
        }
        
    "#;

    let (status, notes) = parse_verification_verdict(json);

    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "Test");
}

// ============================================================================
// build_stable_discovery_prefix tests
// ============================================================================

#[test]
fn test_build_stable_discovery_prefix_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(prefix.contains("You are a security vulnerability analyzer"));
    assert!(prefix.contains("Output valid JSON only"));
}

#[test]
fn test_build_stable_discovery_prefix_with_hunt_prompts() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let mut hunt_prompts: HashMap<String, String> = HashMap::new();
    hunt_prompts.insert("discovery".to_string(), "Discovery guidance".to_string());

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(prefix.contains("HUNT MODULE"));
    assert!(prefix.contains("Discovery guidance"));
}

#[test]
fn test_build_stable_discovery_prefix_multiple_hunt_domains() {
    let findings = vec![
        make_finding("1", "Test1", "src/test.php", Some(10), Severity::High),
        make_finding("2", "Test2", "src/test.py", Some(20), Severity::Medium),
    ];
    let mut hunt_prompts: HashMap<String, String> = HashMap::new();
    hunt_prompts.insert("domain1".to_string(), "Guidance 1".to_string());
    hunt_prompts.insert("domain2".to_string(), "Guidance 2".to_string());

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(prefix.contains("domain1"));
    assert!(prefix.contains("domain2"));
}

#[test]
fn test_build_stable_discovery_prefix_empty_hunt_prompt_ignored() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let mut hunt_prompts: HashMap<String, String> = HashMap::new();
    hunt_prompts.insert("empty".to_string(), "".to_string());

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(!prefix.contains("HUNT MODULE: empty"));
}

#[test]
fn test_build_stable_discovery_prefix_byte_stable() {
    let findings = vec![make_finding(
        "1",
        "Test",
        "src/test.php",
        Some(10),
        Severity::High,
    )];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix1 = build_stable_discovery_prefix(&findings, &hunt_prompts);
    let prefix2 = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert_eq!(prefix1, prefix2);
}

// ============================================================================
// build_volatile_discovery_tail tests
// ============================================================================

#[test]
fn test_build_volatile_discovery_tail_basic() {
    let finding = make_finding(
        "1",
        "SQL Injection",
        "src/db.php",
        Some(42),
        Severity::Critical,
    );

    let tail = build_volatile_discovery_tail(&finding);

    assert!(tail.contains("Vulnerability: SQL Injection"));
    assert!(tail.contains("Location: src/db.php:42"));
    assert!(tail.contains("Current description: Test finding"));
    assert!(tail.contains("Respond with ONLY JSON"));
}

#[test]
fn test_build_volatile_discovery_tail_missing_line_number() {
    let finding = make_finding("1", "Test", "src/test.php", None, Severity::Medium);

    let tail = build_volatile_discovery_tail(&finding);

    assert!(tail.contains("Location: src/test.php:0"));
}

#[test]
fn test_build_volatile_discovery_tail_json_format() {
    let finding = make_finding("1", "Test", "src/test.php", Some(10), Severity::High);

    let tail = build_volatile_discovery_tail(&finding);

    assert!(tail.contains("\"description\":"));
    assert!(tail.contains("\"fix_code\":"));
}

#[test]
fn test_build_volatile_discovery_tail_custom_description() {
    let mut finding = make_finding("1", "XSS", "src/view.php", Some(15), Severity::High);
    finding.description = "Cross-site scripting vulnerability".to_string();

    let tail = build_volatile_discovery_tail(&finding);

    assert!(tail.contains("Cross-site scripting vulnerability"));
}

#[test]
fn test_build_volatile_discovery_tail_single_line() {
    let finding = make_finding("1", "A", "src/a.php", Some(1), Severity::Low);

    let tail = build_volatile_discovery_tail(&finding);

    assert!(tail.contains("Vulnerability: A"));
    assert!(tail.contains("Location: src/a.php:1"));
}

// ============================================================================
// merge_agent_severity tests
// ============================================================================

#[test]
fn test_merge_agent_severity_agent_higher() {
    let result = merge_agent_severity(Severity::Medium, Severity::High, "Test");

    assert_eq!(result, Severity::High);
}

#[test]
fn test_merge_agent_severity_agent_lower() {
    let result = merge_agent_severity(Severity::High, Severity::Medium, "Test");

    assert_eq!(result, Severity::High);
}

#[test]
fn test_merge_agent_severity_agent_equal() {
    let result = merge_agent_severity(Severity::Critical, Severity::Critical, "Test");

    assert_eq!(result, Severity::Critical);
}

#[test]
fn test_merge_agent_severity_all_combinations() {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for current in &severities {
        for suggested in &severities {
            let result = merge_agent_severity(*current, *suggested, "Test");
            if *suggested > *current {
                assert_eq!(
                    result, *suggested,
                    "current={:?}, suggested={:?}",
                    current, suggested
                );
            } else {
                assert_eq!(
                    result, *current,
                    "current={:?}, suggested={:?}",
                    current, suggested
                );
            }
        }
    }
}

#[test]
fn test_merge_agent_severity_title_with_severity_keyword() {
    let result = merge_agent_severity(Severity::Medium, Severity::High, "Critical XSS issue");

    assert_eq!(result, Severity::High);
}

#[test]
fn test_merge_agent_severity_info_to_low() {
    let result = merge_agent_severity(Severity::Info, Severity::Low, "Test");

    assert_eq!(result, Severity::Low);
}

#[test]
fn test_merge_agent_severity_low_to_info() {
    let result = merge_agent_severity(Severity::Low, Severity::Info, "Test");

    assert_eq!(result, Severity::Low);
}

// ============================================================================
// partition_for_discovery tests
// ============================================================================

#[test]
fn test_partition_for_discovery_empty() {
    let findings: Vec<VulnerabilityFinding> = vec![];

    let (high, low) = partition_for_discovery(findings);

    assert!(high.is_empty());
    assert!(low.is_empty());
}

#[test]
fn test_partition_for_discovery_all_high_priority() {
    let findings = vec![
        make_finding_with_evidence("1", "Test1", "src/1.php", false),
        make_finding_with_evidence("2", "Test2", "src/2.php", false),
    ];

    let (high, low) = partition_for_discovery(findings);

    assert_eq!(high.len(), 2);
    assert!(low.is_empty());
}

#[test]
fn test_partition_for_discovery_all_low_priority() {
    let findings = vec![
        make_finding_with_evidence("1", "Test1", "src/1.php", true),
        make_finding_with_evidence("2", "Test2", "src/2.php", true),
    ];

    let (high, low) = partition_for_discovery(findings);

    assert!(high.is_empty());
    assert_eq!(low.len(), 2);
}

#[test]
fn test_partition_for_discovery_mixed() {
    let findings = vec![
        make_finding_with_evidence("1", "Test1", "src/1.php", false),
        make_finding_with_evidence("2", "Test2", "src/2.php", true),
        make_finding_with_evidence("3", "Test3", "src/3.php", false),
    ];

    let (high, low) = partition_for_discovery(findings);

    assert_eq!(high.len(), 2);
    assert_eq!(low.len(), 1);
    assert_eq!(high[0].id, "1");
    assert_eq!(high[1].id, "3");
    assert_eq!(low[0].id, "2");
}

#[test]
fn test_partition_for_discovery_single_item_high() {
    let findings = vec![make_finding_with_evidence(
        "1",
        "Test",
        "src/test.php",
        false,
    )];

    let (high, low) = partition_for_discovery(findings);

    assert_eq!(high.len(), 1);
    assert!(low.is_empty());
}

#[test]
fn test_partition_for_discovery_single_item_low() {
    let findings = vec![make_finding_with_evidence(
        "1",
        "Test",
        "src/test.php",
        true,
    )];

    let (high, low) = partition_for_discovery(findings);

    assert!(high.is_empty());
    assert_eq!(low.len(), 1);
}

// ============================================================================
// should_analyze_file tests
// ============================================================================

#[test]
fn test_should_analyze_file_above_threshold() {
    let result = should_analyze_file(0.8, 0.5);

    assert!(result);
}

#[test]
fn test_should_analyze_file_below_threshold() {
    let result = should_analyze_file(0.3, 0.5);

    assert!(!result);
}

#[test]
fn test_should_analyze_file_equal_to_threshold() {
    let result = should_analyze_file(0.5, 0.5);

    assert!(result);
}

#[test]
fn test_should_analyze_file_zero_suspicion() {
    let result = should_analyze_file(0.0, 0.5);

    assert!(!result);
}

#[test]
fn test_should_analyze_file_one_suspicion() {
    let result = should_analyze_file(1.0, 0.5);

    assert!(result);
}

#[test]
fn test_should_analyze_file_just_above_threshold() {
    let result = should_analyze_file(0.5001, 0.5);

    assert!(result);
}

#[test]
fn test_should_analyze_file_just_below_threshold() {
    let result = should_analyze_file(0.4999, 0.5);

    assert!(!result);
}

#[test]
fn test_should_analyze_file_zero_threshold() {
    let result = should_analyze_file(0.1, 0.0);

    assert!(result);
}

#[test]
fn test_should_analyze_file_one_threshold() {
    let result = should_analyze_file(0.5, 1.0);

    assert!(!result);
}

#[test]
fn test_should_analyze_file_boundary_precision() {
    // Test with f32 precision boundaries
    let result1 = should_analyze_file(0.7000001, 0.7);
    let result2 = should_analyze_file(0.6999999, 0.7);

    assert!(result1);
    assert!(!result2);
}
#[test]
fn extract_language_from_path_edges() {
    use baco::scanner::phases::llm_phases::verification::extract_language_from_path;
    assert_eq!(extract_language_from_path("x.phtml"), "php");
    assert_eq!(extract_language_from_path("a.RS"), "rs");
    assert_eq!(extract_language_from_path("Makefile"), "");
}

#[test]
fn volatile_tail_early_line_reads_from_file_start() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("s.rs");
    let body = (1..=10)
        .map(|i| format!("let x{i} = {i};"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, body).unwrap();
    let finding = make_finding("1", "Test", path.to_str().unwrap(), Some(3), Severity::Low);
    let tail = build_volatile_verification_tail(&[finding], &std::collections::HashMap::new());
    assert!(tail.contains("Code context"));
    assert!(tail.contains("1:"));
}

#[test]
fn parse_batch_mixed_index_positional_and_skipped() {
    use baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict;
    let content = r#"[{"index": 1, "verification_status": "confirmed", "verification_notes": "b"}, {"verification_status": "false_positive", "verification_notes": "fp"}, {"index": 9, "verification_status": "confirmed", "verification_notes": "oob"}, {"verification_status": "", "verification_notes": ""}]"#;
    let results = parse_batch_verification_verdict(content, 4);
    assert_eq!(results.len(), 4);
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[1].1, "fp");
    assert_eq!(results[3].0, VerificationStatus::NeedsReview);
    assert!(results[3].1.contains("missing"));
}
