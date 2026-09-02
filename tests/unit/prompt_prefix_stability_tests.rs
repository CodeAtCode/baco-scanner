//! Tests for prompt-prefix caching stability (T20)
//!
//! These tests verify that stable prompt prefixes are byte-identical across
//! different findings/batches, enabling provider-side prompt caching.

use std::collections::HashMap;

#[test]
fn test_verification_stable_prefix_identical() {
    // Test that verification prompts share identical stable prefix across different findings
    use baco::scanner::phases::llm_phases::verification::build_stable_verification_prefix;

    // Create two different findings
    let mut finding1 = crate::fixtures::create_test_finding(
        "f1",
        "Buffer overflow in parse_input",
        "/tmp/test1.c",
        42,
    );
    finding1.description = "Potential buffer overflow".to_string();
    finding1.sources = vec!["static_analysis".to_string()];
    finding1.code_snippet = Some("strcpy(buf, input);".to_string());
    finding1.cwe_id = Some("CWE-120".to_string());
    finding1.severity = baco::findings::Severity::High;

    let mut finding2 = crate::fixtures::create_test_finding(
        "f2",
        "Use-after-free in cleanup",
        "/tmp/test2.c",
        128,
    );
    finding2.description = "Use after free detected".to_string();
    finding2.sources = vec!["static_analysis".to_string()];
    finding2.code_snippet = Some("free(ptr); use(ptr);".to_string());
    finding2.cwe_id = Some("CWE-416".to_string());
    finding2.severity = baco::findings::Severity::Critical;

    let hunt_prompts: HashMap<String, String> = HashMap::new();

    // Build stable prefixes for both findings
    let prefix1 = build_stable_verification_prefix(&[finding1.clone()], &hunt_prompts);
    let prefix2 = build_stable_verification_prefix(&[finding2.clone()], &hunt_prompts);

    // Prefixes should be identical (same phase + domain combination)
    assert_eq!(
        prefix1, prefix2,
        "Stable verification prefix must be byte-identical across findings"
    );

    // Verify prefixes are substantial (not empty)
    assert!(prefix1.len() > 100, "Stable prefix should be substantial");
}

#[test]
fn test_discovery_stable_prefix_identical() {
    // Test that discovery prompts share identical stable prefix across different findings
    use baco::scanner::phases::llm_phases::discovery::build_stable_discovery_prefix;

    let mut finding1 =
        crate::fixtures::create_test_finding("d1", "SQL injection in query", "/tmp/test1.rs", 15);
    finding1.description = "SQL injection vulnerability".to_string();
    finding1.sources = vec!["static_analysis".to_string()];
    finding1.code_snippet =
        Some("query(&format!(\"SELECT * FROM users WHERE id={}\", id))".to_string());
    finding1.cwe_id = Some("CWE-89".to_string());
    finding1.severity = baco::findings::Severity::Critical;

    let mut finding2 =
        crate::fixtures::create_test_finding("d2", "XSS in response", "/tmp/test2.rs", 89);
    finding2.description = "Cross-site scripting vulnerability".to_string();
    finding2.sources = vec!["static_analysis".to_string()];
    finding2.code_snippet = Some("format!(\"<div>{}</div>\", user_input)".to_string());
    finding2.cwe_id = Some("CWE-79".to_string());
    finding2.severity = baco::findings::Severity::High;

    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix1 = build_stable_discovery_prefix(&[finding1.clone()], &hunt_prompts);
    let prefix2 = build_stable_discovery_prefix(&[finding2.clone()], &hunt_prompts);

    assert_eq!(
        prefix1, prefix2,
        "Stable discovery prefix must be byte-identical across findings"
    );
    assert!(prefix1.len() > 100, "Stable prefix should be substantial");
}

#[test]
fn test_enrichment_stable_prefix_identical() {
    // Test that enrichment prompts share identical stable prefix across different findings
    use baco::report::ai_aggregation::enrichment::build_stable_enrichment_prefix;

    let mut finding1 =
        crate::fixtures::create_test_finding("e1", "Buffer overflow", "/tmp/test1.c", 42);
    finding1.description = "Potential buffer overflow".to_string();
    finding1.sources = vec!["static_analysis".to_string()];
    finding1.code_snippet = Some("strcpy(buf, input);".to_string());
    finding1.cwe_id = Some("CWE-120".to_string());
    finding1.severity = baco::findings::Severity::High;

    let mut finding2 =
        crate::fixtures::create_test_finding("e2", "Use-after-free", "/tmp/test2.c", 128);
    finding2.description = "Use after free detected".to_string();
    finding2.sources = vec!["static_analysis".to_string()];
    finding2.code_snippet = Some("free(ptr); use(ptr);".to_string());
    finding2.cwe_id = Some("CWE-416".to_string());
    finding2.severity = baco::findings::Severity::Critical;

    let prefix1 = build_stable_enrichment_prefix(&[finding1.clone()]);
    let prefix2 = build_stable_enrichment_prefix(&[finding2.clone()]);

    assert_eq!(
        prefix1, prefix2,
        "Stable enrichment prefix must be byte-identical across findings"
    );
    assert!(prefix1.len() > 50, "Stable prefix should be substantial");
}

#[test]
fn test_volatile_content_differs() {
    // Verify that volatile content (finding-specific) differs between prompts
    use baco::scanner::phases::llm_phases::verification::{
        build_stable_verification_prefix, build_volatile_verification_tail,
    };

    let mut finding1 =
        crate::fixtures::create_test_finding("b1", "Buffer overflow", "/tmp/test1.c", 42);
    finding1.description = "Potential buffer overflow".to_string();
    finding1.sources = vec!["static_analysis".to_string()];
    finding1.code_snippet = Some("strcpy(buf, input);".to_string());
    finding1.cwe_id = Some("CWE-120".to_string());
    finding1.severity = baco::findings::Severity::High;

    let mut finding2 =
        crate::fixtures::create_test_finding("b2", "Different finding", "/tmp/test2.c", 99);
    finding2.description = "Different issue".to_string();
    finding2.sources = vec!["static_analysis".to_string()];
    finding2.code_snippet = Some("free(ptr); use(ptr);".to_string());
    finding2.cwe_id = Some("CWE-416".to_string());
    finding2.severity = baco::findings::Severity::Critical;

    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let stable1 = build_stable_verification_prefix(&[finding1.clone()], &hunt_prompts);
    let stable2 = build_stable_verification_prefix(&[finding2.clone()], &hunt_prompts);
    let volatile1 = build_volatile_verification_tail(&[finding1.clone()], &hunt_prompts);
    let volatile2 = build_volatile_verification_tail(&[finding2.clone()], &hunt_prompts);

    // Stable prefixes should be identical
    assert_eq!(stable1, stable2);

    // Volatile content should differ
    assert_ne!(
        volatile1, volatile2,
        "Volatile tail must differ for different findings"
    );

    // Full prompt should differ
    let full1 = format!("{}{}", stable1, volatile1);
    let full2 = format!("{}{}", stable2, volatile2);
    assert_ne!(full1, full2, "Full prompts must differ");
}

#[test]
fn test_batch_prefix_stability() {
    // Test that batch prompts have stable prefix regardless of batch content
    use baco::scanner::phases::llm_phases::verification::{
        build_stable_verification_prefix, build_volatile_verification_tail,
    };

    let mut finding1 = crate::fixtures::create_test_finding("p1", "Finding 1", "/tmp/test1.c", 10);
    finding1.description = "First finding".to_string();
    finding1.sources = vec!["static_analysis".to_string()];
    finding1.code_snippet = Some("code1".to_string());
    finding1.cwe_id = Some("CWE-120".to_string());
    finding1.severity = baco::findings::Severity::High;

    let mut finding2 = crate::fixtures::create_test_finding("p2", "Finding 2", "/tmp/test2.c", 20);
    finding2.description = "Second finding".to_string();
    finding2.sources = vec!["static_analysis".to_string()];
    finding2.code_snippet = Some("code2".to_string());
    finding2.cwe_id = Some("CWE-120".to_string());
    finding2.severity = baco::findings::Severity::High;

    let mut finding3 = crate::fixtures::create_test_finding("p3", "Finding 3", "/tmp/test3.c", 30);
    finding3.description = "Third finding".to_string();
    finding3.sources = vec!["static_analysis".to_string()];
    finding3.code_snippet = Some("code3".to_string());
    finding3.cwe_id = Some("CWE-120".to_string());
    finding3.severity = baco::findings::Severity::High;

    let hunt_prompts: HashMap<String, String> = HashMap::new();

    // Batch 1: findings 1, 2
    let batch1 = vec![finding1.clone(), finding2.clone()];
    let prefix1 = build_stable_verification_prefix(&batch1, &hunt_prompts);
    let volatile1 = build_volatile_verification_tail(&batch1, &hunt_prompts);

    // Batch 2: findings 2, 3
    let batch2 = vec![finding2.clone(), finding3.clone()];
    let prefix2 = build_stable_verification_prefix(&batch2, &hunt_prompts);
    let volatile2 = build_volatile_verification_tail(&batch2, &hunt_prompts);

    // Prefixes should be identical (same domain/phase)
    assert_eq!(
        prefix1, prefix2,
        "Batch prefixes must be stable across different batches"
    );

    // Volatile content differs
    assert_ne!(volatile1, volatile2);
}
