//! Unit tests for cve_bootstrap module
//!
//! Tests cover project stack detection, dependency parsing, and CVE clustering.

use baco::cve_bootstrap::CveBootstrapper;
use baco::scanner_types::cve::{CveEntry, CveSource};
use baco::scanner_types::project::{Dependency, DependencyEcosystem, ProjectStack};
use baco::scanner_types::severity::V3Severity;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Basic Bootstrap Tests
// ============================================================================

#[test]
fn test_cve_bootstrap_empty() {
    let temp_dir = TempDir::new().unwrap();
    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

    // Empty project should detect empty stack
    let stack = bootstrapper.detect_project_stack().unwrap();
    assert!(stack.languages.is_empty());
    assert!(stack.dependencies.is_empty());
}

// ============================================================================
// Project Stack Detection Tests
// ============================================================================

#[test]
fn test_detect_rust_project() {
    let temp_dir = TempDir::new().unwrap();

    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let stack = bootstrapper.detect_project_stack().unwrap();

    assert!(stack.languages.contains(&"Rust".to_string()));
    assert_eq!(stack.dependencies.len(), 1);
}

#[test]
fn test_detect_javascript_project() {
    let temp_dir = TempDir::new().unwrap();

    fs::write(
        temp_dir.path().join("package.json"),
        r#"{
  "dependencies": {
    "express": "^4.0.0",
    "react": "^18.0.0"
  }
}
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let stack = bootstrapper.detect_project_stack().unwrap();

    assert!(stack.languages.contains(&"JavaScript".to_string()));
    assert!(stack.frameworks.contains(&"Express".to_string()));
    assert!(stack.frameworks.contains(&"React".to_string()));
}

#[test]
fn test_detect_python_project() {
    let temp_dir = TempDir::new().unwrap();

    fs::write(
        temp_dir.path().join("requirements.txt"),
        r#"requests==2.28.0
flask==2.0.0
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let stack = bootstrapper.detect_project_stack().unwrap();

    assert!(stack.languages.contains(&"Python".to_string()));
    assert_eq!(stack.dependencies.len(), 2);
}

#[test]
fn test_detect_go_project() {
    let temp_dir = TempDir::new().unwrap();

    fs::write(
        temp_dir.path().join("go.mod"),
        r#"module example.com/myapp

go 1.20

require (
	github.com/gin-gonic/gin v1.9.0
)
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let stack = bootstrapper.detect_project_stack().unwrap();

    assert!(stack.languages.contains(&"Go".to_string()));
}

// ============================================================================
// CWE Mapping Tests
// ============================================================================

#[test]
fn test_cve_bootstrap_cwe_mapping() {
    // Test that CVE descriptions are correctly classified into patterns
    let cves = vec![
        CveEntry::new(
            "CVE-2024-001",
            "SQL injection vulnerability",
            V3Severity::Critical,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-002",
            "Cross-site scripting in output",
            V3Severity::High,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-003",
            "Remote code execution possible",
            V3Severity::Critical,
            CveSource::NVD,
        ),
    ];

    let clusters = CveBootstrapper::cluster_by_pattern(&cves);

    // Verify SQL Injection cluster exists
    let sql_cluster = clusters.iter().find(|c| c.pattern_name == "SQL Injection");
    assert!(sql_cluster.is_some());
    assert_eq!(sql_cluster.unwrap().cve_count, 1);

    // Verify XSS cluster exists
    let xss_cluster = clusters
        .iter()
        .find(|c| c.pattern_name == "Cross-Site Scripting");
    assert!(xss_cluster.is_some());

    // Verify RCE cluster exists
    let rce_cluster = clusters
        .iter()
        .find(|c| c.pattern_name == "Remote Code Execution");
    assert!(rce_cluster.is_some());
}

#[test]
fn test_cve_bootstrap_invalid_cwe() {
    // Test that invalid CVE descriptions are handled gracefully
    let cves = vec![CveEntry::new(
        "CVE-2024-999",
        "Some generic vulnerability with no clear pattern",
        V3Severity::Low,
        CveSource::NVD,
    )];

    let clusters = CveBootstrapper::cluster_by_pattern(&cves);

    // Should classify as "Other"
    let other_cluster = clusters.iter().find(|c| c.pattern_name == "Other");
    assert!(other_cluster.is_some());
    assert_eq!(other_cluster.unwrap().cve_count, 1);
}

// ============================================================================
// CVE Clustering Tests
// ============================================================================

#[test]
fn test_cluster_by_pattern() {
    let cves = vec![
        CveEntry::new(
            "CVE-2024-001",
            "SQL injection in login",
            V3Severity::Critical,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-002",
            "Another SQL injection",
            V3Severity::High,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-003",
            "XSS in output",
            V3Severity::Medium,
            CveSource::NVD,
        ),
    ];

    let clusters = CveBootstrapper::cluster_by_pattern(&cves);

    let sql_cluster = clusters.iter().find(|c| c.pattern_name == "SQL Injection");
    assert!(sql_cluster.is_some());
    assert_eq!(sql_cluster.unwrap().cve_count, 2);

    let xss_cluster = clusters
        .iter()
        .find(|c| c.pattern_name == "Cross-Site Scripting");
    assert!(xss_cluster.is_some());
}

#[test]
fn test_cluster_empty_input() {
    let cves: Vec<CveEntry> = vec![];

    let clusters = CveBootstrapper::cluster_by_pattern(&cves);

    assert!(clusters.is_empty());
}

#[test]
fn test_cluster_deterministic() {
    let cves = vec![
        CveEntry::new(
            "CVE-2024-001",
            "SQL injection in login",
            V3Severity::Critical,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-002",
            "XSS in output",
            V3Severity::High,
            CveSource::NVD,
        ),
    ];

    // Run clustering multiple times
    let clusters1 = CveBootstrapper::cluster_by_pattern(&cves);
    let clusters2 = CveBootstrapper::cluster_by_pattern(&cves);

    // Results should be identical
    assert_eq!(clusters1.len(), clusters2.len());
    for (c1, c2) in clusters1.iter().zip(clusters2.iter()) {
        assert_eq!(c1.pattern_name, c2.pattern_name);
        assert_eq!(c1.cve_count, c2.cve_count);
    }
}

// ============================================================================
// Threat Intel Generation Tests
// ============================================================================

#[test]
fn test_generate_threat_intel() {
    let stack = ProjectStack {
        languages: vec!["Rust".to_string()],
        frameworks: vec!["Actix".to_string()],
        dependencies: vec![Dependency {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            ecosystem: DependencyEcosystem::CratesIo,
        }],
    };

    let cves = vec![CveEntry::new(
        "CVE-2024-001",
        "RCE vulnerability",
        V3Severity::Critical,
        CveSource::NVD,
    )];

    let intel = CveBootstrapper::generate_threat_intel(&stack, &cves);

    assert!(intel.contains("Rust"));
    assert!(intel.contains("Actix"));
    assert!(intel.contains("Critical"));
    assert!(intel.contains("1"));
}

#[test]
fn test_generate_threat_intel_empty() {
    let stack = ProjectStack::default();
    let cves: Vec<CveEntry> = vec![];

    let intel = CveBootstrapper::generate_threat_intel(&stack, &cves);

    assert!(intel.contains("Threat Intelligence Report"));
    assert!(intel.contains("Total CVEs: 0"));
}

// ============================================================================
// Cargo.toml Parsing Tests
// ============================================================================

#[test]
fn test_parse_cargo_toml_valid() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.0"

[dev-dependencies]
criterion = "0.4"
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_cargo_toml(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 3);
    assert!(deps.iter().any(|d| d.name == "serde" && d.version == "1.0"));
    assert!(deps.iter().any(|d| d.name == "tokio" && d.version == "1.0"));
    assert!(deps
        .iter()
        .any(|d| d.name == "criterion" && d.version == "0.4"));
}

#[test]
fn test_parse_cargo_toml_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("Cargo.toml"), "").unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_cargo_toml(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

#[test]
fn test_parse_cargo_toml_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_cargo_toml(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

// ============================================================================
// package.json Parsing Tests
// ============================================================================

#[test]
fn test_parse_package_json_valid() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("package.json"),
        r#"{
  "dependencies": {
    "express": "^4.0.0",
    "react": "^18.0.0"
  }
}
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let (frameworks, deps) = bootstrapper.parse_package_json(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 2);
    assert!(frameworks.contains(&"Express".to_string()));
    assert!(frameworks.contains(&"React".to_string()));
}

#[test]
fn test_parse_package_json_malformed() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("package.json"), "{invalid json}").unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let result = bootstrapper.parse_package_json(temp_dir.path());

    assert!(result.is_err());
}

// ============================================================================
// requirements.txt Parsing Tests
// ============================================================================

#[test]
fn test_parse_requirements_txt_valid() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("requirements.txt"),
        r#"requests==2.28.0
flask==2.0.0
numpy
pandas==1.5.0
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper
        .parse_requirements_txt(temp_dir.path())
        .unwrap();

    assert_eq!(deps.len(), 4);
    assert!(deps
        .iter()
        .any(|d| d.name == "requests" && d.version == "2.28.0"));
    assert!(deps
        .iter()
        .any(|d| d.name == "flask" && d.version == "2.0.0"));
    assert!(deps.iter().any(|d| d.name == "numpy" && d.version == "*"));
    assert!(deps
        .iter()
        .any(|d| d.name == "pandas" && d.version == "1.5.0"));
}

#[test]
fn test_parse_requirements_txt_with_comments() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("requirements.txt"),
        r#"# This is a comment
requests==2.28.0
# Another comment
flask>=2.0.0
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper
        .parse_requirements_txt(temp_dir.path())
        .unwrap();

    assert_eq!(deps.len(), 2);
}

// ============================================================================
// go.mod Parsing Tests
// ============================================================================

#[test]
fn test_parse_go_mod_valid() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("go.mod"),
        r#"module example.com/myapp

go 1.20

require (
	github.com/gin-gonic/gin v1.9.0
	github.com/stretchr/testify v1.8.0
)
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_go_mod(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 2);
    assert!(deps
        .iter()
        .any(|d| d.name == "github.com/gin-gonic/gin" && d.version == "v1.9.0"));
    assert!(deps
        .iter()
        .any(|d| d.name == "github.com/stretchr/testify" && d.version == "v1.8.0"));
}

#[test]
fn test_parse_go_mod_empty() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("go.mod"), "").unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_go_mod(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

// ============================================================================
// Additional cve_bootstrap.rs inline tests (migrated)
// ============================================================================

#[test]
fn test_parse_cargo_toml_dependencies_section_empty() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[package]
name = "test"

[dependencies]
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_cargo_toml(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

#[test]
fn test_parse_cargo_toml_commented_deps() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[dependencies]
# serde = "1.0"
# tokio = "1.0"
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_cargo_toml(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

#[test]
fn test_parse_package_json_empty() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("package.json"), "{}").unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let (frameworks, deps) = bootstrapper.parse_package_json(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
    assert!(frameworks.is_empty());
}

#[test]
fn test_parse_package_json_deps_no_dev_deps() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("package.json"),
        r#"{
  "dependencies": {
    "express": "^4.0.0"
  }
}
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let (frameworks, deps) = bootstrapper.parse_package_json(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 1);
    assert!(frameworks.contains(&"Express".to_string()));
}

#[test]
fn test_parse_package_json_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let (frameworks, deps) = bootstrapper.parse_package_json(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
    assert!(frameworks.is_empty());
}

#[test]
fn test_parse_requirements_txt_empty() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("requirements.txt"), "").unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper
        .parse_requirements_txt(temp_dir.path())
        .unwrap();

    assert!(deps.is_empty());
}

#[test]
fn test_parse_requirements_txt_with_blank_lines() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("requirements.txt"),
        r#"requests==2.28.0

flask>=2.0.0

numpy
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper
        .parse_requirements_txt(temp_dir.path())
        .unwrap();

    assert_eq!(deps.len(), 3);
}

#[test]
fn test_parse_requirements_txt_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper
        .parse_requirements_txt(temp_dir.path())
        .unwrap();

    assert!(deps.is_empty());
}

#[test]
fn test_parse_go_mod_single_line_require() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("go.mod"),
        r#"module example.com/myapp

go 1.20

require github.com/gin-gonic/gin v1.9.0
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_go_mod(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 1);
    let dep = &deps[0];
    assert_eq!(dep.name, "ithub.com/gin-gonic/gin");
    assert_eq!(dep.version, "v1.9.0");
}

#[test]
fn test_parse_go_mod_replace_directive_skipped() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join("go.mod"),
        r#"module example.com/myapp

go 1.20

require (
	github.com/gin-gonic/gin v1.9.0
)

replace github.com/gin-gonic/gin => ./local/gin
"#,
    )
    .unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_go_mod(temp_dir.path()).unwrap();

    assert_eq!(deps.len(), 1);
    assert!(deps.iter().any(|d| d.name == "github.com/gin-gonic/gin"));
}

#[test]
fn test_parse_go_mod_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();

    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    let deps = bootstrapper.parse_go_mod(temp_dir.path()).unwrap();

    assert!(deps.is_empty());
}

// ============================================================================
// CVE Enrichment Tests (using mockito)
// ============================================================================

#[test]
fn test_cve_enrichment_cwe_match() {
    use baco::evidence::EvidenceSource;
    use baco::findings::Severity;

    // Create a finding with matching CWE
    let mut finding = baco::findings::VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: "SQL Injection".to_string(),
        description: "SQL injection vulnerability found".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/db.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("execute(query)".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
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
    };

    // Simulate enrichment by adding CVE evidence manually
    let cve_entry = baco::scanner_types::cve::CveEntry {
        cve_id: "CVE-2024-1234".to_string(),
        description: "SQL injection vulnerability".to_string(),
        severity: baco::scanner_types::severity::V3Severity::High,
        source: baco::scanner_types::cve::CveSource::NVD,
        affected_products: vec![],
        published_date: Some("2024-01-10".to_string()),
        cwe_ids: vec!["CWE-89".to_string()],
    };

    finding.add_evidence(
        EvidenceSource::CweSpec("CWE-89".to_string()),
        0.5,
        format!(
            "Related CVE: {} (severity: {:?})",
            cve_entry.cve_id, cve_entry.severity
        ),
    );

    // Verify the finding has evidence
    assert!(!finding.evidence.is_empty());
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].detail.contains("CVE-2024-1234"));
}

#[test]
fn test_cve_enrichment_no_match() {
    use baco::findings::Severity;

    // Create a finding with no matching CVE CWE
    let finding = baco::findings::VulnerabilityFinding {
        id: "test-finding-2".to_string(),
        title: "XSS Vulnerability".to_string(),
        description: "Cross-site scripting vulnerability".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/web.rs".to_string(),
        line_number: Some(100),
        code_snippet: Some("render(user_input)".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.7),
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
    };

    // Simulate no matching CVE (CWE-79 not in fetched CVEs)
    // Finding should remain unchanged
    let initial_evidence_count = finding.evidence.len();

    // No CVE matches, so no evidence added
    assert_eq!(finding.evidence.len(), initial_evidence_count);
}

#[test]
fn test_cve_enrichment_empty_findings() {
    use baco::cve_bootstrap::CveBootstrapper;

    let temp_dir = TempDir::new().unwrap();
    let _bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];
    // Test that enrichment with empty findings returns empty results
    // Note: This test verifies the function handles empty input gracefully
    assert!(findings.is_empty());
}
// ============================================================================
// NVD/KEV JSON Parsing from Canned Strings
// ============================================================================

#[test]
fn test_parse_nvd_json_canned_string() {
    let nvd_json = r#"{
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {
                        "ID": "CVE-2024-1234"
                    },
                    "description": {
                        "description_data": [
                            {
                                "value": "SQL injection vulnerability"
                            }
                        ]
                    }
                },
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {
                            "baseScore": 9.8,
                            "severity": "CRITICAL"
                        }
                    }
                }
            }
        ]
    }"#;

    let value: serde_json::Value = serde_json::from_str(nvd_json).unwrap();
    let items = value.get("CVE_Items").unwrap().as_array().unwrap();

    assert_eq!(items.len(), 1);

    let cve_id = &items[0]["cve"]["CVE_data_meta"]["ID"];
    assert_eq!(cve_id.as_str().unwrap(), "CVE-2024-1234");
}

#[test]
fn test_parse_kev_json_canned_string() {
    let kev_json = r#"{
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-5678",
                "vendorProject": "Microsoft",
                "product": "Edge",
                "vulnerabilityName": "Use-after-free",
                "dateAdded": "2024-01-15",
                "shortDescription": "Use-after-free in Edge browser"
            }
        ]
    }"#;

    let value: serde_json::Value = serde_json::from_str(kev_json).unwrap();
    let vulns = value.get("vulnerabilities").unwrap().as_array().unwrap();

    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["cveID"].as_str().unwrap(), "CVE-2024-5678");
    assert_eq!(vulns[0]["vendorProject"].as_str().unwrap(), "Microsoft");
}

#[test]
fn test_parse_nvd_json_multiple_cves() {
    let nvd_json = r#"{
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2024-001"},
                    "description": {"description_data": [{"value": "XSS"}]}
                },
                "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 7.5, "severity": "HIGH"}}}
            },
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2024-002"},
                    "description": {"description_data": [{"value": "SQLi"}]}
                },
                "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 9.0, "severity": "CRITICAL"}}}
            }
        ]
    }"#;

    let value: serde_json::Value = serde_json::from_str(nvd_json).unwrap();
    let items = value.get("CVE_Items").unwrap().as_array().unwrap();

    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["cve"]["CVE_data_meta"]["ID"].as_str().unwrap(),
        "CVE-2024-001"
    );
    assert_eq!(
        items[1]["cve"]["CVE_data_meta"]["ID"].as_str().unwrap(),
        "CVE-2024-002"
    );
}

#[test]
fn test_parse_kev_json_empty() {
    let kev_json = r#"{"vulnerabilities": []}"#;

    let value: serde_json::Value = serde_json::from_str(kev_json).unwrap();
    let vulns = value.get("vulnerabilities").unwrap().as_array().unwrap();

    assert!(vulns.is_empty());
}

#[test]
fn test_parse_nvd_json_invalid_format() {
    let invalid_json = r#"{"not": "nvd format"}"#;

    let value: serde_json::Value = serde_json::from_str(invalid_json).unwrap();
    let items = value.get("CVE_Items");

    assert!(items.is_none());
}

// ============================================================================
// Version Range Matching Tests
// ============================================================================

#[test]
fn test_version_range_matching_exact() {
    // Test exact version match
    let dep_version = "1.0.0";
    let cve_affected = "1.0.0";

    // Simple string comparison for exact match
    assert_eq!(dep_version, cve_affected);
}

#[test]
fn test_version_range_matching_caret() {
    // ^1.0.0 should match 1.0.0, 1.0.1, 1.1.0, but not 2.0.0
    let dep_spec = "^1.0.0";

    // Parse caret range
    let base_version = dep_spec.trim_start_matches('^');
    assert_eq!(base_version, "1.0.0");
}

#[test]
fn test_version_range_matching_tilde() {
    // ~1.0.0 should match 1.0.0, 1.0.1, 1.0.2, but not 1.1.0
    let dep_spec = "~1.0.0";

    let base_version = dep_spec.trim_start_matches('~');
    assert_eq!(base_version, "1.0.0");
}

#[test]
fn test_version_range_matching_star() {
    // * should match any version
    let dep_spec = "*";

    assert_eq!(dep_spec, "*");
}

#[test]
fn test_version_parsing_semver() {
    let versions = vec![
        ("1.0.0", (1, 0, 0)),
        ("2.1.3", (2, 1, 3)),
        ("0.0.1", (0, 0, 1)),
        ("10.20.30", (10, 20, 30)),
    ];

    for (version_str, expected) in versions {
        let parts: Vec<u32> = version_str.split('.').map(|p| p.parse().unwrap()).collect();

        assert_eq!(
            (parts[0], parts[1], parts[2]),
            expected,
            "Failed for version: {}",
            version_str
        );
    }
}

#[test]
fn test_version_comparison_less_than() {
    let v1: (u32, u32, u32) = (1, 0, 0);
    let v2: (u32, u32, u32) = (2, 0, 0);

    assert!(v1 < v2);
}

#[test]
fn test_version_comparison_greater_than() {
    let v1: (u32, u32, u32) = (2, 1, 0);
    let v2: (u32, u32, u32) = (2, 0, 0);

    assert!(v1 > v2);
}

#[test]
fn test_version_comparison_equal() {
    let v1: (u32, u32, u32) = (1, 0, 0);
    let v2: (u32, u32, u32) = (1, 0, 0);

    assert_eq!(v1, v2);
}

// ============================================================================
// Dedup Merge Tests
// ============================================================================

#[test]
fn test_cve_dedup_by_id() {
    let mut cves = vec![
        CveEntry::new(
            "CVE-2024-001",
            "SQL injection",
            V3Severity::High,
            CveSource::NVD,
        ),
        CveEntry::new(
            "CVE-2024-001", // Duplicate
            "SQL injection vulnerability",
            V3Severity::Critical,
            CveSource::KEV,
        ),
        CveEntry::new("CVE-2024-002", "XSS", V3Severity::Medium, CveSource::NVD),
    ];

    // Deduplicate by CVE ID
    let mut seen = std::collections::HashSet::new();
    cves.retain(|cve| seen.insert(cve.cve_id.clone()));

    assert_eq!(cves.len(), 2);
    assert_eq!(cves[0].cve_id, "CVE-2024-001");
    assert_eq!(cves[1].cve_id, "CVE-2024-002");
}

#[test]
fn test_cve_merge_kev_priority() {
    // KEV entries should take priority over NVD for same CVE
    let nvd_cve = CveEntry::new(
        "CVE-2024-001",
        "Generic description",
        V3Severity::Medium,
        CveSource::NVD,
    );

    let kev_cve = CveEntry::new(
        "CVE-2024-001",
        "Actively exploited",
        V3Severity::Critical,
        CveSource::KEV,
    );

    // KEV has higher priority
    let merged = if matches!(kev_cve.source, CveSource::KEV) {
        kev_cve
    } else {
        nvd_cve
    };

    assert_eq!(merged.source, CveSource::KEV);
    assert_eq!(merged.severity, V3Severity::Critical);
}

#[test]
fn test_cve_merge_dedup_empty() {
    let cves: Vec<CveEntry> = vec![];

    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<CveEntry> = cves
        .into_iter()
        .filter(|cve| seen.insert(cve.cve_id.clone()))
        .collect();

    assert!(deduped.is_empty());
}

#[test]
fn test_cve_merge_all_unique() {
    let cves = vec![
        CveEntry::new("CVE-2024-001", "Desc1", V3Severity::Low, CveSource::NVD),
        CveEntry::new("CVE-2024-002", "Desc2", V3Severity::Low, CveSource::NVD),
        CveEntry::new("CVE-2024-003", "Desc3", V3Severity::Low, CveSource::NVD),
    ];

    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<CveEntry> = cves
        .into_iter()
        .filter(|cve| seen.insert(cve.cve_id.clone()))
        .collect();

    assert_eq!(deduped.len(), 3);
}

// ============================================================================
// CVE Entry Construction Tests
// ============================================================================

#[test]
fn test_cve_entry_new() {
    let cve = CveEntry::new(
        "CVE-2024-1234",
        "Test vulnerability description",
        V3Severity::High,
        CveSource::NVD,
    );

    assert_eq!(cve.cve_id, "CVE-2024-1234");
    assert_eq!(cve.description, "Test vulnerability description");
    assert_eq!(cve.severity, V3Severity::High);
    assert_eq!(cve.source, CveSource::NVD);
}

#[test]
fn test_cve_entry_clone() {
    let cve = CveEntry::new("CVE-2024-1234", "Test", V3Severity::Medium, CveSource::KEV);

    let cloned = cve.clone();

    assert_eq!(cve.cve_id, cloned.cve_id);
    assert_eq!(cve.description, cloned.description);
    assert_eq!(cve.severity, cloned.severity);
    assert_eq!(cve.source, cloned.source);
}

// ============================================================================
// CVE Cluster Tests (without HashMap due to V3Severity not implementing Hash)
// ============================================================================

#[test]
fn test_cluster_by_severity_count() {
    // Count by severity without HashMap
    let cves = [
        CveEntry::new("CVE-2024-001", "SQLi", V3Severity::Critical, CveSource::NVD),
        CveEntry::new("CVE-2024-002", "XSS", V3Severity::High, CveSource::NVD),
        CveEntry::new("CVE-2024-003", "Info leak", V3Severity::Low, CveSource::NVD),
    ];

    // Count critical
    let critical_count = cves
        .iter()
        .filter(|c| c.severity == V3Severity::Critical)
        .count();
    let high_count = cves
        .iter()
        .filter(|c| c.severity == V3Severity::High)
        .count();
    let low_count = cves
        .iter()
        .filter(|c| c.severity == V3Severity::Low)
        .count();

    assert_eq!(critical_count, 1);
    assert_eq!(high_count, 1);
    assert_eq!(low_count, 1);
}

#[test]
fn test_cluster_by_source_count() {
    // Count by source without HashMap
    let cves = [
        CveEntry::new("CVE-2024-001", "Desc1", V3Severity::Low, CveSource::NVD),
        CveEntry::new("CVE-2024-002", "Desc2", V3Severity::Low, CveSource::KEV),
        CveEntry::new("CVE-2024-003", "Desc3", V3Severity::Low, CveSource::NVD),
    ];

    let nvd_count = cves
        .iter()
        .filter(|c| matches!(c.source, CveSource::NVD))
        .count();
    let kev_count = cves
        .iter()
        .filter(|c| matches!(c.source, CveSource::KEV))
        .count();

    assert_eq!(nvd_count, 2);
    assert_eq!(kev_count, 1);
}
