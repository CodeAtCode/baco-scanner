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
fn test_cve_bootstrap_basic() {
    let temp_dir = TempDir::new().unwrap();
    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

    // Should initialize without error
    assert!(temp_dir.path().exists());
    drop(bootstrapper);
}

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
