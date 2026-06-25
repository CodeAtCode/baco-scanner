//! Test fixtures for integration tests

use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::scanner::Scanner;
use mockito::Server;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a temporary project with test files
pub fn create_test_project(temp_dir: &TempDir) -> PathBuf {
    let project_path = temp_dir.path().join("test-project");
    fs::create_dir_all(&project_path).unwrap();

    // Create a Rust file with a potential vulnerability
    let vuln_file = project_path.join("vulnerable.rs");
    fs::write(
        &vuln_file,
        r#"
// Vulnerable code for testing
fn process_input(input: &str) {
    let command = format!("echo {}", input);
    std::process::command("bash").arg("-c").arg(&command);
}

fn main() {
    process_input("hello");
}
"#,
    )
    .unwrap();

    // Create a TypeScript file
    let ts_file = project_path.join("app.ts");
    fs::write(
        &ts_file,
        r#"
// TypeScript file for multi-language test
function userInput(data: string) {
    const query = "SELECT * FROM users WHERE id = " + data;
    console.log(query);
}
"#,
    )
    .unwrap();

    project_path
}

/// Helper to create scanner with config
pub fn create_test_scanner(project_path: PathBuf, output_dir: PathBuf) -> Scanner {
    let mut config = ScannerConfig::default();
    config.output.dir = output_dir.to_string_lossy().to_string();
    config.project.path = project_path.to_string_lossy().to_string();
    config.project.name = "test-e2e-project".to_string();

    Scanner::new(config, project_path, false)
}

/// Creates a finding for testing
pub fn create_test_finding(id: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test finding: {}", id),
        description: format!("Description for {}", id),
        file_path: "test.rs".to_string(),
        line_number: Some(1),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        sources: vec!["test".to_string()],
        verification_status: None,
        verification_notes: None,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

/// Creates a complete finding with all fields populated
pub fn create_complete_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "complete-finding".to_string(),
        title: "Complete Finding".to_string(),
        description: "A finding with all fields set".to_string(),
        file_path: "complete.rs".to_string(),
        line_number: Some(42),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-78".to_string()),
        sources: vec!["semgrep".to_string(), "llm".to_string()],
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Verified".to_string()),
        code_snippet: Some("vulnerable_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: Some("complete.rs:42".to_string()),
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.85),
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: Some("llama3.1".to_string()),
        agent_mode: true,
    }
}

/// Creates a mock LLM server for testing
pub async fn create_mock_llm_server() -> mockito::ServerGuard {
    let mut server = Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": json!({
                            "description": "Potential vulnerability detected",
                            "fix_code": "Use secure coding practices"
                        })
                        .to_string()
                    }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;
    // Return the server - the mock is stored in the server internally in mockito 1.x
    server
}
