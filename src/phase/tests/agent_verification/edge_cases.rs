//! Edge case tests

use crate::agent::session::AgentSession;
use crate::config::AgentConfig;
use crate::phase::tests::agent_verification::test_helpers::{
    create_agent_mock_client, make_chat_response,
};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

/// Test 6: Edge case - empty finding.description (should still run agent loop)
#[tokio::test]
async fn test_empty_description_still_runs_agent_loop() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    fs::write(&test_file, "void test() {}").unwrap();

    // Mock that returns empty description initially
    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Empty Finding",
                "description": "",
                "severity": "Medium",
                "cwe_id": "",
                "line_number": 0,
                "code_snippet": ""
            }"#,
            "test-model",
            vec![],
        ),
    ];

    let mock_client = create_agent_mock_client(responses);
    let config = AgentConfig {
        enabled: true,
        max_turns: 2,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let session = AgentSession::new(
        mock_client,
        &config,
        temp_dir.path(),
        Arc::new(|_| {}),
    );

    let result = session.analyze_file(test_file.to_str().unwrap()).await;
    
    // Agent loop should complete even with empty description
    assert!(result.is_ok());
    let finding = result.unwrap();
    
    // Finding should still be created (may have empty fields)
    assert_eq!(finding.finding.title, "Empty Finding");
    assert_eq!(finding.finding.description, "");
}

/// Test 7: Edge case - finding with no code snippet
#[tokio::test]
async fn test_finding_with_no_code_snippet() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    fs::write(&test_file, "void test() {}").unwrap();

    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Configuration Issue",
                "description": "Insecure default configuration detected",
                "severity": "Medium",
                "cwe_id": "CWE-15",
                "line_number": null,
                "code_snippet": null
            }"#,
            "test-model",
            vec![],
        ),
    ];

    let mock_client = create_agent_mock_client(responses);
    let config = AgentConfig {
        enabled: true,
        max_turns: 2,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let session = AgentSession::new(
        mock_client,
        &config,
        temp_dir.path(),
        Arc::new(|_| {}),
    );

    let result = session.analyze_file(test_file.to_str().unwrap()).await;
    
    assert!(result.is_ok());
    let finding = result.unwrap();
    
    // Code snippet can be None for configuration issues
    assert_eq!(finding.finding.title, "Configuration Issue");
    assert!(finding.finding.code_snippet.is_none() || finding.finding.code_snippet.unwrap().is_empty());
}
