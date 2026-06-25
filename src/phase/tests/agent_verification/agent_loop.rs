//! Agent loop execution tests

use crate::agent::session::AgentSession;
use crate::config::AgentConfig;
use crate::phase::tests::agent_verification::test_helpers::{
    create_agent_mock_client, make_chat_response, make_file_read_tool,
    make_file_write_tool, make_pattern_search_tool,
};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

/// Test 1: Agent loop executes with tool calls (not just simulation)
#[tokio::test]
async fn test_agent_loop_executes_with_real_tool_calls() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("vulnerable.c");
    
    // Create a file with a real vulnerability
    fs::write(&test_file, r#"
#include <string.h>
#include <stdio.h>

void copy_input(char *buf, char *input) {
    strcpy(buf, input);  // Buffer overflow vulnerability
    printf("Copied: %s\n", buf);
}
"#).unwrap();

    // Create mock responses that trigger tool usage
    let responses = vec![
        // First turn: tool call to read the file
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in copy_input",
                "description": "Buffer overflow vulnerability due to unsafe strcpy usage",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 6,
                "code_snippet": "strcpy(buf, input);"
            }"#,
            "test-model",
            vec![make_file_read_tool(test_file.to_str().unwrap())],
        ),
        // Second turn: final finding (no tool calls)
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in copy_input",
                "description": "Buffer overflow vulnerability due to unsafe strcpy usage on line 6. The strcpy function does not check buffer bounds.",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 6,
                "code_snippet": "strcpy(buf, input);"
            }"#,
            "test-model",
            vec![],
        ),
    ];

    let mock_client = create_agent_mock_client(responses);
    let config = AgentConfig {
        enabled: true,
        max_turns: 3,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let progress_cb = Arc::new(|msg| {
        tracing::debug!("Progress: {}", msg);
    });

    let session = AgentSession::new(
        mock_client,
        &config,
        temp_dir.path(),
        progress_cb,
    );

    let result = session.analyze_file(test_file.to_str().unwrap()).await;
    
    assert!(result.is_ok(), "Agent analysis should succeed");
    let finding = result.unwrap();
    
    // Verify finding was created
    assert!(!finding.finding.title.is_empty(), "Title should be populated");
    assert!(!finding.finding.description.is_empty(), "Description should be populated");
    assert_eq!(finding.agent_turns, 2, "Should have completed 2 turns");
    assert!(finding.tools_used.contains(&"file_read".to_string()), "file_read tool should be tracked");
}

/// Test 10: Tool usage tracking - verify tools are actually called
#[tokio::test]
async fn test_tool_usage_tracking() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    fs::write(&test_file, "void test() { char buf[10]; }").unwrap();

    // Mock that uses multiple tools
    let responses = vec![
        make_chat_response(
            "Initial analysis",
            "test-model",
            vec![make_file_read_tool("test.c")],
        ),
        make_chat_response(
            "Pattern search",
            "test-model",
            vec![make_pattern_search_tool("strcpy", "")],
        ),
        make_chat_response(
            r#"{
                "title": "No Issues Found",
                "description": "After thorough analysis using file_read and pattern_search tools, no vulnerabilities detected",
                "severity": "Low",
                "cwe_id": "",
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
        max_turns: 5,
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
    
    // Verify all tools were tracked
    assert!(finding.tools_used.contains(&"file_read".to_string()));
    assert!(finding.tools_used.contains(&"pattern_search".to_string()));
    assert_eq!(finding.tools_used.len(), 2, "Should have tracked exactly 2 tools");
    assert_eq!(finding.agent_turns, 3, "Should have completed 3 turns");
}

/// Test 11: Multiple tool calls in single turn are tracked
#[tokio::test]
async fn test_multiple_tool_calls_per_turn_tracked() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    fs::write(&test_file, "void test() {}").unwrap();

    let responses = vec![
        make_chat_response(
            "Multi-tool analysis",
            "test-model",
            vec![
                make_file_read_tool("test.c"),
                make_pattern_search_tool("unsafe", ""),
                make_file_write_tool("test.c", "test"),
            ],
        ),
        make_chat_response(
            r#"{
                "title": "Analysis Complete",
                "description": "Used file_read, pattern_search, and file_write tools",
                "severity": "Low",
                "cwe_id": "",
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
        max_turns: 3,
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
    
    // All three tools should be tracked even though called in same turn
    assert!(finding.tools_used.contains(&"file_read".to_string()));
    assert!(finding.tools_used.contains(&"pattern_search".to_string()));
    assert!(finding.tools_used.contains(&"file_write".to_string()));
    assert_eq!(finding.tools_used.len(), 3);
}
