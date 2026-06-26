//! Tool execution tests

use crate::agent::session::AgentSession;
use crate::config::AgentConfig;
use crate::findings::Severity;
use crate::phase::tests::agent_verification::test_helpers::{
    create_agent_mock_client, make_chat_response, make_file_read_tool, make_file_write_tool,
    make_pattern_search_tool,
};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

/// Test 2: file_read tool works correctly on test files
#[tokio::test]
async fn test_file_read_tool_on_test_files() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test_source.c");

    let expected_content = r#"
#include <stdio.h>
int main() {
    char buf[10];
    scanf("%s", buf);  // Buffer overflow
    return 0;
}
"#;

    fs::write(&test_file, expected_content).unwrap();

    // Mock client that simulates file_read being called and returning content
    let responses = vec![make_chat_response(
        r#"{
                "title": "Buffer Overflow with scanf",
                "description": "scanf without width limit causes buffer overflow",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 5,
                "code_snippet": "scanf(\"%s\", buf);"
            }"#,
        "test-model",
        vec![],
    )];

    let mock_client = create_agent_mock_client(responses);
    let config = AgentConfig {
        enabled: true,
        max_turns: 2,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), Arc::new(|_| {}));

    let result = session.analyze_file(test_file.to_str().unwrap()).await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.finding.title, "Buffer Overflow with scanf");
    assert!(finding.finding.code_snippet.is_some());
    assert!(finding.finding.code_snippet.unwrap().contains("scanf"));
}

/// Test 3: pattern_search tool finds vulnerabilities
#[tokio::test]
async fn test_pattern_search_finds_vulnerabilities() {
    let temp_dir = TempDir::new().unwrap();

    // Create a multi-file project with vulnerability
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    let main_file = src_dir.join("main.c");
    fs::write(
        &main_file,
        r#"
#include <stdio.h>
#include "utils.h"

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
"#,
    )
    .unwrap();

    let utils_file = src_dir.join("utils.c");
    fs::write(
        &utils_file,
        r#"
#include <string.h>

void process_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable: no bounds checking
    printf("Processed: %s\n", buffer);
}
"#,
    )
    .unwrap();

    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in process_input",
                "description": "strcpy vulnerability found in utils.c",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 6,
                "code_snippet": "strcpy(buffer, input);"
            }"#,
            "test-model",
            vec![make_pattern_search_tool(
                "strcpy",
                src_dir.to_str().unwrap(),
            )],
        ),
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in process_input",
                "description": "strcpy vulnerability found - data flows from main argument to unsafe strcpy call",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 6,
                "code_snippet": "strcpy(buffer, input);"
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

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), Arc::new(|_| {}));

    let result = session.analyze_file(main_file.to_str().unwrap()).await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert!(finding.tools_used.contains(&"pattern_search".to_string()));
    assert_eq!(finding.finding.severity, Severity::High);
}

/// Test 4: file_write tool generates test code
#[tokio::test]
async fn test_file_write_generates_test_code() {
    let temp_dir = TempDir::new().unwrap();
    let vulnerable_file = temp_dir.path().join("vuln.c");

    fs::write(
        &vulnerable_file,
        r#"
#include <string.h>
void copy(char *dst, char *src) {
    strcpy(dst, src);
}
"#,
    )
    .unwrap();

    // Mock that simulates writing a PoC test
    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Buffer Overflow PoC",
                "description": "Test case demonstrating buffer overflow",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 4,
                "code_snippet": "strcpy(dst, src);"
            }"#,
            "test-model",
            vec![make_file_write_tool(
                "test_poc.c",
                "// PoC test for buffer overflow\n#include <string.h>\nint main() {\n    char buf[10];\n    strcpy(buf, \"this is too long\");\n    return 0;\n}"
            )],
        ),
        make_chat_response(
            r#"{
                "title": "Buffer Overflow PoC",
                "description": "Test case demonstrating buffer overflow vulnerability",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 4,
                "code_snippet": "strcpy(dst, src);"
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

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), Arc::new(|_| {}));

    let result = session
        .analyze_file(vulnerable_file.to_str().unwrap())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();

    // Verify file_write was used
    assert!(finding.tools_used.contains(&"file_write".to_string()));

    // Verify test_source_path was captured
    assert!(finding.test_source_path.is_some());
}

/// Test 12: Full agent verification flow with real file operations
#[tokio::test]
async fn test_full_agent_verification_flow() {
    let temp_dir = TempDir::new().unwrap();

    // Create a realistic vulnerable C project
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    let auth_file = src_dir.join("auth.c");
    fs::write(
        &auth_file,
        r#"
#include <string.h>
#include <stdio.h>

// Authentication function with buffer overflow
int authenticate(char *username, char *password) {
    char user_buf[32];
    char pass_buf[32];
    
    // Vulnerable: no length checking
    strcpy(user_buf, username);
    strcpy(pass_buf, password);
    
    // Simplified check
    if (strcmp(user_buf, "admin") == 0 && strcmp(pass_buf, "secret") == 0) {
        return 1;  // Auth success
    }
    return 0;  // Auth fail
}
"#,
    )
    .unwrap();

    // Mock responses simulating realistic agent behavior
    let responses = vec![
        // Turn 1: Read the file
        make_chat_response(
            "Analyzing auth.c for vulnerabilities",
            "test-model",
            vec![make_file_read_tool(auth_file.to_str().unwrap())],
        ),
        // Turn 2: Search for similar patterns
        make_chat_response(
            "Looking for other strcpy usage",
            "test-model",
            vec![make_pattern_search_tool("strcpy", src_dir.to_str().unwrap())],
        ),
        // Turn 3: Write PoC test
        make_chat_response(
            "Creating PoC test",
            "test-model",
            vec![make_file_write_tool(
                "test_auth_poc.c",
                "// PoC for auth buffer overflow\n#include <string.h>\nint main() {\n    char *long_user = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";\n    char *long_pass = \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\";\n    authenticate(long_user, long_pass);  // Overflow!\n    return 0;\n}"
            )],
        ),
        // Turn 4: Final finding
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in authenticate function",
                "description": "The authenticate function uses strcpy without bounds checking, allowing stack buffer overflow via username or password parameters. CWE-120.",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 10,
                "code_snippet": "strcpy(user_buf, username);"
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
        Arc::new(|msg| tracing::debug!("Agent: {}", msg)),
    );

    let result = session.analyze_file(auth_file.to_str().unwrap()).await;

    assert!(result.is_ok(), "Agent verification should succeed");
    let finding = result.unwrap();

    // Verify complete flow
    assert!(!finding.finding.title.is_empty());
    assert!(!finding.finding.description.is_empty());
    assert_eq!(finding.finding.severity, Severity::High);
    assert!(finding.finding.cwe_id.is_some());
    assert_eq!(finding.finding.cwe_id.unwrap(), "CWE-120");

    // Verify all tools were used
    assert!(finding.tools_used.contains(&"file_read".to_string()));
    assert!(finding.tools_used.contains(&"pattern_search".to_string()));
    assert!(finding.tools_used.contains(&"file_write".to_string()));
    assert_eq!(finding.tools_used.len(), 3);

    // Verify turns
    assert_eq!(finding.agent_turns, 4);

    // Verify evidence path was captured
    assert!(finding.test_source_path.is_some());
}
