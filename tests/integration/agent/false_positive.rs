//! False positive detection tests

use crate::agent::session::AgentSession;
use crate::config::AgentConfig;
use crate::findings::Severity;
use crate::phase::tests::agent_verification::test_helpers::{
    create_agent_mock_client, make_chat_response, make_run_test_tool,
};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

/// Test 8: False positive detection - agent removes finding when tests pass
#[tokio::test]
async fn test_false_positive_detection_tests_pass() {
    let temp_dir = TempDir::new().unwrap();

    // Create a SAFE version of the code
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    fs::write(
        src_dir.join("lib.rs"),
        r#"
pub fn safe_copy(dst: &mut [u8], src: &[u8]) {
    // Safe: uses min to prevent overflow
    let len = src.len().min(dst.len());
    dst[..len].copy_from_slice(&src[..len]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_copy() {
        let mut dst = [0u8; 5];
        let src = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8];
        safe_copy(&mut dst, &src);  // Should NOT panic
        assert_eq!(dst, [1, 2, 3, 4, 5]);
    }
}
"#,
    )
    .unwrap();

    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Potential Buffer Overflow",
                "description": "Checking if copy function is safe",
                "severity": "Medium",
                "cwe_id": "CWE-120",
                "line_number": 3,
                "code_snippet": "dst[..len].copy_from_slice(&src[..len]);"
            }"#,
            "test-model",
            vec![make_run_test_tool("cargo test")],
        ),
        make_chat_response(
            r#"{
                "title": "No Vulnerability Found",
                "description": "After running tests, the code is confirmed safe. The copy function uses proper bounds checking.",
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
        tool_timeout_secs: 60,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), Arc::new(|_| {}));

    let result = session
        .analyze_file(src_dir.join("lib.rs").to_str().unwrap())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();

    // Agent should conclude no vulnerability
    assert!(
        finding.finding.title.contains("No Vulnerability")
            || finding.finding.severity == Severity::Low
    );
}

/// Test 9: True positive detection - agent keeps finding when tests fail
#[tokio::test]
async fn test_true_positive_detection_tests_fail() {
    let temp_dir = TempDir::new().unwrap();

    // Create vulnerable code with failing test
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    fs::write(
        src_dir.join("lib.rs"),
        r#"
pub fn unsafe_copy(dst: &mut [u8], src: &[u8]) {
    // UNSAFE: no bounds checking
    for (i, &byte) in src.iter().enumerate() {
        dst[i] = byte;  // Panics if src > dst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_unsafe_copy_panics() {
        let mut dst = [0u8; 5];
        let src = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8];  // Too long!
        unsafe_copy(&mut dst, &src);  // WILL panic
    }
}
"#,
    )
    .unwrap();

    let responses = vec![
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in unsafe_copy",
                "description": "Function does not check bounds before writing",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 4,
                "code_snippet": "dst[i] = byte;"
            }"#,
            "test-model",
            vec![make_run_test_tool("cargo test")],
        ),
        make_chat_response(
            r#"{
                "title": "Buffer Overflow in unsafe_copy",
                "description": "Test confirmed the vulnerability - function panics with oversized input. This is a true positive.",
                "severity": "High",
                "cwe_id": "CWE-120",
                "line_number": 4,
                "code_snippet": "dst[i] = byte;"
            }"#,
            "test-model",
            vec![],
        ),
    ];

    let mock_client = create_agent_mock_client(responses);
    let config = AgentConfig {
        enabled: true,
        max_turns: 3,
        tool_timeout_secs: 60,
        trusted_paths: vec![],
        keep_artifacts: false,
    };

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), Arc::new(|_| {}));

    let result = session
        .analyze_file(src_dir.join("lib.rs").to_str().unwrap())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();

    // Agent should confirm the vulnerability
    assert_eq!(finding.finding.severity, Severity::High);
    assert!(
        finding.finding.description.contains("true positive")
            || finding.finding.description.contains("confirmed")
    );
}
