#[cfg(test)]
mod tests {
    use baco::agent::mock_llm::MockLlmClient;
    use baco::agent::session::{AgentSession, ProgressCallback};
    use baco::config::AgentConfig;
    use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
    use baco::llm::ChatResponse;
    use serde_json::json;
    use std::sync::Arc;

    // NOTE: `test_agent_session_new` and `test_agent_session_tool_registry_initialization`
    // from the original inline block are commented out below because they read private
    // fields of `AgentSession` (`max_turns`, `sandbox`, `tool_registry`). External tests
    // can only access the crate's public API. To re-enable them, either expose the
    // fields via `pub` accessors on `AgentSession` or keep them as inline tests in
    // `src/agent/session.rs`.
    //
    // The commented-out `test_agent_session_new` also needs
    //     use baco::agent::tool_schema::SandboxLike;
    // in scope to call `.temp_dir()` on the sandbox. It is omitted from the active
    // imports above to avoid an unused-import warning.

    /*
    #[test]
    fn test_agent_session_new() {
        let mock_client = MockLlmClient::new(vec![]);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        assert_eq!(session.max_turns, 10);
        assert_eq!(session.sandbox.temp_dir(), tmpdir.path());
    }
    */

    #[tokio::test]
    async fn test_analyze_file_max_turns_reached() {
        let mock_client = MockLlmClient::new(vec![]);
        let config = AgentConfig {
            enabled: false,
            max_turns: 5,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        // Create a test file
        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();
        // Should have an empty finding since no LLM responses
        assert!(
            finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit")
        );
    }

    #[tokio::test]
    async fn test_analyze_file_with_mock_llm_tool_call() {
        let responses = vec![
            // First turn: tool call
            MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" })),
            // Second turn: final response with vulnerability
            MockLlmClient::mock_final_response(
                r#"{"title": "Buffer Overflow", "description": "Found buffer overflow", "severity": "High", "cwe_id": "CWE-120"}"#,
            ),
        ];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        // Create a test file
        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        // Should have parsed the JSON finding
        assert!(!finding.finding.title.is_empty());
        assert_eq!(finding.agent_turns, 2);
        assert!(!finding.tools_used.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_with_mock_llm_no_vulnerability() {
        let responses = vec![
            // Single response indicating no vulnerability
            ChatResponse {
                content: "After reviewing the code, no security vulnerabilities were found. All inputs are properly validated.".to_string(),
                tool_calls: vec![],
                raw: json!({}),
                model_used: "mock".to_string(),
            },
        ];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        // Create a test file
        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        // Should have an audit finding
        assert!(
            finding.finding.title.contains("Security Audit") || finding.finding.title.is_empty()
        );
    }

    #[tokio::test]
    async fn test_verify_finding_with_mock_llm() {
        let responses = vec![
            // First turn: tool call to write test
            MockLlmClient::mock_tool_call(
                "file_write",
                json!({ "path": "poc.py", "content": "print('exploit')" }),
            ),
            // Second turn: verification result
            ChatResponse {
                content: "compiled=true\ntest_passed=true\nTest successfully demonstrated the vulnerability".to_string(),
                tool_calls: vec![],
                raw: json!({}),
                model_used: "mock".to_string(),
            },
        ];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let finding = VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test Vulnerability".to_string(),
            description: "A test vulnerability".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: Some(42),
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
            agent_mode: true,
            statement_range: None,
            triage_verdict: None,
        };

        let result = session.verify_finding("test.rs", &finding).await;
        assert!(result.is_ok());
        let verified = result.unwrap();

        assert_eq!(verified.agent_turns, 2);
        assert!(!verified.tools_used.is_empty());
        assert!(verified.test_log.is_some());
    }

    #[tokio::test]
    async fn test_verify_finding_unconfirmed() {
        let responses = vec![ChatResponse {
            content: "Could not reproduce the vulnerability. Test compilation failed.".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        }];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let finding = VulnerabilityFinding {
            id: "test-2".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
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
            agent_mode: true,
            statement_range: None,
            triage_verdict: None,
        };

        let result = session.verify_finding("test.rs", &finding).await;
        assert!(result.is_ok());
        let verified = result.unwrap();

        // Should be marked as NeedsReview since not confirmed
        assert_eq!(
            verified.finding.verification_status,
            Some(VerificationStatus::NeedsReview)
        );
    }

    #[test]
    fn test_progress_callback_type() {
        // Verify that ProgressCallback can be created and called
        let cb: ProgressCallback = Arc::new(|_msg| {
            // Note: This test demonstrates the limitation - the closure cannot modify outer vars
            // In real usage, ProgressCallback would use channels or other mechanisms
        });

        cb("test message".to_string());
        // Just verify the callback can be created and invoked without panicking
    }

    #[tokio::test]
    async fn test_analyze_file_llm_error_handling() {
        // Test that LLM errors are handled gracefully and messages are updated
        let responses = vec![
            ChatResponse {
                content: "Error: rate limit exceeded".to_string(),
                tool_calls: vec![],
                raw: json!({}),
                model_used: "mock".to_string(),
            },
            ChatResponse {
                content: "After reviewing, no vulnerabilities found.".to_string(),
                tool_calls: vec![],
                raw: json!({}),
                model_used: "mock".to_string(),
            },
        ];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();
        // Should have an audit finding after recovery from error
        assert!(
            finding.finding.title.contains("Security Audit") || finding.finding.title.is_empty()
        );
    }

    #[tokio::test]
    async fn test_analyze_file_with_high_severity() {
        let responses = vec![MockLlmClient::mock_final_response(
            r#"{"title": "Buffer Overflow", "description": "Found buffer overflow in strcpy", "severity": "High", "cwe_id": "CWE-120", "line_number": 42}"#,
        )];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        assert_eq!(finding.finding.severity, Severity::High);
        assert_eq!(finding.finding.line_number, Some(42));
        assert_eq!(finding.finding.cwe_id, Some("CWE-120".to_string()));
    }

    #[tokio::test]
    async fn test_analyze_file_with_low_severity() {
        let responses = vec![MockLlmClient::mock_final_response(
            r#"{"title": "Information Disclosure", "description": "Debug info exposed", "severity": "Low"}"#,
        )];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        assert_eq!(finding.finding.severity, Severity::Low);
    }

    #[tokio::test]
    async fn test_analyze_file_with_medium_severity_default() {
        let responses = vec![MockLlmClient::mock_final_response(
            r#"{"title": "Missing Input Validation", "description": "Input not validated"}"#,
        )];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        // Default severity is Medium
        assert_eq!(finding.finding.severity, Severity::Medium);
    }

    #[tokio::test]
    async fn test_verify_finding_max_turns_reached() {
        // Keep returning tool calls until max turns reached
        let responses: Vec<ChatResponse> = (0..20)
            .map(|i| {
                MockLlmClient::mock_tool_call(
                    "file_write",
                    json!({ "path": format!("test{}.py", i), "content": "print('test')" }),
                )
            })
            .collect();

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 5,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let finding = VulnerabilityFinding {
            id: "test-3".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
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
            agent_mode: true,
            statement_range: None,
            triage_verdict: None,
        };

        let result = session.verify_finding("test.rs", &finding).await;
        assert!(result.is_ok());
        let verified = result.unwrap();

        // Should stop at or around max_turns (may be one more due to loop structure)
        assert!(verified.agent_turns >= 5 && verified.agent_turns <= 6);
    }

    #[tokio::test]
    async fn test_verify_finding_llm_error() {
        // LLM returns error immediately
        let responses = vec![ChatResponse {
            content: "Error: model unavailable".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        }];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let finding = VulnerabilityFinding {
            id: "test-4".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
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
            agent_mode: true,
            statement_range: None,
            triage_verdict: None,
        };

        let result = session.verify_finding("test.rs", &finding).await;
        assert!(result.is_ok());
        let verified = result.unwrap();

        // Should have error in test_log and be NeedsReview
        assert!(verified.test_log.is_some());
        assert!(verified.test_log.unwrap().contains("Error"));
        assert_eq!(
            verified.finding.verification_status,
            Some(VerificationStatus::NeedsReview)
        );
    }

    /*
    #[test]
    fn test_agent_session_tool_registry_initialization() {
        let mock_client = MockLlmClient::new(vec![]);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        // Verify tool registry has expected tools - definitions are populated by default_tools()
        // but new() only registers tools without definitions
        let definitions = session.tool_registry.get_definitions();
        // Note: new() registers tools but doesn't populate definitions
        // This test verifies that the registry can be created
        let _ = definitions.len(); // Just verify it exists
    }
    */

    #[tokio::test]
    async fn test_analyze_file_empty_response() {
        // LLM returns empty content
        let responses = vec![ChatResponse {
            content: "".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        }];

        let mock_client = MockLlmClient::new(responses);
        let config = AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        };
        let tmpdir = tempfile::tempdir().unwrap();
        let progress_cb = Arc::new(|_| {});

        let test_file = tmpdir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

        let result = session
            .analyze_file(test_file.to_string_lossy().as_ref())
            .await;
        assert!(result.is_ok());
        let finding = result.unwrap();

        // Empty response should result in empty finding or audit finding
        assert!(
            finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit")
        );
    }
}
