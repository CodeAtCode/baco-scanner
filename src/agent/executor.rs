//! Tool execution helper to avoid duplication in session.rs

use crate::agent::sandbox::ToolSandbox;
use crate::agent::tool_schema::ToolRegistry;
use crate::agent::AgentFinding;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm::{ChatMessage, ChatResponse};
use std::path::PathBuf;
use std::sync::Arc;

pub type ProgressCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Create an empty AgentFinding with default values
pub fn create_empty_finding(
    file_path: &str,
    turn: u32,
    tools_used: Vec<String>,
    model_name: Option<String>,
) -> AgentFinding {
    AgentFinding {
        finding: VulnerabilityFinding {
            id: String::new(),
            title: String::new(),
            description: String::new(),
            severity: Severity::Low,
            confidence_score: 0.0,
            cwe_id: None,
            file_path: file_path.to_string(),
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
            llm_model: model_name.filter(|m| !m.is_empty()),
            agent_mode: true,
        },
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: turn,
        tools_used,
    }
}

/// Create a security audit finding (no vulnerabilities detected)
pub fn create_audit_finding(
    file_path: &str,
    turn: u32,
    tools_used: Vec<String>,
    analysis_reasoning: String,
    model_name: Option<String>,
) -> AgentFinding {
    AgentFinding {
        finding: VulnerabilityFinding {
            id: format!("agent-{}", turn),
            title: "Security Audit - No Critical Vulnerabilities Detected".to_string(),
            description: analysis_reasoning,
            severity: Severity::Medium,
            confidence_score: 0.7,
            cwe_id: None,
            file_path: file_path.to_string(),
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
            llm_model: model_name.filter(|m| !m.is_empty()),
            agent_mode: true,
        },
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: turn,
        tools_used,
    }
}

/// Execute tool calls from an LLM response and update messages
/// Returns: (tools_used, test_source_path, compile_path, updated_messages)
#[allow(clippy::too_many_arguments)]
pub async fn execute_tool_calls(
    tool_registry: &ToolRegistry,
    sandbox: &ToolSandbox,
    response: &ChatResponse,
    mut messages: Vec<ChatMessage>,
    progress_cb: &ProgressCallback,
    project_root: &std::path::Path,
    turn: u32,
    max_turns: u32,
    turn_label: &str,
) -> (
    Vec<String>,
    Option<PathBuf>,
    Option<PathBuf>,
    Vec<ChatMessage>,
) {
    let mut tools_used = Vec::new();
    let mut test_source_path = None;
    let mut compile_path = None;

    for tool_call in &response.tool_calls {
        if let Some(tool) = tool_registry.get(&tool_call.name) {
            // Track which tools are used
            if !tools_used.contains(&tool_call.name) {
                tools_used.push(tool_call.name.clone());
            }

            let result = tool.execute(tool_call.arguments.clone(), sandbox);
            let result_str = match &result {
                Ok(r) => format!("Tool {} result: {}\n\n", r.success, r.output),
                Err(e) => format!("Tool {} error: {}\n\n", tool_call.name, e),
            };

            // Capture test source path if file_write was used
            if tool_call.name == "file_write" {
                if let Some(path) = tool_call.arguments.get("path").and_then(|v| v.as_str()) {
                    test_source_path = Some(project_root.join(path));
                }
            }

            // Capture compile path if test_compile was used
            if tool_call.name == "test_compile" {
                if let Some(path) = tool_call
                    .arguments
                    .get("source_path")
                    .and_then(|v| v.as_str())
                {
                    compile_path = Some(project_root.join(path));
                }
            }

            messages.push(ChatMessage::assistant(
                format!(
                    "Calling: {}\nArgs: {:#}",
                    tool_call.name, tool_call.arguments
                )
                .as_str(),
            ));
            messages.push(ChatMessage::user(result_str.as_str()));
        }
    }

    progress_cb(format!("{} {}/{}", turn_label, turn, max_turns));

    (tools_used, test_source_path, compile_path, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::sandbox::ToolSandbox;
    use crate::agent::tool_schema::ToolRegistry;
    use crate::agent::ToolCall;
    use std::sync::Arc;

    #[test]
    fn test_create_empty_finding() {
        let finding = create_empty_finding(
            "test.rs",
            1,
            vec!["tool1".to_string()],
            Some("test-model".to_string()),
        );

        assert!(finding.finding.id.is_empty());
        assert!(finding.finding.title.is_empty());
        assert!(finding.finding.description.is_empty());
        assert_eq!(finding.finding.severity, Severity::Low);
        assert_eq!(finding.finding.confidence_score, 0.0);
        assert_eq!(finding.finding.file_path, "test.rs");
        assert!(finding.finding.line_number.is_none());
        assert_eq!(finding.agent_turns, 1);
        assert_eq!(finding.tools_used, vec!["tool1".to_string()]);
        assert_eq!(finding.finding.llm_model, Some("test-model".to_string()));
        assert!(finding.finding.agent_mode);
    }

    #[test]
    fn test_create_empty_finding_no_model() {
        let finding = create_empty_finding("test.rs", 1, vec![], None);

        assert!(finding.finding.llm_model.is_none());
        assert_eq!(finding.agent_turns, 1);
    }

    #[test]
    fn test_create_audit_finding() {
        let reasoning = "No vulnerabilities found after thorough analysis";
        let finding = create_audit_finding(
            "test.rs",
            2,
            vec!["file_read".to_string()],
            reasoning.to_string(),
            Some("model".to_string()),
        );

        assert!(finding.finding.id.starts_with("agent-"));
        assert_eq!(
            finding.finding.title,
            "Security Audit - No Critical Vulnerabilities Detected"
        );
        assert_eq!(finding.finding.description, reasoning);
        assert_eq!(finding.finding.severity, Severity::Medium);
        assert_eq!(finding.finding.confidence_score, 0.7);
        assert_eq!(finding.finding.file_path, "test.rs");
        assert_eq!(finding.agent_turns, 2);
        assert_eq!(finding.tools_used, vec!["file_read".to_string()]);
    }

    #[test]
    fn test_create_audit_finding_no_model() {
        let finding = create_audit_finding("test.rs", 1, vec![], "reasoning".to_string(), None);

        assert!(finding.finding.llm_model.is_none());
    }

    #[tokio::test]
    async fn test_execute_tool_calls_single_tool() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::FileReadTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("test.txt");
        std::fs::write(&path, "hello").unwrap();

        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "test.txt" }),
            }],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, test_path, compile_path, messages) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert_eq!(tools_used, vec!["file_read".to_string()]);
        assert!(test_path.is_none());
        assert!(compile_path.is_none());
        assert_eq!(messages.len(), 3); // original + assistant call + user result
    }

    #[tokio::test]
    async fn test_execute_tool_calls_file_write_path_capture() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::FileWriteTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".to_string()),
                name: "file_write".to_string(),
                arguments: serde_json::json!({ "path": "test.rs", "content": "fn main() {}" }),
            }],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, test_path, compile_path, _) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert_eq!(tools_used, vec!["file_write".to_string()]);
        assert!(test_path.is_some());
        assert!(compile_path.is_none());
    }

    #[tokio::test]
    async fn test_execute_tool_calls_test_compile_path_capture() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::TestCompileTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".to_string()),
                name: "test_compile".to_string(),
                arguments: serde_json::json!({ "source_path": "test.rs", "language": "rust" }),
            }],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, test_path, compile_path, _) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert_eq!(tools_used, vec!["test_compile".to_string()]);
        assert!(test_path.is_none());
        assert!(compile_path.is_some());
    }

    #[tokio::test]
    async fn test_execute_tool_calls_unknown_tool() {
        let registry = ToolRegistry::new();
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".to_string()),
                name: "unknown_tool".to_string(),
                arguments: serde_json::json!({}),
            }],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, _, _, messages) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert!(tools_used.is_empty());
        assert_eq!(messages.len(), 1); // No new messages since tool not found
    }

    #[tokio::test]
    async fn test_execute_tool_calls_tool_error() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::FileReadTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "nonexistent.txt" }),
            }],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (_, _, _, messages) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        // Should have assistant call + user error message
        assert_eq!(messages.len(), 3);
        assert!(messages[2].content.contains("error"));
    }

    #[tokio::test]
    async fn test_execute_tool_calls_multiple_tools() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::FileReadTool));
        registry.register(Box::new(crate::agent::tools::FileWriteTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![
                ToolCall {
                    id: Some("call_1".to_string()),
                    name: "file_read".to_string(),
                    arguments: serde_json::json!({ "path": "test.txt" }),
                },
                ToolCall {
                    id: Some("call_2".to_string()),
                    name: "file_write".to_string(),
                    arguments: serde_json::json!({ "path": "out.txt", "content": "test" }),
                },
            ],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, test_path, _, _) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert_eq!(tools_used.len(), 2);
        assert!(tools_used.contains(&"file_read".to_string()));
        assert!(tools_used.contains(&"file_write".to_string()));
        assert!(test_path.is_some());
    }

    #[tokio::test]
    async fn test_execute_tool_calls_duplicate_tool_calls() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(crate::agent::tools::FileReadTool));

        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        // Same tool called twice
        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![
                ToolCall {
                    id: Some("call_1".to_string()),
                    name: "file_read".to_string(),
                    arguments: serde_json::json!({ "path": "test1.txt" }),
                },
                ToolCall {
                    id: Some("call_2".to_string()),
                    name: "file_read".to_string(),
                    arguments: serde_json::json!({ "path": "test2.txt" }),
                },
            ],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, _, _, _) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        // Should only track tool once even if called multiple times
        assert_eq!(tools_used.len(), 1);
        assert_eq!(tools_used[0], "file_read");
    }

    #[tokio::test]
    async fn test_execute_tool_calls_empty_tool_calls() {
        let registry = ToolRegistry::new();
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let progress_cb: ProgressCallback = Arc::new(|_| {});

        let response = ChatResponse {
            content: "".to_string(),
            tool_calls: vec![],
            raw: serde_json::json!({}),
            model_used: "test".to_string(),
        };

        let messages = vec![ChatMessage::user("test")];

        let (tools_used, test_path, compile_path, messages) = execute_tool_calls(
            &registry,
            &sandbox,
            &response,
            messages,
            &progress_cb,
            tmpdir.path(),
            1,
            10,
            "Turn",
        )
        .await;

        assert!(tools_used.is_empty());
        assert!(test_path.is_none());
        assert!(compile_path.is_none());
        assert_eq!(messages.len(), 1); // No changes
    }

    #[test]
    fn test_create_empty_finding_all_defaults() {
        let finding = create_empty_finding("test.rs", 0, vec![], None);

        assert!(finding.finding.id.is_empty());
        assert!(finding.finding.title.is_empty());
        assert!(finding.finding.description.is_empty());
        assert_eq!(finding.finding.severity, Severity::Low);
        assert_eq!(finding.finding.confidence_score, 0.0);
        assert_eq!(finding.agent_turns, 0);
        assert!(finding.tools_used.is_empty());
        assert!(finding.finding.llm_model.is_none());
        assert!(finding.finding.agent_mode);
    }

    #[test]
    fn test_create_audit_finding_all_defaults() {
        let finding = create_audit_finding("test.rs", 0, vec![], "No issues".to_string(), None);

        assert!(finding.finding.id.starts_with("agent-"));
        assert!(finding.finding.title.contains("Security Audit"));
        assert_eq!(finding.finding.description, "No issues");
        assert_eq!(finding.finding.severity, Severity::Medium);
        assert_eq!(finding.finding.confidence_score, 0.7);
        assert_eq!(finding.agent_turns, 0);
        assert!(finding.finding.llm_model.is_none());
    }
}
