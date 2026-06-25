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
