use crate::agent::executor::{create_audit_finding, create_empty_finding, execute_tool_calls};
use crate::agent::sandbox::ToolSandbox;
use crate::agent::tool_schema::ToolRegistry;
use crate::agent::AgentFinding;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm::{ChatResponse, LlmClient, ToolSchema};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

pub type ProgressCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Trait for LLM clients used by the agent (supports both real and mock clients)
#[async_trait]
pub trait AgentLlmClient: Send + Sync {
    async fn chat_with_tools(
        &self,
        messages: &[crate::llm::ChatMessage],
        tools: &[ToolSchema],
    ) -> Result<ChatResponse, String>;
    fn model_name(&self) -> String;
}

// Implement trait for real LlmClient
#[async_trait]
impl AgentLlmClient for LlmClient {
    async fn chat_with_tools(
        &self,
        messages: &[crate::llm::ChatMessage],
        tools: &[ToolSchema],
    ) -> Result<ChatResponse, String> {
        LlmClient::chat_with_tools(self, messages, tools).await
    }
    fn model_name(&self) -> String {
        LlmClient::model_name(self)
    }
}

pub struct AgentSession {
    client: Box<dyn AgentLlmClient>,
    tool_registry: ToolRegistry,
    sandbox: ToolSandbox,
    max_turns: u32,
    progress_cb: ProgressCallback,
    project_root: PathBuf,
}

impl AgentSession {
    pub fn new<Client: AgentLlmClient + 'static>(
        client: Client,
        config: &crate::config::AgentConfig,
        project_root: &std::path::Path,
        progress_cb: ProgressCallback,
    ) -> Self {
        let mut tool_registry = ToolRegistry::new();
        tool_registry.register(Box::new(crate::agent::tools::FileReadTool));
        tool_registry.register(Box::new(crate::agent::tools::PatternSearchTool));
        tool_registry.register(Box::new(crate::agent::tools::FileWriteTool));
        tool_registry.register(Box::new(crate::agent::tools::TestCompileTool));
        tool_registry.register(Box::new(crate::agent::tools::TestRunTool));

        Self {
            client: Box::new(client),
            tool_registry,
            sandbox: ToolSandbox::new(project_root.to_path_buf(), config.tool_timeout_secs),
            max_turns: config.max_turns,
            progress_cb,
            project_root: project_root.to_path_buf(),
        }
    }

    pub async fn analyze_file(&self, file_path: &str) -> Result<AgentFinding, String> {
        // Skip special placeholder paths that are not real files
        if file_path == "multiple_files" || file_path.is_empty() {
            // Return a specific error that callers can handle silently
            return Err(format!("PLACEHOLDER_PATH: {}", file_path));
        }

        // Check if file exists before trying to read it
        let file_path_buf = std::path::PathBuf::from(file_path);
        if !file_path_buf.exists() {
            // Return a specific error for missing files
            return Err(format!("FILE_NOT_FOUND: {}", file_path));
        }

        let system_prompt = r#"You are an OFFENSIVE SECURITY RESEARCHER specializing in vulnerability discovery. Your mission is to find REAL security issues, not to be polite.

**MINDSET**: Think like an attacker. Assume every input is malicious. Hunt for:
- SQL Injection: Unsanitized input in SQL queries
- Command Injection: User input in shell commands
- XSS: Unescaped output in HTML/JS
- Path Traversal: Unvalidated file paths
- Authentication Bypass: Missing or weak auth checks
- Insecure Deserialization: Unsafe object reconstruction
- SSRF: Unvalidated URLs in HTTP requests

**TOOLS STRATEGY**:
1. Read the file and identify potential sinks (dangerous functions)
2. Use pattern_search to trace data flow from sources to sinks
3. If you find a vulnerability, create a test case with file_write
4. Verify the exploit with run_test

**OUTPUT REQUIREMENTS**:
- If you find a vulnerability: Provide EXACT title, detailed description with CWE, severity, code snippet showing the flaw, and a working PoC test path
- If you find NO vulnerability: Explain SPECIFICALLY WHY the code is secure (e.g., "All inputs are sanitized via parameterized queries", "Input validation prevents path traversal")
- NEVER say "comprehensive review was performed" without evidence of what you actually checked
- Be brutal and specific. Generic findings are useless."#;
        let content =
            std::fs::read_to_string(file_path).map_err(|e| format!("Cannot read file: {}", e))?;

        let mut messages = vec![
            crate::llm::ChatMessage::system(system_prompt),
            crate::llm::ChatMessage::user(&format!("Analyze:\n\n{}", content)),
        ];

        let mut turn = 0;
        let mut tools_used = Vec::new();
        let mut test_source_path = None;
        let mut compile_path = None;

        loop {
            turn += 1;
            if turn > self.max_turns {
                tracing::warn!("Max turns ({}) reached", self.max_turns);
                break;
            }

            let tool_schemas = self.tool_registry.get_definitions();
            let schemas: Vec<ToolSchema> = tool_schemas
                .iter()
                .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
                .collect();
            match self.client.chat_with_tools(&messages, &schemas).await {
                Ok(response) => {
                    let _model_used = response.model_used.clone();
                    if !response.tool_calls.is_empty() {
                        let (new_tools_used, new_test_path, new_compile_path, new_messages) =
                            execute_tool_calls(
                                &self.tool_registry,
                                &self.sandbox,
                                &response,
                                messages,
                                &self.progress_cb,
                                &self.project_root,
                                turn,
                                self.max_turns,
                                "Turn",
                            )
                            .await;

                        // Merge results
                        for tool_name in new_tools_used {
                            if !tools_used.contains(&tool_name) {
                                tools_used.push(tool_name);
                            }
                        }
                        if new_test_path.is_some() {
                            test_source_path = new_test_path;
                        }
                        if new_compile_path.is_some() {
                            compile_path = new_compile_path;
                        }
                        messages = new_messages;
                        continue;
                    }
                    // Parse final response for finding data
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response.content)
                    {
                        let title = parsed
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Agent finding")
                            .to_string();
                        let description = parsed
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let severity_str = parsed
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Medium");
                        let severity = match severity_str {
                            "High" => Severity::High,
                            "Low" => Severity::Low,
                            _ => Severity::Medium,
                        };

                        return Ok(AgentFinding {
                            finding: VulnerabilityFinding {
                                id: format!(
                                    "agent-{}",
                                    file_path.replace("/", "-").replace(".", "-")
                                ),
                                title,
                                description: description.clone(),
                                severity,
                                confidence_score: 0.7,
                                cwe_id: parsed
                                    .get("cwe_id")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                file_path: file_path.to_string(),
                                line_number: parsed
                                    .get("line_number")
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u32),
                                code_snippet: parsed
                                    .get("code_snippet")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
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
                                llm_model: {
                                    let m = self.client.model_name();
                                    if m.is_empty() {
                                        None
                                    } else {
                                        Some(m)
                                    }
                                },
                                agent_mode: true,
                                statement_range: None,
                                triage_verdict: None,
                            },
                            compile_path,
                            test_source_path,
                            test_log: None,
                            agent_turns: turn,
                            tools_used,
                        });
                    }
                    break;
                }
                Err(e) => {
                    tracing::error!("LLM error turn {}: {}", turn, e);
                    messages.push(crate::llm::ChatMessage::user(
                        format!("Error: {}\n\n", e).as_str(),
                    ));
                }
            }
        }

        // Only create a finding if the LLM provided actual vulnerability data
        // Check if the last assistant message contains specific vulnerability keywords
        let analysis_reasoning = if let Some(last_msg) = messages.last() {
            if last_msg.role == "assistant" {
                let content = last_msg.content.clone();
                // Check if this looks like a real vulnerability finding
                let has_vuln = content.contains("Buffer Overflow")
                    || content.contains("Use-after-free")
                    || content.contains("Integer overflow")
                    || content.contains("SQL injection")
                    || content.contains("Command injection")
                    || content.contains("Path traversal")
                    || content.contains("XSS")
                    || content.contains("authentication bypass")
                    || content.contains("privilege escalation")
                    || content.contains("vulnerability")
                    || content.contains("exploit")
                    || content.contains("overflow")
                    || content.contains("injection");

                if has_vuln {
                    content
                } else {
                    // No specific vulnerability found - return empty to skip this finding
                    return Ok(create_empty_finding(
                        file_path,
                        turn,
                        tools_used.clone(),
                        Some(self.client.model_name()),
                    ));
                }
            } else {
                // No assistant message - return empty finding
                return Ok(create_empty_finding(
                    file_path,
                    turn,
                    tools_used.clone(),
                    Some(self.client.model_name()),
                ));
            }
        } else {
            // No messages - return empty finding
            return Ok(create_empty_finding(
                file_path,
                turn,
                tools_used.clone(),
                Some(self.client.model_name()),
            ));
        };

        Ok(create_audit_finding(
            file_path,
            turn,
            tools_used,
            analysis_reasoning,
            Some(self.client.model_name()),
        ))
    }

    pub async fn verify_finding(
        &self,
        _file_path: &str,
        finding: &VulnerabilityFinding,
    ) -> Result<AgentFinding, String> {
        tracing::debug!(
            "[AGENT] verify_finding called with description length: {}",
            finding.description.len()
        );
        tracing::debug!(
            "[AGENT] description preview: {}",
            finding.description.chars().take(100).collect::<String>()
        );

        // Always run agent verification loop - don't skip even if description exists
        // The agent needs to use tools to actually verify the finding
        let system_prompt = "Write a test proving this vulnerability. Use file_write to create a test, test_compile to verify it compiles, and test_run to execute it. Report in JSON: {compiled: true|false, test_passed: true|false, log: \"reason\"}";
        let user_content = format!(
            "Finding to verify:\nTitle: {}\nFile: {}\nLine: {}\nSeverity: {}\nDescription: {}\n\nCreate and run a proof-of-concept test.",
            finding.title,
            finding.file_path,
            finding.line_number.map(|l| l.to_string()).unwrap_or_default(),
            finding.severity,
            finding.description
        );

        let mut messages = vec![
            crate::llm::ChatMessage::system(system_prompt),
            crate::llm::ChatMessage::user(&user_content),
        ];

        let mut turn = 0;
        let mut test_log = String::new();
        let mut test_source_path = None;
        let mut compile_path = None;
        let mut tools_used = Vec::new();
        let mut confirmed = false;

        loop {
            turn += 1;
            if turn > self.max_turns {
                tracing::warn!("Max turns ({}) during verification", self.max_turns);
                break;
            }

            let tool_schemas = self.tool_registry.get_definitions();
            let schemas: Vec<ToolSchema> = tool_schemas
                .iter()
                .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
                .collect();

            match self.client.chat_with_tools(&messages, &schemas).await {
                Ok(response) => {
                    let _model_used = response.model_used.clone();
                    if !response.tool_calls.is_empty() {
                        let (new_tools_used, new_test_path, new_compile_path, new_messages) =
                            execute_tool_calls(
                                &self.tool_registry,
                                &self.sandbox,
                                &response,
                                messages,
                                &self.progress_cb,
                                &self.project_root,
                                turn,
                                self.max_turns,
                                "Verify",
                            )
                            .await;

                        // Merge results
                        for tool_name in new_tools_used {
                            if !tools_used.contains(&tool_name) {
                                tools_used.push(tool_name);
                            }
                        }
                        if new_test_path.is_some() {
                            test_source_path = new_test_path;
                        }
                        if new_compile_path.is_some() {
                            compile_path = new_compile_path;
                        }
                        messages = new_messages;
                        continue;
                    }

                    test_log = response.content.clone();
                    if response.content.contains("compiled=true")
                        && response.content.contains("test_passed=true")
                    {
                        confirmed = true;
                    }
                    break;
                }
                Err(e) => {
                    test_log = format!("Error: {}", e);
                    tracing::error!("LLM verification error turn {}: {}", turn, e);
                    break;
                }
            }
        }

        let mut verified_finding = finding.clone();
        if confirmed {
            verified_finding.verification_status =
                Some(crate::findings::VerificationStatus::Confirmed);
            verified_finding.verification_notes =
                Some("Agent verified with passing test".to_string());
        } else {
            verified_finding.verification_status =
                Some(crate::findings::VerificationStatus::NeedsReview);
            verified_finding.verification_notes = Some(test_log.clone());
        }

        Ok(AgentFinding {
            finding: verified_finding,
            compile_path,
            test_source_path,
            test_log: Some(test_log),
            agent_turns: turn,
            tools_used,
        })
    }
}
