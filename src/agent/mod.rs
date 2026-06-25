pub mod executor;
pub mod sandbox;
pub mod session;
pub mod tool_schema;
pub mod tools;

use crate::findings::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

pub type ProgressCallback = Box<dyn Fn(String) + Send + Sync>;

pub use session::AgentSession;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub output: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub finding: VulnerabilityFinding,
    #[serde(default)]
    pub compile_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub test_source_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub test_log: Option<String>,
    #[serde(default)]
    pub agent_turns: u32,
    #[serde(default)]
    pub tools_used: Vec<String>,
}

impl AgentFinding {
    pub fn into_finding(self) -> VulnerabilityFinding {
        let mut f = self.finding;

        let evidence_path = self
            .test_source_path
            .map(|p| p.to_string_lossy().into_owned())
            .or_else(|| self.compile_path.map(|p| p.to_string_lossy().into_owned()));

        if let Some(path) = evidence_path {
            f.agent_evidence_path = Some(path);
        } else if self.agent_turns > 0 {
            f.agent_evidence_path = Some(format!(
                "{} turns, {} tools",
                self.agent_turns,
                self.tools_used.len()
            ));
        }

        if let Some(ref log) = self.test_log {
            if f.verification_notes.is_none() {
                f.verification_notes = Some(log.clone());
            }
        }

        f
    }
}
pub mod mock_llm;
