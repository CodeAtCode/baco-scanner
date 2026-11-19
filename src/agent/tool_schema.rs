use crate::agent::ToolResult;
use serde_json::json;
use std::collections::HashMap;

pub trait SandboxLike: Send + Sync {
    fn temp_dir(&self) -> &std::path::Path;
    fn resolve_safe_path(&self, path: &str) -> Result<std::path::PathBuf, String>;
    fn run_with_timeout(
        &self,
        command: &str,
        args: &[&str],
        timeout_secs: Option<u64>,
    ) -> Result<ToolResult, String>;
    fn validate_test_source(&self, path: &str, content: &str) -> Result<(), String>;
    fn create_temp_file(&self, path: &str, content: &str) -> Result<std::path::PathBuf, String>;
    fn is_path_allowed(&self, path: &std::path::Path) -> bool;
}

pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String>;
}

pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
    definitions: Vec<serde_json::Value>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            definitions: Vec::new(),
        }
    }
    pub fn register(&mut self, tool: Box<dyn Tool>) {
        let name = tool.name().to_string();
        self.tools.insert(name, tool);
    }
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|b| b.as_ref())
    }
    pub fn get_definitions(&self) -> &[serde_json::Value] {
        &self.definitions
    }
}

/// Build the registry of agent tools.
///
/// `allow_run` decides whether the code-executing `test_run` tool is offered at
/// all. With it false the tool is neither registered nor advertised, so the
/// model cannot ask for generated code to be run on the host — the capability
/// is absent rather than refused, because a refusal still spends a turn.
pub fn default_tools(allow_run: bool) -> ToolRegistry {
    let mut reg = ToolRegistry::new();
    reg.register(Box::new(super::tools::FileReadTool));
    reg.register(Box::new(super::tools::PatternSearchTool));
    reg.register(Box::new(super::tools::FileWriteTool));
    reg.register(Box::new(super::tools::TestCompileTool));
    if allow_run {
        reg.register(Box::new(super::tools::TestRunTool));
    }
    reg.definitions = tool_definitions(allow_run);
    reg
}

pub fn tool_definitions(allow_run: bool) -> Vec<serde_json::Value> {
    let mut definitions = vec![
        json!({"type": "function", "function": {
            "name": "file_read", "description": "Read file content from the project",
            "parameters": {"type": "object", "properties": {
                "path": {"type": "string", "description": "Path relative to project root"},
                "start_line": {"type": "integer", "description": "Start line (1-based, optional)"},
                "end_line": {"type": "integer", "description": "End line inclusive (optional)"}
            }, "required": ["path"]}
        }}),
        json!({"type": "function", "function": {
            "name": "pattern_search", "description": "Search for regex pattern in project files",
            "parameters": {"type": "object", "properties": {
                "pattern": {"type": "string", "description": "Regex pattern"},
                "path": {"type": "string", "description": "Directory to search"},
                "context_lines": {"type": "integer", "description": "Context lines (default 2)"}
            }, "required": ["pattern", "path"]}
        }}),
        json!({"type": "function", "function": {
            "name": "file_write", "description": "Write a file inside the project root",
            "parameters": {"type": "object", "properties": {
                "path": {"type": "string", "description": "Filename (placed in sandbox tempdir)"},
                "content": {"type": "string", "description": "File content"}
            }, "required": ["path", "content"]}
        }}),
        json!({"type": "function", "function": {
            "name": "test_compile", "description": "Compile a test source file (language parameter required)",
            "parameters": {"type": "object", "properties": {
                "source_path": {"type": "string", "description": "Path in sandbox tempdir"},
                "language": {"type": "string", "enum": ["rust", "python", "c", "cpp"]}
            }, "required": ["source_path", "language"]}
        }}),
    ];
    if allow_run {
        definitions.push(json!({"type": "function", "function": {
            "name": "test_run", "description": "Run a compiled test or script",
            "parameters": {"type": "object", "properties": {
                "executable_path": {"type": "string", "description": "Path to executable or script"},
                "timeout_secs": {"type": "integer", "description": "Timeout (default from config)"}
            }, "required": ["executable_path"]}
        }}));
    }
    definitions
}
