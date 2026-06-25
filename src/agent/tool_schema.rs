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
    fn validate_test_source(&self, content: &str) -> Result<(), String>;
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

pub fn default_tools() -> ToolRegistry {
    let mut reg = ToolRegistry::new();
    reg.register(Box::new(super::tools::FileReadTool));
    reg.register(Box::new(super::tools::PatternSearchTool));
    reg.register(Box::new(super::tools::FileWriteTool));
    reg.register(Box::new(super::tools::TestCompileTool));
    reg.register(Box::new(super::tools::TestRunTool));
    reg
}

pub fn tool_definitions() -> Vec<serde_json::Value> {
    vec![
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
            "name": "file_write", "description": "Write file to sandbox temp directory only",
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
        json!({"type": "function", "function": {
            "name": "test_run", "description": "Run a compiled test or script",
            "parameters": {"type": "object", "properties": {
                "executable_path": {"type": "string", "description": "Path to executable or script"},
                "timeout_secs": {"type": "integer", "description": "Timeout (default from config)"}
            }, "required": ["executable_path"]}
        }}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_registry_registration() {
        let mut registry = ToolRegistry::new();
        let mock_tool = MockTool {};
        registry.register(Box::new(mock_tool));

        assert!(registry.get("mock_tool").is_some());
    }

    #[test]
    fn test_tool_registry_get_definitions() {
        let definitions = tool_definitions();
        assert_eq!(definitions.len(), 5);

        for def in &definitions {
            let func = def["function"].as_object().unwrap();
            assert!(func.contains_key("name"));
            assert!(func.contains_key("description"));
            assert!(func.contains_key("parameters"));
        }
    }

    #[test]
    fn test_tool_definitions_contains_all_tools() {
        let definitions = tool_definitions();
        let names: Vec<&str> = definitions
            .iter()
            .flat_map(|d| d["function"].as_object().unwrap().get("name"))
            .filter_map(|v| v.as_str())
            .collect();

        assert!(names.contains(&"file_read"));
        assert!(names.contains(&"pattern_search"));
        assert!(names.contains(&"file_write"));
        assert!(names.contains(&"test_compile"));
        assert!(names.contains(&"test_run"));
    }

    #[test]
    fn test_file_read_schema_has_required_path() {
        let defs = tool_definitions();
        let file_read = defs
            .iter()
            .find(|d| d["function"]["name"].as_str() == Some("file_read"))
            .unwrap();

        let params = file_read["function"]["parameters"].as_object().unwrap();
        let required = params["required"].as_array().unwrap();

        assert!(required.contains(&serde_json::json!("path")));
    }
}

#[allow(dead_code)]
struct MockTool;
impl Tool for MockTool {
    fn name(&self) -> &str {
        "mock_tool"
    }
    fn execute(
        &self,
        _args: serde_json::Value,
        _sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        Ok(ToolResult {
            tool_call_id: "mock".to_string(),
            success: true,
            output: "".to_string(),
        })
    }
}
