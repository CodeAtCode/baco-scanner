//! Context summary structures for hierarchical context extraction.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Summary of function-level context extracted from a source file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Summary of module-level context extracted from a source file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContextSummary {
    pub file_path: PathBuf,
    pub language: String,
    pub functions: Vec<FunctionSummary>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub call_relationships: Vec<String>,
    pub module_summary: String,
}

impl ContextSummary {
    /// Create an empty summary for a given file path.
    fn default_for_path(file_path: &Path) -> ContextSummary {
        ContextSummary {
            file_path: file_path.to_path_buf(),
            language: String::new(),
            ..Default::default()
        }
    }

    /// Format the summary as a multi-line string for prompt injection.
    pub fn format_for_prompt(&self) -> String {
        let mut output = String::new();

        if self.functions.is_empty() && self.imports.is_empty() && self.exports.is_empty() {
            return "No context available (empty or unrecognized file)".to_string();
        }

        if !self.functions.is_empty() {
            output.push_str("## Functions\n");
            for func in &self.functions {
                output.push_str(&format!(
                    "- {} (lines {}-{}): {}\n",
                    func.name, func.start_line, func.end_line, func.signature
                ));
            }
        }

        if !self.imports.is_empty() {
            output.push_str("\n## Imports\n");
            for import in &self.imports {
                output.push_str(&format!("- {}\n", import));
            }
        }

        if !self.exports.is_empty() {
            output.push_str("\n## Exports\n");
            for export in &self.exports {
                output.push_str(&format!("- {}\n", export));
            }
        }

        if !self.call_relationships.is_empty() {
            output.push_str("\n## Call Relationships\n");
            for rel in &self.call_relationships {
                output.push_str(&format!("- {}\n", rel));
            }
        }

        if !self.module_summary.is_empty() {
            output.push_str(&format!("\n## Module Purpose\n{}\n", self.module_summary));
        }

        output
    }
}

/// Extracts hierarchical context from source code files.
pub struct ContextExtractor;

impl ContextExtractor {
    /// Extract context summary from a source file.
    ///
    /// Supports C, Rust, Python, JavaScript/TypeScript.
    /// Returns empty summary on parse failure (no panic).
    pub fn extract(file_path: &Path) -> ContextSummary {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return ContextSummary::default_for_path(file_path),
        };

        let language = Self::detect_language(file_path);

        let mut summary = ContextSummary {
            file_path: file_path.to_path_buf(),
            language: language.clone(),
            ..Default::default()
        };

        // Extract based on language
        match language.as_str() {
            "c" | "cpp" => {
                summary.functions = Self::extract_c_functions(&content);
                summary.imports = Self::extract_c_imports(&content);
                summary.exports = Self::extract_c_exports(&content);
            }
            "rust" => {
                summary.functions = Self::extract_rust_functions(&content);
                summary.imports = Self::extract_rust_imports(&content);
                summary.exports = Self::extract_rust_exports(&content);
            }
            "python" => {
                summary.functions = Self::extract_python_functions(&content);
                summary.imports = Self::extract_python_imports(&content);
                summary.exports = Self::extract_python_exports(&content);
            }
            "javascript" | "typescript" => {
                summary.functions = Self::extract_js_functions(&content);
                summary.imports = Self::extract_js_imports(&content);
                summary.exports = Self::extract_js_exports(&content);
            }
            _ => {
                // Unrecognized language - return empty summary
                return ContextSummary::default_for_path(file_path);
            }
        }

        // Build call relationships
        summary.call_relationships = Self::build_call_relationships(&summary.functions, &content);

        // Generate module summary
        summary.module_summary = Self::generate_module_summary(&summary);

        summary
    }

    fn detect_language(file_path: &Path) -> String {
        match file_path.extension().and_then(|e| e.to_str()) {
            Some("c") | Some("h") => "c".to_string(),
            Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") => "cpp".to_string(),
            Some("rs") => "rust".to_string(),
            Some("py") | Some("pyw") => "python".to_string(),
            Some("js") | Some("jsx") => "javascript".to_string(),
            Some("ts") | Some("tsx") => "typescript".to_string(),
            Some("java") => "java".to_string(),
            Some("go") => "go".to_string(),
            _ => "unknown".to_string(),
        }
    }

    // C/C++ extraction
    fn extract_c_functions(content: &str) -> Vec<FunctionSummary> {
        let mut functions = Vec::new();
        // Match C function definitions: return_type function_name(params) {
        let re = Regex::new(
            r"(?m)^\s*(?:static\s+|inline\s+|extern\s+)*(\w+(?:\s*\*?)?)\s+(\w+)\s*\([^)]*\)\s*\{",
        )
        .unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for cap in re.captures_iter(content) {
            if let Some(matched) = cap.get(0) {
                let start_line = content[..matched.start()].lines().count() + 1;
                let func_name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let return_type = cap.get(1).map(|m| m.as_str()).unwrap_or("");

                // Find end of function (simple brace matching)
                let end_line = Self::find_brace_end(content, matched.start(), lines.len());

                functions.push(FunctionSummary {
                    name: func_name.to_string(),
                    signature: format!("{} {}", return_type, func_name),
                    start_line,
                    end_line,
                });
            }
        }

        functions
    }

    fn extract_c_imports(content: &str) -> Vec<String> {
        let mut imports = Vec::new();
        let re = Regex::new(r#"(?m)^\s*#include\s*["<]([^">]+)[">]"#).unwrap();

        for cap in re.captures_iter(content) {
            if let Some(include) = cap.get(1) {
                imports.push(include.as_str().to_string());
            }
        }

        imports
    }

    fn extract_c_exports(_content: &str) -> Vec<String> {
        // C doesn't have explicit exports, return empty
        Vec::new()
    }

    // Rust extraction
    fn extract_rust_functions(content: &str) -> Vec<FunctionSummary> {
        let mut functions = Vec::new();
        // Match Rust function definitions
        let re = Regex::new(r"(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for cap in re.captures_iter(content) {
            if let Some(matched) = cap.get(0) {
                let start_line = content[..matched.start()].lines().count() + 1;
                let func_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");

                let end_line = Self::find_brace_end(content, matched.start(), lines.len());

                // Extract full signature
                let signature = matched.as_str().lines().next().unwrap_or("").to_string();

                functions.push(FunctionSummary {
                    name: func_name.to_string(),
                    signature,
                    start_line,
                    end_line,
                });
            }
        }

        functions
    }

    fn extract_rust_imports(content: &str) -> Vec<String> {
        let mut imports = Vec::new();
        let re = Regex::new(r"(?m)^\s*use\s+([^;]+);").unwrap();

        for cap in re.captures_iter(content) {
            if let Some(import) = cap.get(1) {
                imports.push(format!("use {};", import.as_str()));
            }
        }

        imports
    }

    fn extract_rust_exports(content: &str) -> Vec<String> {
        let mut exports = Vec::new();
        // Match pub items
        let re = Regex::new(r"(?m)^\s*pub\s+(fn|struct|enum|mod|trait|type|const|static)\s+(\w+)")
            .unwrap();

        for cap in re.captures_iter(content) {
            if let Some(item_type) = cap.get(1) {
                if let Some(item_name) = cap.get(2) {
                    exports.push(format!("{} {}", item_type.as_str(), item_name.as_str()));
                }
            }
        }

        exports
    }

    // Python extraction
    fn extract_python_functions(content: &str) -> Vec<FunctionSummary> {
        let mut functions = Vec::new();
        let re = Regex::new(r"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(:|\->\s*[^:]+:)\s*")
            .unwrap();
        let lines: Vec<&str> = content.lines().collect();

        for cap in re.captures_iter(content) {
            if let Some(matched) = cap.get(0) {
                let start_line = content[..matched.start()].lines().count() + 1;
                let func_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");

                // Find end of function (indentation-based)
                let end_line = Self::find_python_func_end(content, matched.end(), lines.len());

                functions.push(FunctionSummary {
                    name: func_name.to_string(),
                    signature: matched.as_str().lines().next().unwrap_or("").to_string(),
                    start_line,
                    end_line,
                });
            }
        }

        functions
    }

    fn extract_python_imports(content: &str) -> Vec<String> {
        let mut imports = Vec::new();

        // Regular imports
        let re_import = Regex::new(r"(?m)^\s*import\s+([^#\n]+)").unwrap();
        for cap in re_import.captures_iter(content) {
            if let Some(import) = cap.get(1) {
                imports.push(format!("import {}", import.as_str().trim()));
            }
        }

        // From imports
        let re_from = Regex::new(r"(?m)^\s*from\s+(\S+)\s+import\s+([^#\n]+)").unwrap();
        for cap in re_from.captures_iter(content) {
            if let Some(module) = cap.get(1) {
                if let Some(names) = cap.get(2) {
                    imports.push(format!(
                        "from {} import {}",
                        module.as_str(),
                        names.as_str().trim()
                    ));
                }
            }
        }

        imports
    }

    fn extract_python_exports(content: &str) -> Vec<String> {
        let mut exports = Vec::new();
        // Check for __all__ definition
        if let Some(cap) = Regex::new(r"(?m)^__all__\s*=\s*\[([^\]]+)\]")
            .unwrap()
            .captures(content)
        {
            if let Some(all_content) = cap.get(1) {
                // Parse the list
                for name in all_content.as_str().split(',') {
                    let name = name.trim().trim_matches('"').trim_matches('\'');
                    if !name.is_empty() {
                        exports.push(name.to_string());
                    }
                }
            }
        }

        exports
    }

    // JavaScript/TypeScript extraction
    fn extract_js_functions(content: &str) -> Vec<FunctionSummary> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Match various function patterns
        let patterns = vec![
            Regex::new(r"(?m)^\s*(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{").unwrap(),
            Regex::new(r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>\s*\{").unwrap(),
            Regex::new(r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\([^)]*\)\s*\{").unwrap(),
            Regex::new(r"(?m)^\s*(?:public|private|protected)?\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*:\s*[^{]+\s*\{").unwrap(), // class methods
        ];

        for re in &patterns {
            for cap in re.captures_iter(content) {
                if let Some(matched) = cap.get(0) {
                    let start_line = content[..matched.start()].lines().count() + 1;
                    let func_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");

                    let end_line = Self::find_brace_end(content, matched.start(), lines.len());

                    functions.push(FunctionSummary {
                        name: func_name.to_string(),
                        signature: matched.as_str().lines().next().unwrap_or("").to_string(),
                        start_line,
                        end_line,
                    });
                }
            }
        }

        functions
    }

    fn extract_js_imports(content: &str) -> Vec<String> {
        let mut imports = Vec::new();

        // ES6 imports
        let re_es6 = Regex::new(r"(?m)^\s*import\s+([^;]+);").unwrap();
        for cap in re_es6.captures_iter(content) {
            if let Some(import) = cap.get(1) {
                imports.push(format!("import {};", import.as_str()));
            }
        }

        // CommonJS requires
        let re_cjs =
            Regex::new(r#"(?m)^\s*const\s+(\w+)\s*=\s*require\(['"]([^'"]+)['"]\)"#).unwrap();
        for cap in re_cjs.captures_iter(content) {
            if let Some(var) = cap.get(1) {
                if let Some(module) = cap.get(2) {
                    imports.push(format!(
                        "const {} = require('{}');",
                        var.as_str(),
                        module.as_str()
                    ));
                }
            }
        }

        imports
    }

    fn extract_js_exports(content: &str) -> Vec<String> {
        let mut exports = Vec::new();

        // ES6 exports
        let re_es6 =
            Regex::new(r"(?m)^\s*export\s+(?:default\s+)?(?:const|let|var|function|class)\s+(\w+)")
                .unwrap();
        for cap in re_es6.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                exports.push(format!("export {};", name.as_str()));
            }
        }

        // Named exports
        let re_named = Regex::new(r"(?m)^\s*export\s+\{([^}]+)\}").unwrap();
        for cap in re_named.captures_iter(content) {
            if let Some(names) = cap.get(1) {
                for name in names.as_str().split(',') {
                    let name = name.trim().split(" as ").next().unwrap_or("").trim();
                    if !name.is_empty() {
                        exports.push(format!("export {{ {} }};", name));
                    }
                }
            }
        }

        // CommonJS module.exports
        let re_cjs = Regex::new(r"(?m)^\s*module\.exports\s*=\s*\{([^}]+)\}").unwrap();
        for cap in re_cjs.captures_iter(content) {
            if let Some(exports_str) = cap.get(1) {
                for name in exports_str.as_str().split(',') {
                    let name = name.trim().split(":").next().unwrap_or("").trim();
                    if !name.is_empty() {
                        exports.push(format!("module.exports.{};", name));
                    }
                }
            }
        }

        exports
    }

    fn find_brace_end(content: &str, start_pos: usize, max_lines: usize) -> usize {
        let mut brace_count = 0;
        let mut started = false;

        for (i, line) in content[start_pos..].lines().enumerate() {
            if i >= max_lines {
                break;
            }

            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                    if started && brace_count == 0 {
                        return content[..start_pos].lines().count() + i + 1;
                    }
                }
            }
        }

        max_lines
    }

    fn find_python_func_end(content: &str, start_pos: usize, max_lines: usize) -> usize {
        let lines: Vec<&str> = content[start_pos..].lines().collect();
        if lines.is_empty() {
            return max_lines;
        }

        let first_line = lines[0];
        let base_indent = first_line.chars().take_while(|c| *c == ' ').count();

        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                continue;
            }

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            let indent = line.chars().take_while(|c| *c == ' ').count();
            if indent <= base_indent && !line.trim().starts_with('#') {
                return content[..start_pos].lines().count() + i;
            }

            if i >= max_lines {
                break;
            }
        }

        max_lines
    }

    fn build_call_relationships(functions: &[FunctionSummary], content: &str) -> Vec<String> {
        let mut relationships = Vec::new();

        for func in functions {
            // Look for calls to other functions within this function's body
            for other_func in functions {
                if func.name == other_func.name {
                    continue;
                }

                // Search for function name as a call pattern
                let pattern = format!(r"\b{}\s*\(", other_func.name);
                if let Ok(re) = Regex::new(&pattern) {
                    // Get the function body content
                    let lines: Vec<&str> = content.lines().collect();
                    if func.start_line <= lines.len() && func.end_line <= lines.len() {
                        let body_start = content
                            .lines()
                            .take(func.start_line - 1)
                            .map(|l| l.len() + 1)
                            .sum::<usize>();
                        let body_end = content
                            .lines()
                            .take(func.end_line)
                            .map(|l| l.len() + 1)
                            .sum::<usize>();

                        let body = &content[body_start..body_end.min(content.len())];

                        if re.is_match(body) {
                            relationships.push(format!("{} calls {}", func.name, other_func.name));
                        }
                    }
                }
            }
        }

        relationships
    }

    fn generate_module_summary(summary: &ContextSummary) -> String {
        let mut parts = Vec::new();

        if !summary.imports.is_empty() {
            parts.push(format!("Imports {} modules", summary.imports.len()));
        }

        if !summary.functions.is_empty() {
            parts.push(format!("Defines {} functions", summary.functions.len()));
        }

        if !summary.exports.is_empty() {
            parts.push(format!("Exports {} symbols", summary.exports.len()));
        }

        if parts.is_empty() {
            "No significant code structure detected".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_extract_c_file() {
        let content = r#"
#include <stdio.h>
#include <stdlib.h>

int add(int a, int b) {
    return a + b;
}

void print_result(int val) {
    printf("Result: %d\n", val);
}

int main() {
    int result = add(1, 2);
    print_result(result);
    return 0;
}
"#;

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.c");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "c");
        assert!(summary.functions.len() >= 3);
        assert_eq!(summary.imports.len(), 2);
        assert!(summary.imports.contains(&"stdio.h".to_string()));
        assert!(summary.imports.contains(&"stdlib.h".to_string()));
    }

    #[test]
    fn test_extract_rust_file() {
        let content = r#"
use std::io;
use std::fs;

pub fn read_file(path: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(path)
}

pub fn process_data(data: &str) -> String {
    data.to_uppercase()
}

fn main() {
    let data = read_file("test.txt").unwrap();
    let processed = process_data(&data);
    println!("{}", processed);
}
"#;

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.rs");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "rust");
        assert!(
            summary.functions.len() >= 1,
            "Expected at least 1 function, got {}",
            summary.functions.len()
        );
        assert_eq!(summary.imports.len(), 2);
        assert!(summary.exports.contains(&"fn read_file".to_string()));
    }

    #[test]
    fn test_extract_python_file() {
        let content = r#"
import os
import sys
from pathlib import Path

def read_file(path):
    with open(path) as f:
        return f.read()

def process_data(data):
    return data.upper()

def main():
    data = read_file("test.txt")
    result = process_data(data)
    print(result)

if __name__ == "__main__":
    main()
"#;

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.py");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "python");
        assert!(summary.functions.len() >= 3);
        assert!(summary.imports.len() >= 3);
    }

    #[test]
    fn test_empty_file() {
        let content = "";

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.rs");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert!(summary.functions.is_empty());
        assert!(summary.imports.is_empty());
        assert!(summary.exports.is_empty());
    }

    #[test]
    fn test_unrecognized_language() {
        let content = "some random content";

        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.xyz");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert!(summary.language.is_empty() || summary.language == "unknown");
        assert!(summary.functions.is_empty());
    }

    #[test]
    fn test_format_for_prompt() {
        let summary = ContextSummary {
            file_path: PathBuf::from("test.rs"),
            language: "rust".to_string(),
            functions: vec![
                FunctionSummary {
                    name: "main".to_string(),
                    signature: "fn main()".to_string(),
                    start_line: 1,
                    end_line: 10,
                },
                FunctionSummary {
                    name: "helper".to_string(),
                    signature: "fn helper()".to_string(),
                    start_line: 12,
                    end_line: 15,
                },
            ],
            imports: vec!["use std::io;".to_string()],
            exports: vec!["fn main".to_string()],
            call_relationships: vec!["main calls helper".to_string()],
            module_summary: "Defines 2 functions, Imports 1 modules".to_string(),
        };

        let formatted = summary.format_for_prompt();

        assert!(formatted.contains("## Functions"));
        assert!(formatted.contains("main"));
        assert!(formatted.contains("helper"));
        assert!(formatted.contains("## Imports"));
        assert!(formatted.contains("## Call Relationships"));
        assert!(formatted.contains("main calls helper"));
    }

    #[test]
    fn test_panic_on_missing_file() {
        // Should not panic, return empty summary
        let path = Path::new("/nonexistent/file.rs");
        let summary = ContextExtractor::extract(path);

        assert!(summary.functions.is_empty());
        assert!(summary.file_path == path);
    }
}
