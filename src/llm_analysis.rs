use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm::LlmClient;
use crate::prompt::loader;
use crate::retrieval::{CweDocument, CweKnowledgeBase};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Sink call tokens for RAG query building (T22)
const SINK_TOKENS: &[&str] = &[
    "eval",
    "exec",
    "system",
    "popen",
    "query",
    "execute",
    "innerHTML",
    "dangerouslySetInnerHTML",
    "unserialize",
    "strcpy",
    "memcpy",
    "sprintf",
    "gets",
    "$wpdb->",
    "Runtime.exec",
    "child_process",
    "subprocess",
    "shell_exec",
    "passthru",
    "proc_open",
    "popen",
    "curl_exec",
    "file_get_contents",
    "include",
    "require",
    "eval(",
    "exec(",
    "system(",
];

/// Extract sink calls from code content (T22)
pub fn extract_sink_calls(code: &str) -> Vec<String> {
    let mut sinks = Vec::new();
    let code_lower = code.to_lowercase();

    for sink in SINK_TOKENS {
        if code_lower.contains(&sink.to_lowercase()) {
            sinks.push(sink.to_string());
        }
    }

    sinks
}

/// Extract import/requires from code (T22)
pub fn extract_imports(code: &str) -> Vec<String> {
    let mut imports = Vec::new();

    for line in code.lines().take(50) {
        let trimmed = line.trim();
        if trimmed.starts_with("import ")
            || trimmed.starts_with("require ")
            || trimmed.starts_with("const ") && trimmed.contains(" = require(")
            || trimmed.starts_with("use ")  // Rust
            || trimmed.starts_with("#include")
        // C/C++
        {
            imports.push(trimmed.to_string());
        }
    }

    imports
}

/// Build a smart RAG query from code content (T22)
/// Returns: sink calls + imports + CWE hints (if available)
pub fn build_rag_query(
    file_path: &str,
    code_content: &str,
    cwe_hints: Option<&[String]>,
) -> String {
    let mut query_parts = Vec::new();

    // Always include file path
    query_parts.push(file_path.to_string());

    // Extract and include sink calls
    let sinks = extract_sink_calls(code_content);
    if !sinks.is_empty() {
        query_parts.push(format!("sinks: {}", sinks.join(", ")));
    }

    // Extract and include imports
    let imports = extract_imports(code_content);
    if !imports.is_empty() {
        query_parts.push(format!("imports: {}", imports.join("; ")));
    }

    // Include CWE hints if available
    if let Some(cwes) = cwe_hints {
        if !cwes.is_empty() {
            query_parts.push(format!("suspected CWEs: {}", cwes.join(", ")));
        }
    }

    // Fallback: if nothing extracted, use first 20 lines
    if query_parts.len() == 1 {
        query_parts.push(code_content.lines().take(20).collect::<Vec<_>>().join(" "));
    }

    query_parts.join(" ")
}

/// Format CWE specifications into a human-readable string
pub fn format_cwe_specs(results: &[&CweDocument]) -> String {
    if results.is_empty() {
        return String::new();
    }

    let mut formatted = String::new();
    for (i, doc) in results.iter().enumerate() {
        if i > 0 {
            formatted.push_str("\n\n");
        }
        formatted.push_str(&format!("{}: {}\n", doc.cwe_id, doc.name));
        formatted.push_str(&format!("Description: {}\n", doc.description));
        if !doc.examples.is_empty() {
            formatted.push_str("Examples:\n");
            for example in &doc.examples {
                formatted.push_str(&format!("  - {}\n", example));
            }
        }
        formatted.push_str(&format!("Mitigation: {}\n", doc.mitigation));
    }

    formatted
}

/// Extract CWE ID from description text
pub fn extract_cwe_id(description: &str) -> Option<String> {
    let re = Regex::new(r"CWE-\d+").ok()?;
    re.find(description).map(|m| m.as_str().to_string())
}

/// Generate a recommendation based on vulnerability title and description
pub fn generate_recommendation(title: &str, description: &str) -> String {
    let title_lower = title.to_lowercase();

    if title_lower.contains("sql")
        || title_lower.contains("injection") && title_lower.contains("sql")
    {
        return "Use parameterized queries or prepared statements instead of string concatenation"
            .to_string();
    }
    if title_lower.contains("command") || title_lower.contains("shell") {
        return "Avoid shell command execution with user input. Use safe APIs or validate/sanitize input rigorously".to_string();
    }
    if title_lower.contains("xss") || title_lower.contains("cross-site scripting") {
        return "Escape user output properly. Use context-aware encoding (HTML, JS, URL)"
            .to_string();
    }
    if title_lower.contains("buffer") || title_lower.contains("overflow") {
        return "Use bounds checking and safe string functions. Validate input lengths before operations".to_string();
    }
    if title_lower.contains("use after free") || title_lower.contains("uaf") {
        return "Ensure proper lifetime management. Use smart pointers (Rust) or explicit nullification after free".to_string();
    }
    if title_lower.contains("null") || title_lower.contains("dereference") {
        return "Check for null pointers before dereferencing. Use Option types where appropriate"
            .to_string();
    }
    if title_lower.contains("format") || title_lower.contains("string") {
        return "Use format specifiers correctly. Never pass user input directly as format string"
            .to_string();
    }

    // Fallback to generic recommendation based on description keywords
    let desc_lower = description.to_lowercase();
    if desc_lower.contains("user") && desc_lower.contains("input") {
        return "Validate and sanitize all user input before use".to_string();
    }
    if desc_lower.contains("untrusted") {
        return "Treat all external data as untrusted. Apply strict validation and encoding"
            .to_string();
    }

    format!(
        "Review and fix this {} vulnerability. Follow secure coding practices for this category",
        title
    )
}

/// Generate PoC code demonstrating the vulnerability
pub fn generate_poc_code(title: &str, file_path: &str, line_number: u32) -> Option<String> {
    let title_lower = title.to_lowercase();

    if title_lower.contains("buffer") || title_lower.contains("overflow") {
        return Some(format!(
            r#"// PoC: Buffer overflow exploit attempt
// Target: {}:{}
void poc_exploit() {{
    char *evil_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    vulnerable_copy(evil_input);  // Overwrites stack/return address
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("use after free") || title_lower.contains("uaf") {
        return Some(format!(
            r#"// PoC: Use-after-free exploit
// Target: {}:{}
void poc_uaf() {{
    char *ptr = (char *)malloc(100);
    free(ptr);
    // ptr is now dangling - use after free!
    ptr[0] = 'H';  // Undefined behavior, potential code execution
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("double free") {
        return Some(format!(
            r#"// PoC: Double-free exploit
// Target: {}:{}
void poc_double_free() {{
    char *ptr = (char *)malloc(100);
    free(ptr);
    free(ptr);  // Double free! Heap corruption
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("format") {
        return Some(format!(
            r#"// PoC: Format string vulnerability exploit
// Target: {}:{}
void poc_format() {{
    // Attacker-controlled input with format specifiers
    char *malicious_input = "%s%s%s%s%s%s%n";
    vulnerable_format(malicious_input);  // Can leak/write memory
}}"#,
            file_path, line_number
        ));
    }

    None
}

/// Generate mitigation code showing the fix
pub fn generate_mitigation_code(title: &str, file_path: &str, line_number: u32) -> Option<String> {
    let title_lower = title.to_lowercase();

    if title_lower.contains("buffer") || title_lower.contains("overflow") {
        return Some(format!(
            r#"// Mitigation: Use bounds-checked string copy
// Original: {}:{}
void safe_copy(char *user_input, size_t input_len) {{
    char buffer[64];
    // Validate input length before copy
    if (input_len >= sizeof(buffer)) {{
        input_len = sizeof(buffer) - 1;  // Truncate safely
    }}
    strncpy(buffer, user_input, input_len);
    buffer[input_len] = '\0';  // Ensure null termination
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("use after free") || title_lower.contains("uaf") {
        return Some(format!(
            r#"// Mitigation: Nullify pointer after free
// Original: {}:{}
void safe_uaf() {{
    char *ptr = (char *)malloc(100);
    // ... use ptr ...
    free(ptr);
    ptr = NULL;  // Prevent use-after-free
    // ptr is now safe - dereferencing gives NULL, not dangling pointer
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("double free") {
        return Some(format!(
            r#"// Mitigation: Track allocation state
// Original: {}:{}
void safe_double_free() {{
    char *ptr = (char *)malloc(100);
    bool is_allocated = true;
    
    // ... use ptr ...
    
    if (is_allocated) {{
        free(ptr);
        ptr = NULL;
        is_allocated = false;  // Track state
    }}
}}"#,
            file_path, line_number
        ));
    }
    if title_lower.contains("format") {
        return Some(format!(
            r#"// Mitigation: Use fixed format specifier
// Original: {}:{}
void safe_format(char *user_input) {{
    // NEVER pass user input directly to printf
    // Always use format specifiers:
    printf("%s", user_input);  // Safe - user input treated as data, not format
}}"#,
            file_path, line_number
        ));
    }

    None
}

/// Analyzes source code files using LLM to find vulnerabilities
pub struct LlmAnalyzer {
    client: LlmClient,
    languages: Vec<String>,
    max_file_size: usize,
    prompt_template: String,
    cwe_kb: Option<CweKnowledgeBase>,
    /// Optional context prefix prepended to the user prompt for RAG-augmented analysis
    /// (VulTriage triple-path + PacVD primitive-API abstraction).
    context_prefix: Option<String>,
    /// Enable structured JSON output using response_format with JSON schema
    enable_structured_output: bool,
}

impl LlmAnalyzer {
    pub fn new(
        client: LlmClient,
        languages: Vec<String>,
        max_file_size_kb: usize,
        config: &crate::config::ScannerConfig,
    ) -> Self {
        // Load prompt template from file
        let loaded_prompts = loader::load_phase_prompts(None);
        let default_prompt = Self::default_llm_static_analysis_prompt();

        // Check for config override first
        let config_override = config
            .llm
            .phases
            .prompt_overrides
            .phase_overrides
            .get("llm_static_analysis")
            .map(|s| s.as_str());

        let prompt_template = loader::get_prompt(
            "llm_static_analysis",
            &loaded_prompts,
            config_override,
            &default_prompt,
        );

        // Load CWE knowledge base for retrieval-augmented generation
        let cwe_kb = CweKnowledgeBase::load_embedded().ok();
        if cwe_kb.is_none() {
            tracing::warn!("Failed to load CWE knowledge base - RAG will be disabled");
        }

        Self {
            client,
            languages,
            max_file_size: max_file_size_kb * 1024,
            prompt_template,
            cwe_kb,
            context_prefix: None,
            enable_structured_output: false,
        }
    }

    /// Get file extensions for configured languages
    fn get_extensions(&self) -> HashMap<String, Vec<&str>> {
        let mut map = HashMap::new();
        map.insert("c".to_string(), vec!["c", "h"]);
        map.insert(
            "cpp".to_string(),
            vec!["cpp", "hpp", "cc", "hh", "cxx", "hxx"],
        );
        map.insert("python".to_string(), vec!["py", "pyw"]);
        map.insert("javascript".to_string(), vec!["js", "jsx"]);
        map.insert("typescript".to_string(), vec!["ts", "tsx"]);
        map.insert("rust".to_string(), vec!["rs"]);
        map.insert("go".to_string(), vec!["go"]);
        map.insert("java".to_string(), vec!["java"]);
        map.insert("php".to_string(), vec!["php", "phtml"]);
        map
    }

    /// Check if file should be analyzed based on extension
    pub fn should_analyze(&self, path: &Path) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let extensions = self.get_extensions();

        for lang in &self.languages {
            if let Some(lang_exts) = extensions.get(lang.to_lowercase().as_str()) {
                if lang_exts.contains(&ext.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    /// Read file content safely
    pub fn read_file_content(&self, path: &Path) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;
        if metadata.len() > self.max_file_size as u64 {
            return None; // File too large
        }
        fs::read_to_string(path).ok()
    }

    /// Get default LLM static analysis prompt (fallback)
    fn default_llm_static_analysis_prompt() -> String {
        include_str!("../prompts/phases/llm_static_analysis.md")
            .trim()
            .to_string()
    }

    /// Set a context prefix prepended to the user prompt.
    ///
    /// Used by VulTriage (triple-path context) and PacVD (primitive-API abstraction)
    /// to inject RAG context before the code-under-analysis.
    pub fn with_context_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.context_prefix = Some(prefix.into());
        self
    }

    /// Enable structured JSON output using response_format with JSON schema
    pub fn with_structured_output(mut self, enabled: bool) -> Self {
        self.enable_structured_output = enabled;
        self
    }

    /// Analyze a single file for vulnerabilities
    pub async fn analyze_file(&self, path: &Path) -> Result<Vec<VulnerabilityFinding>, String> {
        let content = match self.read_file_content(path) {
            Some(c) => c,
            None => return Ok(Vec::new()), // Skip large or unreadable files
        };

        let file_path = path.to_string_lossy().to_string();
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Retrieve relevant CWE specifications using RAG
        let cwe_specs = self.retrieve_cwe_specs(&file_path, &content);

        // Use loaded prompt template with variable substitution
        let prompt = self
            .prompt_template
            .replace("%%LANGUAGE%%", extension)
            .replace("%%FILE_PATH%%", &file_path)
            .replace("%%LINE_RANGE%%", "1-max")
            .replace("%%CONTEXT_LINES%%", "3")
            .replace("%%CODE_CONTENT%%", &self.truncate_code(&content))
            .replace("%%CWE_SPECS%%", &cwe_specs);

        // Debug: log prompt length and first 300 chars
        tracing::info!(
            "PROMPT: len={}, preview={}",
            self.prompt_template.len(),
            &self.prompt_template.chars().take(300).collect::<String>()
        );

        // Prepend optional RAG context (VulTriage triple-path + PacVD abstraction)
        let user_prompt = if let Some(ref prefix) = self.context_prefix {
            format!("{}\n\n{}", prefix, prompt)
        } else {
            prompt
        };

        let messages = vec![
            crate::llm::ChatMessage::system(
                "You are a security expert analyzing code for vulnerabilities. Return ONLY valid JSON array."
            ),
            crate::llm::ChatMessage::user(&user_prompt)
        ];

        // Use structured output if enabled, otherwise fall back to regular chat
        let response = if self.enable_structured_output {
            // Define the JSON schema for structured findings
            let schema = serde_json::json!({
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "cwe_id": {"type": "string"},
                                "severity": {"type": "string"},
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "description": {"type": "string"},
                                "recommendation": {"type": "string"}
                            },
                            "required": ["title", "cwe_id", "severity", "file", "line", "description", "recommendation"]
                        }
                    }
                },
                "required": ["findings"]
            });

            self.client
                .chat_with_json_schema(&messages, "vulnerability_findings", schema)
                .await
        } else {
            self.client.chat(&messages).await
        };

        match response {
            Ok(response_with_model) => {
                // If structured output was used, unwrap the findings array from the response
                if self.enable_structured_output {
                    self.parse_structured_llm_response(
                        &response_with_model.content,
                        &file_path,
                        &response_with_model.model_used,
                    )
                } else {
                    self.parse_llm_response(
                        &response_with_model.content,
                        &file_path,
                        &response_with_model.model_used,
                    )
                }
            }
            Err(e) => {
                tracing::error!(
                    "LLM analysis failed for {}: Error: {}\n  Model: {}",
                    path.display(),
                    e,
                    self.client.model_name()
                );
                Ok(Vec::new())
            }
        }
    }

    /// Retrieve relevant CWE specifications based on file path and code content
    fn retrieve_cwe_specs_inner(&self, file_path: &str, code_content: &str) -> String {
        let kb = match &self.cwe_kb {
            Some(kb) => kb,
            None => return String::new(),
        };

        // Build smart RAG query (T22)
        let query = build_rag_query(file_path, code_content, None);

        // Search for top-3 relevant CWE specifications
        let results = kb.search(&query, 3);

        if results.is_empty() {
            return String::new();
        }

        format_cwe_specs(&results)
    }

    /// Retrieve relevant CWE specifications based on file path and code content
    fn retrieve_cwe_specs(&self, file_path: &str, code_content: &str) -> String {
        self.retrieve_cwe_specs_inner(file_path, code_content)
    }

    /// Retrieve relevant CWE specifications based on file path and code content (public)
    pub fn truncate_code(&self, code: &str) -> String {
        let max_bytes = 8000; // Total budget for content plus truncation notice
        if code.len() <= max_bytes {
            return code.to_string();
        }
        fn prev_char_boundary(s: &str, mut i: usize) -> usize {
            while i > 0 && !s.is_char_boundary(i) {
                i -= 1;
            }
            i
        }
        let mut boundary = prev_char_boundary(code, max_bytes);
        loop {
            let notice = format!(
                "...\n[truncated - {} chars omitted]",
                code[boundary..].chars().count()
            );
            if boundary + notice.len() <= max_bytes {
                return format!("{}{}", &code[..boundary], notice);
            }
            boundary = prev_char_boundary(code, boundary - 1);
        }
    }

    /// Chunk code using tree-sitter AST parsing (T19)
    /// Extracts whole functions/classes, groups them under max_bytes cap.
    /// Falls back to truncate_code when parsing unavailable.
    pub fn chunk_code_tree_sitter(
        &self,
        content: &str,
        language: &str,
        max_bytes: usize,
    ) -> Vec<String> {
        // Try to parse with tree-sitter
        let chunks = self.parse_and_chunk(content, language, max_bytes);

        // Fallback to line-based truncation if parsing fails
        if chunks.is_empty() {
            vec![self.truncate_code(content)]
        } else {
            chunks
        }
    }

    /// Parse content and extract function/class chunks
    fn parse_and_chunk(&self, content: &str, language: &str, max_bytes: usize) -> Vec<String> {
        // Map language to tree-sitter parser
        let lang = match language.to_lowercase().as_str() {
            "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
            "c" | "c++" | "cpp" => Some(tree_sitter_c::LANGUAGE.into()),
            "python" => Some(tree_sitter_python::LANGUAGE.into()),
            "javascript" | "typescript" | "tsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
            "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
            _ => None,
        };

        let lang = match lang {
            Some(l) => l,
            None => return vec![],
        };

        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&lang).is_err() {
            return vec![];
        }

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return vec![],
        };

        // Extract top-level function/class nodes
        let mut function_ranges = Vec::new();
        let root = tree.root_node();

        Self::extract_function_ranges(root, content, &mut function_ranges);

        if function_ranges.is_empty() {
            return vec![];
        }

        // Group functions into chunks under max_bytes
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();

        // Find preamble (imports/includes before first function)
        let first_func_start = function_ranges.iter().map(|(s, _)| *s).min().unwrap_or(0);
        let preamble = if first_func_start > 0 {
            &content[..first_func_start]
        } else {
            ""
        };

        for (func_start, func_end) in function_ranges {
            let func_content = &content[func_start..func_end];
            let func_bytes = func_content.len();

            // Check if function alone exceeds cap - hard split with marker
            if func_bytes > max_bytes {
                // Push current chunk if any
                if !current_chunk.is_empty() {
                    chunks.push(std::mem::take(&mut current_chunk));
                }

                // Hard split large function
                let marker = "\n// [chunk continues - function too large for single chunk]\n";
                let mut remaining = &content[func_start..func_end];
                let mut chunk_num = 1;

                while !remaining.is_empty() {
                    let take = max_bytes.saturating_sub(marker.len());
                    let end = std::cmp::min(take, remaining.len());

                    let chunk_text = if chunk_num == 1 {
                        format!("{}{}{}", preamble, marker, &remaining[..end])
                    } else {
                        format!("{}{}", marker, &remaining[..end])
                    };

                    chunks.push(chunk_text);
                    remaining = &remaining[end..];
                    chunk_num += 1;
                }
                current_chunk = String::new();
            } else if current_chunk.len() + func_bytes <= max_bytes {
                // Add to current chunk
                if current_chunk.is_empty() && !preamble.is_empty() {
                    current_chunk.push_str(preamble);
                }
                current_chunk.push_str(func_content);
                current_chunk.push('\n');
            } else {
                // Push current chunk and start new one
                if !current_chunk.is_empty() {
                    chunks.push(current_chunk);
                }
                current_chunk = format!("{}{}", preamble, func_content);
                current_chunk.push('\n');
            }
        }

        // Push final chunk
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        chunks
    }

    /// Recursively extract function/class node ranges from tree-sitter AST
    fn extract_function_ranges(
        node: tree_sitter::Node,
        _content: &str,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        // Check for common function/class node types
        let node_type = node.kind();
        let is_function = matches!(
            node_type,
            "function_definition"
                | "method_definition"
                | "class_definition"
                | "function_item"
                | "impl_item"
                | "declaration_list"
                | "compound_statement"
        );

        if is_function {
            ranges.push((node.start_byte(), node.end_byte()));
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::extract_function_ranges(child, _content, ranges);
        }
    }

    /// Parse structured LLM response with JSON schema into findings
    fn parse_structured_llm_response(
        &self,
        text: &str,
        file_path: &str,
        model_name: &str,
    ) -> Result<Vec<VulnerabilityFinding>, String> {
        // Remove markdown code fences
        let cleaned = text
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim_end_matches("~~~")
            .trim();

        // Parse the outer wrapper object
        let parsed: serde_json::Value =
            serde_json::from_str(cleaned).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // Extract the findings array
        let findings_array = parsed
            .get("findings")
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid 'findings' array in response")?;

        tracing::debug!(
            "Parsed {} findings from structured JSON",
            findings_array.len()
        );

        // Process each finding
        let mut findings = Vec::new();
        for item in findings_array.iter() {
            let severity_str = item.get("severity").and_then(|v| v.as_str());
            let title = item.get("title").and_then(|v| v.as_str());
            let description = item.get("description").and_then(|v| v.as_str());
            let line = item.get("line").and_then(|v| v.as_i64());

            if let (Some(severity_str), Some(title), Some(line)) = (severity_str, title, line) {
                let description = description.map(|s| s.to_string()).unwrap_or_default();

                let severity = match severity_str.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };

                let recommendation = item
                    .get("recommendation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                let cwe_id = item
                    .get("cwe_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let cwe_id_for_hash = cwe_id.as_deref().unwrap_or("CWE-000");

                findings.push(VulnerabilityFinding {
                    id: VulnerabilityFinding::generate_id(
                        file_path,
                        Some(line as u32),
                        cwe_id_for_hash,
                    ),
                    title: title.to_string(),
                    description,
                    severity,
                    confidence_score: 0.7,
                    cwe_id,
                    file_path: file_path.to_string(),
                    line_number: Some(line as u32),
                    code_snippet: None,
                    diff_hunk: None,
                    recommendation: Some(recommendation),
                    code_location: Some(format!("{}:{}", file_path, line)),
                    already_reported: false,
                    sources: vec!["llm_analysis".to_string()],
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
                    llm_model: if model_name == "fallback" || model_name.is_empty() {
                        None
                    } else {
                        Some(model_name.to_string())
                    },
                    agent_mode: false,
                    statement_range: None,
                    triage_verdict: None,
                    evidence: vec![crate::evidence::Evidence {
                        source: crate::evidence::EvidenceSource::LlmAnalysis(
                            model_name.to_string(),
                        ),
                        weight: 0.6,
                        detail: "LLM static analysis finding (structured output)".to_string(),
                        timestamp: chrono::Utc::now(),
                    }],
                    verification_tier: None,
                });
            }
        }

        Ok(findings)
    }

    /// Parse LLM response into findings
    pub fn parse_llm_response(
        &self,
        text: &str,
        file_path: &str,
        model_name: &str,
    ) -> Result<Vec<VulnerabilityFinding>, String> {
        // Remove markdown code fences (including language specifiers like ```json)
        let cleaned = text
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_start_matches("```yaml")
            .trim_start_matches("~~~")
            .trim_start_matches(|c: char| c.is_whitespace())
            .trim_end_matches("```")
            .trim_end_matches("~~~")
            .trim_end_matches(|c: char| c.is_whitespace())
            .trim();

        // LLM response parsing
        let mut findings = Vec::new();

        // Try to parse as JSON array
        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(cleaned) {
            tracing::debug!("Parsed {} items from JSON", parsed.len());
            for (i, item) in parsed.iter().enumerate() {
                let desc_val = item.get("description");
                if let Some(desc_str) = desc_val.and_then(|v| v.as_str()) {
                    tracing::debug!("Finding {} description length: {}", i, desc_str.len());
                } else {
                    tracing::debug!("Finding {} description is NOT a string or missing!", i);
                }
            }
            for item in parsed {
                // Extract fields with fallback for empty description
                let severity_str = item.get("severity").and_then(|v| v.as_str());
                let title = item.get("title").and_then(|v| v.as_str());
                let description = item.get("description").and_then(|v| v.as_str());
                let line = item.get("line").and_then(|v| v.as_i64());

                // Skip if essential fields are missing
                if let (Some(severity_str), Some(title), Some(line)) = (severity_str, title, line) {
                    // Use description from LLM response (may be empty if LLM didn't provide one)
                    let description = description.map(|s| s.to_string()).unwrap_or_default();

                    let severity = match severity_str.to_lowercase().as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        _ => Severity::Low,
                    };

                    // Parse fix_code field (NEW - shows fixed code, not continuation)
                    let _fix_code = item
                        .get("fix_code")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // Parse code_snippet - now an object with before/code/after
                    let code_snippet_obj = item.get("code_snippet");
                    let code_snippet =
                        if let Some(obj) = code_snippet_obj.and_then(|v| v.as_object()) {
                            let before = obj.get("before").and_then(|v| v.as_str()).unwrap_or("");
                            let code = obj.get("code").and_then(|v| v.as_str()).unwrap_or("");
                            let after = obj.get("after").and_then(|v| v.as_str()).unwrap_or("");

                            // Format with context - universal format for all languages
                            let mut snippet = String::new();
                            if !before.is_empty() {
                                snippet.push_str("--- Context before ---\n");
                                snippet.push_str(before);
                                if !before.ends_with('\n') {
                                    snippet.push('\n');
                                }
                            }
                            snippet.push_str(">>> VULNERABLE CODE <<<\n");
                            snippet.push_str(code);
                            if !code.ends_with('\n') {
                                snippet.push('\n');
                            }
                            if !after.is_empty() {
                                snippet.push_str(after);
                                if !after.ends_with('\n') {
                                    snippet.push('\n');
                                }
                                snippet.push_str("--- Context after ---\n");
                            }
                            snippet
                        } else {
                            // Fallback to old format (string)
                            code_snippet_obj
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string()
                        };

                    // Extract diff_hunk from JSON if provided (unified diff format)
                    let diff_hunk = item
                        .get("diff_hunk")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        // Fallback to fix_code if diff_hunk not provided
                        .or_else(|| {
                            item.get("fix_code")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string())
                        })
                        // Fallback to after field if neither diff_hunk nor fix_code provided
                        .or_else(|| {
                            if let Some(obj) = item.get("code_snippet").and_then(|v| v.as_object())
                            {
                                obj.get("after")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string())
                            } else {
                                None
                            }
                        });

                    // Parse statement_range from JSON: [start_line, end_line]
                    let statement_range = item
                        .get("statement_range")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| {
                            if arr.len() == 2 {
                                let start = arr[0].as_i64()? as u32;
                                let end = arr[1].as_i64()? as u32;
                                Some((start, end))
                            } else {
                                None
                            }
                        });

                    // Generate recommendation based on vulnerability type
                    let recommendation = generate_recommendation(title, &description);

                    // Set code location
                    let code_location = format!("{}:{}", file_path, line);

                    // Generate PoC and mitigation code if applicable
                    let poc_code = generate_poc_code(title, file_path, line as u32);
                    let mitigation_code = poc_code
                        .is_some()
                        .then(|| generate_mitigation_code(title, file_path, line as u32))
                        .flatten();

                    // Extract CWE ID from JSON or description if present
                    let cwe_id = item
                        .get("cwe_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| extract_cwe_id(&description));

                    // Use default CWE if none found
                    let cwe_id_for_hash = cwe_id.as_deref().unwrap_or("CWE-000");

                    findings.push(VulnerabilityFinding {
                        id: VulnerabilityFinding::generate_id(
                            file_path,
                            Some(line as u32),
                            cwe_id_for_hash,
                        ),
                        title: title.to_string(),
                        description: description.clone(), // Use the description (possibly fallback)
                        severity,
                        confidence_score: 0.7,
                        cwe_id,
                        file_path: file_path.to_string(),
                        line_number: Some(line as u32),
                        code_snippet: Some(code_snippet),
                        diff_hunk,
                        recommendation: Some(recommendation),
                        code_location: Some(code_location),
                        already_reported: false,
                        sources: vec!["llm_analysis".to_string()],
                        commit_reference: None,
                        ticket_reference: None,
                        priority_score: None,
                        cross_file_references: None,
                        verification_status: None,
                        verification_notes: None,
                        verification_error: None,
                        agent_evidence_path: None,
                        security_issue: None,
                        poc_code: poc_code.clone(),
                        mitigation_code: mitigation_code.clone(),
                        poc_format: None,
                        llm_model: if model_name == "fallback" || model_name.is_empty() {
                            None
                        } else {
                            Some(model_name.to_string())
                        },
                        agent_mode: false,
                        statement_range,
                        triage_verdict: None,
                        evidence: vec![crate::evidence::Evidence {
                            source: crate::evidence::EvidenceSource::LlmAnalysis(
                                model_name.to_string(),
                            ),
                            weight: 0.6,
                            detail: "LLM static analysis finding".to_string(),
                            timestamp: chrono::Utc::now(),
                        }],
                        verification_tier: None,
                    });
                }
            }
        }

        Ok(findings)
    }
}
