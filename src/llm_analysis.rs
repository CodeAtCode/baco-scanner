use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm::LlmClient;
use crate::prompt::loader;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

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

        Self {
            client,
            languages,
            max_file_size: max_file_size_kb * 1024,
            prompt_template,
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
        map
    }

    /// Check if file should be analyzed based on extension
    pub fn should_analyze(&self, path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let extensions = self.get_extensions();

        for lang in &self.languages {
            if let Some(lang_exts) = extensions.get(lang.to_lowercase().as_str()) {
                if lang_exts.contains(&ext) {
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

    /// Analyze a single file for vulnerabilities
    pub async fn analyze_file(&self, path: &Path) -> Result<Vec<VulnerabilityFinding>, String> {
        let content = match self.read_file_content(path) {
            Some(c) => c,
            None => return Ok(Vec::new()), // Skip large or unreadable files
        };

        let file_path = path.to_string_lossy().to_string();
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Use loaded prompt template with variable substitution
        let prompt = self
            .prompt_template
            .replace("%%LANGUAGE%%", extension)
            .replace("%%FILE_PATH%%", &file_path)
            .replace("%%LINE_RANGE%%", "1-max")
            .replace("%%CONTEXT_LINES%%", "3")
            .replace("%%CODE_CONTENT%%", &self.truncate_code(&content));

        // Debug: log prompt length and first 300 chars
        tracing::info!(
            "PROMPT: len={}, preview={}",
            self.prompt_template.len(),
            &self.prompt_template.chars().take(300).collect::<String>()
        );

        let messages = vec![
            crate::llm::ChatMessage::system(
                "You are a security expert analyzing code for vulnerabilities. Return ONLY valid JSON array."
            ),
            crate::llm::ChatMessage::user(&prompt)
        ];

        let response = self.client.chat(&messages).await;

        match response {
            Ok(response_with_model) => self.parse_llm_response(
                &response_with_model.content,
                &file_path,
                &response_with_model.model_used,
            ),
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

    /// Truncate code to fit in context window
    pub fn truncate_code(&self, code: &str) -> String {
        let max_chars = 8000; // Keep under context limits
        if code.len() <= max_chars {
            code.to_string()
        } else {
            format!(
                "{}...\n[truncated - {} chars omitted]",
                &code[..max_chars],
                code.len() - max_chars
            )
        }
    }

    /// Parse LLM response into findings
    pub(crate) fn parse_llm_response(
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
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Analyze all files in a directory autonomously for vulnerabilities
    pub async fn analyze_directory(
        &self,
        target_path: &str,
    ) -> Result<Vec<VulnerabilityFinding>, String> {
        let mut all_findings = Vec::new();
        let target = Path::new(target_path);

        tracing::info!(
            "Starting autonomous LLM security analysis of {}",
            target_path
        );

        for entry in WalkDir::new(target).into_iter().filter_entry(|e| {
            !e.path().starts_with("tests") && !e.path().starts_with("node_modules")
        }) {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();

            if path.is_file() && self.should_analyze(path) {
                tracing::debug!("Analyzing file: {}", path.display());
                match self.analyze_file(path).await {
                    Ok(findings) => {
                        if !findings.is_empty() {
                            tracing::info!(
                                "Found {} vulnerabilities in {}",
                                findings.len(),
                                path.display()
                            );
                        }
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        tracing::warn!("Error analyzing {}: {}", path.display(), e);
                    }
                }
            }
        }

        tracing::info!(
            "Autonomous LLM analysis complete: {} findings total",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::LlmConfig;

    #[test]
    fn test_should_analyze_c_file() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        assert!(analyzer.should_analyze(Path::new("test.c")));
        assert!(analyzer.should_analyze(Path::new("test.h")));
        assert!(!analyzer.should_analyze(Path::new("test.py")));
    }

    #[test]
    fn test_should_analyze_python_file() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["python".to_string()], 512, &scanner_config);

        assert!(analyzer.should_analyze(Path::new("test.py")));
        assert!(!analyzer.should_analyze(Path::new("test.js")));
    }

    #[test]
    fn test_extract_cwe_id_from_description() {
        assert_eq!(
            extract_cwe_id("This is CWE-611 vulnerability"),
            Some("CWE-611".to_string())
        );
        assert_eq!(
            extract_cwe_id("XXE attack CWE-611 in XML parser"),
            Some("CWE-611".to_string())
        );
        assert_eq!(
            extract_cwe_id("Path traversal CWE-22 vulnerability"),
            Some("CWE-22".to_string())
        );
        assert_eq!(extract_cwe_id("No CWE mentioned here"), None);
        assert_eq!(extract_cwe_id(""), None);
    }

    #[test]
    fn test_parse_llm_response_with_fix_code() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "critical",
                "title": "XXE Vulnerability",
                "description": "XML External Entity injection CWE-611",
                "line": 65,
                "cwe_id": "CWE-611",
                "fix_code": "reader = xmlReaderForFile(filename, NULL, XML_PARSE_NOENT | XML_PARSE_NONET);",
                "recommendation": "Disable external entities"
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.cwe_id, Some("CWE-611".to_string()));
        assert_eq!(
            finding.diff_hunk,
            Some(
                "reader = xmlReaderForFile(filename, NULL, XML_PARSE_NOENT | XML_PARSE_NONET);"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_parse_llm_response_without_fix_code_uses_after() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "high",
                "title": "Path Traversal",
                "description": "CWE-22 path traversal vulnerability",
                "line": 100,
                "code_snippet": {
                    "before": "char *path = input;",
                    "code": "open(path, O_RDONLY);",
                    "after": "char *validated = validate_path(input); open(validated, O_RDONLY);"
                }
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.cwe_id, Some("CWE-22".to_string()));
        assert_eq!(
            finding.diff_hunk,
            Some("char *validated = validate_path(input); open(validated, O_RDONLY);".to_string())
        );
    }

    #[test]
    fn test_parse_llm_response_extracts_cwe_from_description() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "medium",
                "title": "XSS Vulnerability",
                "description": "Cross-site scripting vulnerability - this is CWE-79 vulnerability",
                "line": 42
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "test.js", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.cwe_id, Some("CWE-79".to_string()));
    }

    #[test]
    fn test_parse_code_snippet_with_before_after() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "high",
                "title": "SQL Injection",
                "description": "Potential SQL injection detected",
                "line": 42,
                "cwe_id": "CWE-89",
                "fix_code": "Use parameterized queries",
                "recommendation": "Validate input",
                "code_snippet": {
                    "before": "let query = \"SELECT * FROM users\";\nlet id = get_input();\nlet full = query + id;",
                    "code": "db.execute(&full);",
                    "after": "let result = db.execute(&full);\nprocess(result);\nreturn Ok(());"
                }
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/db.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.cwe_id, Some("CWE-89".to_string()));
        assert!(finding.diff_hunk.is_some());
        assert!(finding.diff_hunk.is_some());
    }

    #[test]
    fn test_parse_code_snippet_empty_before_after() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "medium",
                "title": "Hardcoded Password",
                "description": "Password hardcoded",
                "line": 15,
                "cwe_id": "CWE-798",
                "fix_code": "Use env vars",
                "recommendation": "Move to config",
                "code_snippet": {
                    "before": "",
                    "code": "const PW = \"admin123\";",
                    "after": ""
                }
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/config.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        // fix_code should be used as diff_hunk when diff_hunk not provided
        assert_eq!(finding.diff_hunk, Some("Use env vars".to_string()));
    }

    #[test]
    fn test_parse_code_snippet_missing() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config.clone());
        let scanner_config = crate::config::ScannerConfig::default();
        let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

        let json_response = r#"[
            {
                "severity": "low",
                "title": "Unused Variable",
                "description": "Variable not used",
                "line": 8,
                "cwe_id": null,
                "fix_code": "Remove var",
                "recommendation": "Clean up"
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/main.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        // fix_code should be used as diff_hunk when diff_hunk not provided
        assert_eq!(finding.diff_hunk, Some("Remove var".to_string()));
    }
}
