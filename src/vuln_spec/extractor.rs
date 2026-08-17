//! Specification extractor from code patches.
//!
//! This module implements the extraction of security specifications from git patches,
//! identifying safe behavior patterns that can be used as references for vulnerability detection.

use crate::vuln_spec::schema::{DomainCategory, SecuritySpecification};
use regex::Regex;
use sha2::{Digest, Sha256};
use tree_sitter::{Language, Parser};

/// Extract specifications from a git patch
pub fn extract_from_patch(patch_diff: &str) -> Vec<SecuritySpecification> {
    let mut specs = Vec::new();

    // Split patch into hunks
    let hunks = parse_patch_hunks(patch_diff);

    for hunk in hunks {
        if let Some(spec) = extract_single_spec(&hunk, patch_diff) {
            specs.push(spec);
        }
    }

    specs
}

/// Parse patch hunks from diff
fn parse_patch_hunks(patch: &str) -> Vec<PatchHunk> {
    let mut hunks = Vec::new();
    let mut current_hunk = PatchHunk {
        content: String::new(),
        line_range: (0, 0),
    };

    for line in patch.lines() {
        if line.starts_with("@@") {
            // Save previous hunk if exists
            if !current_hunk.content.is_empty() {
                hunks.push(current_hunk.clone());
            }
            // Parse line range
            if let Some(range) = parse_hunk_header(line) {
                current_hunk.line_range = range;
            }
            current_hunk.content.clear();
        } else {
            current_hunk.content.push_str(line);
            current_hunk.content.push('\n');
        }
    }

    // Don't forget the last hunk
    if !current_hunk.content.is_empty() {
        hunks.push(current_hunk);
    }

    hunks
}

fn parse_hunk_header(header: &str) -> Option<(u32, u32)> {
    let re = Regex::new(r"@@ -\d+,\d+ \+(\d+),(\d+)").unwrap();
    if let Some(caps) = re.captures(header) {
        if let (Ok(start), Ok(len)) = (
            caps.get(1)?.as_str().parse::<u32>(),
            caps.get(2)?.as_str().parse::<u32>(),
        ) {
            return Some((start, len));
        }
    }
    None
}

#[derive(Clone)]
struct PatchHunk {
    #[allow(dead_code)]
    content: String,
    #[allow(dead_code)]
    line_range: (u32, u32),
}

/// Extract a single specification from a patch hunk
fn extract_single_spec(hunk: &PatchHunk, full_patch: &str) -> Option<SecuritySpecification> {
    // Extract added and removed lines
    let added_lines: Vec<&str> = hunk
        .content
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .collect();

    let removed_lines: Vec<&str> = hunk
        .content
        .lines()
        .filter(|line| line.starts_with('-') && !line.starts_with("---"))
        .collect();

    if added_lines.is_empty() || removed_lines.is_empty() {
        return None;
    }

    // Extract the code context
    let added_code = extract_code_from_lines(&added_lines);
    let removed_code = extract_code_from_lines(&removed_lines);

    // Analyze the pattern to determine vulnerability type
    let vuln_type = identify_vulnerability_type(&removed_code, &added_code);

    // Generate safe behavior pattern from the fix
    let safe_pattern = generate_safe_pattern(&added_code, &removed_code);

    if safe_pattern.is_empty() {
        return None;
    }

    // Generate specification ID from patch hash
    let patch_hash = compute_patch_hash(full_patch);
    let spec_id = format!("spec-{}", &patch_hash[..8]);

    // Determine domain from file paths in patch
    let domain = extract_domain_from_patch(full_patch);

    // Categorize as general or domain-specific
    let category = categorize_spec_internal(&vuln_type, &domain, &safe_pattern);

    Some(SecuritySpecification {
        id: spec_id,
        vuln_type: vuln_type.clone(),
        description: generate_description(&vuln_type, &removed_code),
        safe_behavior_pattern: safe_pattern,
        project_domain: domain,
        source_patch_hash: patch_hash,
        category,
    })
}

/// Internal categorization logic
fn categorize_spec_internal(vuln_type: &str, domain: &str, pattern: &str) -> DomainCategory {
    // General specifications address fundamental security issues
    let general_cwes = ["CWE-79", "CWE-89", "CWE-125", "CWE-416", "CWE-22"];

    if general_cwes.contains(&vuln_type) {
        // Check if the pattern is universally applicable
        let universal_patterns = [
            "sanitize",
            "validate",
            "parameterized",
            "bound check",
            "escape",
        ];
        if universal_patterns
            .iter()
            .any(|p| pattern.to_lowercase().contains(p))
        {
            return DomainCategory::General;
        }
    }

    // Domain-specific: repeated patterns in particular domains
    DomainCategory::DomainSpecific(domain.to_string())
}

/// Extract code from diff lines (removing +/- prefixes)
fn extract_code_from_lines(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|line| {
            if line.starts_with('+') || line.starts_with('-') {
                &line[1..]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Identify vulnerability type from code patterns
fn identify_vulnerability_type(removed: &str, added: &str) -> String {
    let removed_lower = removed.to_lowercase();
    let added_lower = added.to_lowercase();

    // SQL injection patterns
    if (removed_lower.contains("execute") && removed_lower.contains("format"))
        && (added_lower.contains("prepare") || added_lower.contains("parameter"))
    {
        return "CWE-89".to_string(); // SQL Injection
    }

    // XSS patterns
    if (removed_lower.contains("innerhtml") || removed_lower.contains("write"))
        && (added_lower.contains("textcontent") || added_lower.contains("escape"))
    {
        return "CWE-79".to_string(); // XSS
    }

    // Buffer overflow patterns
    if (removed_lower.contains("strcpy") || removed_lower.contains("sprintf"))
        && (added_lower.contains("strncpy") || added_lower.contains("snprintf"))
    {
        return "CWE-120".to_string(); // Buffer Copy
    }

    // Use-after-free patterns
    if removed_lower.contains("free") && added_lower.contains("null") {
        return "CWE-416".to_string(); // Use After Free
    }

    // Path traversal patterns
    if removed_lower.contains("join")
        && !added_lower.contains("sanitize")
        && (added_lower.contains("absolute") || added_lower.contains("canonicalize"))
    {
        return "CWE-22".to_string(); // Path Traversal
    }

    // Default to generic based on context
    "CWE-787".to_string() // Out-of-bounds Write (generic)
}

/// Generate safe behavior pattern from the fix
fn generate_safe_pattern(added: &str, removed: &str) -> String {
    let mut patterns = Vec::new();

    // Analyze what changed
    let added_lower = added.to_lowercase();
    let removed_lower = removed.to_lowercase();

    if added_lower.contains("sanitize") || added_lower.contains("escape") {
        patterns.push("Input sanitization/escaping applied");
    }

    if added_lower.contains("validate") || added_lower.contains("check") {
        patterns.push("Input validation performed");
    }

    if added_lower.contains("parameter") || added_lower.contains("prepared") {
        patterns.push("Parameterized queries used");
    }

    if added_lower.contains("bound") || added_lower.contains("length") {
        patterns.push("Boundary checking implemented");
    }

    if added_lower.contains("canonicalize") || added_lower.contains("absolute") {
        patterns.push("Path canonicalization performed");
    }

    if added_lower.contains("null") && removed_lower.contains("free") {
        patterns.push("Pointer nullified after deallocation");
    }

    if patterns.is_empty() {
        // Generic pattern based on context
        if !added.is_empty() {
            format!(
                "Code modified to address security concern: {}",
                truncate_text(added, 100)
            )
        } else {
            String::new()
        }
    } else {
        patterns.join("; ")
    }
}

/// Generate human-readable description
fn generate_description(vuln_type: &str, vulnerable_code: &str) -> String {
    let vuln_desc = match vuln_type {
        "CWE-79" => "Cross-site scripting (XSS) vulnerability",
        "CWE-89" => "SQL injection vulnerability",
        "CWE-120" => "Buffer copy without boundary checking",
        "CWE-416" => "Use-after-free vulnerability",
        "CWE-22" => "Path traversal vulnerability",
        "CWE-787" => "Out-of-bounds write vulnerability",
        _ => "Security vulnerability",
    };

    format!(
        "{} detected. Vulnerable code pattern: {}",
        vuln_desc,
        truncate_text(vulnerable_code, 150)
    )
}

/// Extract domain from patch file paths
pub fn extract_domain_from_patch(patch: &str) -> String {
    // Look for file paths in the patch (format: --- a/path/to/file)
    let re = Regex::new(r"--- a/([^\s]+)").unwrap();

    if let Some(mat) = re.find(patch) {
        let path = mat.as_str().to_lowercase();
        if path.contains("crypto") || path.contains("cipher") {
            return "crypto".to_string();
        }
        if path.contains("db.rs") || path.contains("database") || path.contains("sql") {
            return "database".to_string();
        }
        if path.contains("http") || path.contains("web") || path.contains("api") {
            return "web-server".to_string();
        }
        if path.contains("network") || path.contains("socket") {
            return "network".to_string();
        }
        if path.contains("auth") || path.contains("login") {
            return "authentication".to_string();
        }
    }

    "general".to_string()
}

/// Compute SHA256 hash of patch
pub fn compute_patch_hash(patch: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(patch.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Truncate text to max length
fn truncate_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        let trunc_len = (max_len.saturating_sub(3)).min(text.chars().count());
        format!("{}...", text.chars().take(trunc_len).collect::<String>())
    }
}

/// Categorize specification as general or domain-specific
pub fn categorize_spec(spec: &SecuritySpecification) -> DomainCategory {
    spec.category.clone()
}

/// Extract specifications using tree-sitter AST analysis
pub fn extract_with_ast(patch_diff: &str, language: Language) -> Vec<SecuritySpecification> {
    let mut specs = Vec::new();

    // First, do basic extraction
    let basic_specs = extract_from_patch(patch_diff);

    // Then enhance with AST analysis
    for mut spec in basic_specs {
        if let Some(enhanced) = enhance_with_ast_analysis(patch_diff, &spec, &language) {
            spec = enhanced;
        }
        specs.push(spec);
    }

    specs
}

/// Enhance specification with AST-based code pattern analysis
fn enhance_with_ast_analysis(
    patch_diff: &str,
    base_spec: &SecuritySpecification,
    language: &Language,
) -> Option<SecuritySpecification> {
    // Extract added code sections
    let added_code = extract_added_code_sections(patch_diff);
    if added_code.is_empty() {
        return None;
    }

    // Parse the modified code with tree-sitter
    let mut parser = Parser::new();
    if parser.set_language(language).is_err() {
        return None;
    }

    let mut enhanced_spec = base_spec.clone();

    // Analyze code structure for security patterns
    for code in &added_code {
        let tree = parser.parse(code, None)?;
        let root = tree.root_node();

        // Check for function definitions that might contain security patterns
        let mut has_validation = false;
        let mut has_sanitization = false;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            let node_type = node.kind();
            if node_type == "call_expression" || node_type == "function_declaration" {
                if let Ok(text) = node.utf8_text(code.as_bytes()) {
                    if text.contains("validate") || text.contains("check") {
                        has_validation = true;
                    }
                    if text.contains("sanitize") || text.contains("escape") {
                        has_sanitization = true;
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }

        // Update safe behavior pattern based on AST findings
        if has_validation || has_sanitization {
            let patch_hash = compute_patch_hash(patch_diff);
            enhanced_spec = SecuritySpecification {
                id: format!("ast-spec-{}", &patch_hash[..8]),
                vuln_type: "CWE-79".to_string(), // Default to XSS for AST-based
                description: "AST-detected security pattern".to_string(),
                safe_behavior_pattern: if has_validation {
                    "Input validation implemented".to_string()
                } else {
                    "Input sanitization implemented".to_string()
                },
                project_domain: base_spec.project_domain.clone(),
                source_patch_hash: patch_hash,
                category: base_spec.category.clone(),
            };
        }
    }

    Some(enhanced_spec)
}

/// Extract added code sections from patch
fn extract_added_code_sections(patch: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current_section = String::new();

    for line in patch.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            current_section.push_str(&line[1..]);
            current_section.push('\n');
        } else if (line.starts_with('-') || line.starts_with("@@")) && !current_section.is_empty() {
            sections.push(current_section.clone());
            current_section.clear();
        }
    }

    // Don't forget the last section
    if !current_section.is_empty() {
        sections.push(current_section);
    }

    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_sql_injection_patch() {
        let patch = r#"
--- a/src/db.rs
+++ b/src/db.rs
@@ -10,4 +10,5 @@
-    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
-    conn.execute(&query);
+    let query = "SELECT * FROM users WHERE id = ?";
+    let stmt = conn.prepare(query);
+    stmt.execute(&[user_id]);
"#;

        let specs = extract_from_patch(patch);
        assert!(!specs.is_empty(), "Should extract specification");

        let spec = &specs[0];
        assert_eq!(spec.vuln_type, "CWE-89");
        assert!(
            spec.safe_behavior_pattern.contains("prepare")
                || spec.safe_behavior_pattern.contains("Parameterized")
        );
        // Check domain extraction
        assert_eq!(spec.project_domain, "database");
    }

    #[test]
    fn test_extract_from_xss_patch() {
        let patch = r#"
--- a/src/web/handler.js
+++ b/src/web/handler.js
@@ -15,3 +15,4 @@
-    element.innerHTML = userInput;
+    element.textContent = escapeHtml(userInput);
+    // Sanitize input before rendering
"#;

        let specs = extract_from_patch(patch);
        assert!(!specs.is_empty(), "Should extract specification");

        let spec = &specs[0];
        assert_eq!(spec.vuln_type, "CWE-79");
        // Domain correctly extracted as 'web-server' from path
        assert_eq!(spec.project_domain, "web-server");
    }

    #[test]
    fn test_categorize_general_spec() {
        let spec = SecuritySpecification {
            id: "test-1".to_string(),
            vuln_type: "CWE-89".to_string(),
            description: "SQL injection".to_string(),
            safe_behavior_pattern: "Use parameterized queries".to_string(),
            project_domain: "database".to_string(),
            source_patch_hash: "abc123".to_string(),
            category: DomainCategory::General,
        };

        let category = categorize_spec(&spec);
        assert_eq!(category, DomainCategory::General);
    }

    #[test]
    fn test_categorize_domain_specific_spec() {
        let spec = SecuritySpecification {
            id: "test-2".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "XSS in specific framework".to_string(),
            safe_behavior_pattern: "Framework-specific escaping".to_string(),
            project_domain: "react-app".to_string(),
            source_patch_hash: "def456".to_string(),
            category: DomainCategory::DomainSpecific("react-app".to_string()),
        };

        let category = categorize_spec(&spec);
        assert!(matches!(category, DomainCategory::DomainSpecific(d) if d == "react-app"));
    }

    #[test]
    fn test_extract_keywords_from_patch() {
        let patch = r#"
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,4 @@
+    let sanitized = sanitize_input(user_input);
-    process(user_input);
"#;

        let specs = extract_from_patch(patch);
        assert!(!specs.is_empty());
        // Check that we got a safe behavior pattern (may vary based on implementation)
        assert!(!specs[0].safe_behavior_pattern.is_empty());
    }

    #[test]
    fn test_patch_hash_computation() {
        let patch1 = "diff --git a/test.rs b/test.rs";
        let patch2 = "diff --git a/test2.rs b/test2.rs";

        let hash1 = compute_patch_hash(patch1);
        let hash2 = compute_patch_hash(patch2);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex length
    }

    #[test]
    fn test_domain_extraction() {
        let db_patch = r#"--- a/src/database.rs
+++ b/src/database.rs
@@ -1,2 +1,3 @@
"#;
        assert_eq!(extract_domain_from_patch(db_patch), "database");

        let web_patch = r#"--- a/src/http/handler.rs
+++ b/src/http/handler.rs
@@ -1,2 +1,3 @@
"#;
        assert_eq!(extract_domain_from_patch(web_patch), "web-server");

        let generic_patch = r#"--- a/src/utils.rs
+++ b/src/utils.rs
@@ -1,2 +1,3 @@
"#;
        assert_eq!(extract_domain_from_patch(generic_patch), "general");
    }

    #[test]
    fn test_safe_pattern_generation() {
        let added = "sanitize_input(data)";
        let removed = "process(data)";

        let pattern = generate_safe_pattern(added, removed);
        assert!(pattern.contains("sanitization"));
    }

    #[test]
    fn test_vulnerability_type_identification() {
        // SQL injection
        let vuln_type = identify_vulnerability_type(
            "execute(format!(\"SELECT {}\", id))",
            "prepare(\"SELECT ?\").execute(&[id])",
        );
        assert_eq!(vuln_type, "CWE-89");

        // XSS
        let vuln_type = identify_vulnerability_type(
            "element.innerHTML = input",
            "element.textContent = escape(input)",
        );
        assert_eq!(vuln_type, "CWE-79");
    }

    #[test]
    fn test_truncate_text() {
        let short = "hello";
        let long = "this is a very long text that should be truncated";

        assert_eq!(truncate_text(short, 10), "hello");
        assert!(truncate_text(long, 10).len() <= 10);
        assert!(truncate_text(long, 10).ends_with("..."));
    }
}
