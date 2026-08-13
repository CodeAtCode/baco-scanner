use crate::findings::VulnerabilityFinding;
use regex::Regex;

/// Detect language from file path
pub(super) fn detect_language(path: &std::path::Path) -> crate::context::control_path::Language {
    match path.extension().and_then(|e| e.to_str()) {
        Some("c" | "h") => crate::context::control_path::Language::C,
        Some("rs") => crate::context::control_path::Language::Rust,
        Some("py") => crate::context::control_path::Language::Python,
        Some("js" | "jsx" | "ts" | "tsx") => crate::context::control_path::Language::JavaScript,
        _ => crate::context::control_path::Language::C, // Default fallback
    }
}

/// Extract function name from a finding's title or code snippet.
///
/// Looks for patterns like "function X", "def X", "fn X" in the title or code_snippet.
pub(super) fn extract_function_name_from_finding(finding: &VulnerabilityFinding) -> Option<String> {
    let patterns = [
        r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"fn\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    ];

    let text_to_search = finding.code_snippet.as_deref().unwrap_or(&finding.title);

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text_to_search) {
                if let Some(matched) = caps.get(1) {
                    let name = matched.as_str().to_string();
                    // Filter out common keywords
                    if !matches!(
                        name.as_str(),
                        "if" | "for" | "while" | "match" | "let" | "const" | "var"
                    ) {
                        return Some(name);
                    }
                }
            }
        }
    }

    None
}
