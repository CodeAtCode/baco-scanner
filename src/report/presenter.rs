//! Finding presenter module - extracts shared presentation logic for reports.
//!
//! This module provides pure functions that normalize finding data for display
//! in both markdown and HTML reports, eliminating duplication between formatters.

use crate::findings::{Severity, VulnerabilityFinding};

/// Severity class name for CSS/styling purposes.
pub fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Confidence class based on score threshold.
pub fn confidence_class(score: f32) -> &'static str {
    if score >= 0.7 {
        "confidence-high"
    } else if score >= 0.4 {
        "confidence-medium"
    } else {
        "confidence-low"
    }
}

/// Detect programming language from file extension.
/// Returns empty string if language not recognized.
pub fn detect_language(file_path: &str) -> &'static str {
    if let Some(ext) = file_path.rsplit('.').next() {
        match ext.to_lowercase().as_str() {
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "tsx" => "typescript",
            "rs" => "rust",
            "go" => "go",
            "java" => "java",
            "c" => "c",
            "cpp" | "cc" | "cxx" => "cpp",
            "h" | "hpp" => "cpp",
            "php" | "phtml" => "php",
            "sql" => "sql",
            "yml" | "yaml" => "yaml",
            "json" => "json",
            "sh" | "bash" => "bash",
            "rb" => "ruby",
            "kt" => "kotlin",
            "scala" => "scala",
            "pl" | "pm" => "perl",
            "lua" => "lua",
            "sol" => "solidity",
            "cs" => "csharp",
            "swift" => "swift",
            _ => "",
        }
    } else {
        ""
    }
}

/// Format location string with optional line number.
/// Example: "src/file.rs:42" or "src/file.rs"
pub fn format_location(file_path: &str, line_number: Option<u32>) -> String {
    if let Some(line) = line_number {
        format!("{}:{}", file_path, line)
    } else {
        file_path.to_string()
    }
}

/// Format location for markdown with backtick wrapping.
/// Example: "`src/file.rs`:42" or "`src/file.rs`"
pub fn format_location_markdown(file_path: &str, line_number: Option<u32>) -> String {
    if let Some(line) = line_number {
        format!("`{}`:{}", file_path, line)
    } else {
        format!("`{}`", file_path)
    }
}

/// Build CWE badge/display string if present.
pub fn build_cwe_badge(cwe_id: &Option<String>) -> String {
    cwe_id.as_ref().cloned().unwrap_or_default()
}

/// Build CWE badge HTML if present.
pub fn build_cwe_badge_html(cwe_id: &Option<String>) -> String {
    if let Some(cwe) = cwe_id {
        format!(
            r#"<span class="cwe-badge">{}</span>"#,
            html_escape::encode_text(cwe)
        )
    } else {
        String::new()
    }
}

/// Build CWE link HTML if present.
pub fn build_cwe_link_html(cwe_id: &Option<String>) -> String {
    if let Some(cwe) = cwe_id {
        format!(
            r#"<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/{}.html" target="_blank">{}</a>"#,
            html_escape::encode_text(cwe),
            html_escape::encode_text(cwe)
        )
    } else {
        String::new()
    }
}

/// Format confidence score as percentage string.
pub fn format_confidence_percentage(score: f64) -> String {
    format!("{:.1}%", score * 100.0)
}

/// Format confidence score as integer percentage string.
pub fn format_confidence_int_percentage(score: f64) -> String {
    format!("{:.0}%", score * 100.0)
}

/// Metadata row builder for HTML reports.
#[derive(Default)]
pub struct MetadataRows {
    pub items: Vec<String>,
}

impl MetadataRows {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn push(&mut self, item: String) {
        self.items.push(item);
    }

    pub fn join(&self, separator: &str) -> String {
        self.items.join(separator)
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Build all metadata items for a finding.
pub fn build_metadata_rows(finding: &VulnerabilityFinding) -> MetadataRows {
    let mut rows = MetadataRows::new();

    if let Some(cwe) = &finding.cwe_id {
        rows.push(format!(
            r#"<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/{}.html" target="_blank">{}</a>"#,
            html_escape::encode_text(cwe),
            html_escape::encode_text(cwe)
        ));
    }

    if let Some(status) = &finding.verification_status {
        rows.push(format!(r#"<strong>Verification:</strong> {}"#, status));
    }

    if let Some(priority) = finding.priority_score {
        rows.push(format!(
            r#"<strong>Priority:</strong> {:.1}"#,
            priority * 100.0
        ));
    }

    if let Some(ref refs) = finding.cross_file_references {
        if !refs.is_empty() {
            rows.push(format!(
                r#"<strong>Cross-file refs:</strong> {}"#,
                html_escape::encode_text(&refs.join(", "))
            ));
        }
    }

    if let Some(ref ticket) = finding.ticket_reference {
        rows.push(format!(
            r#"<strong>Ticket:</strong> {}"#,
            html_escape::encode_text(ticket)
        ));
    }

    if let Some((start, end)) = finding.statement_range {
        if finding.line_number.map(|l| l != start).unwrap_or(true) {
            rows.push(format!(
                r#"<strong>Statement range:</strong> lines {}-{}"#,
                start, end
            ));
        }
    }

    if let Some(notes) = &finding.verification_notes {
        rows.push(format!(
            r#"<strong>Verification notes:</strong> {}"#,
            markdown_to_html(notes)
        ));
    }

    if let Some(err) = &finding.verification_error {
        rows.push(format!(
            r#"<strong>Verification error:</strong> <span class="verification-error">{}</span>"#,
            html_escape::encode_text(err)
        ));
    }

    if let Some(commit) = &finding.commit_reference {
        rows.push(format!(
            r#"<strong>Commit:</strong> {}"#,
            html_escape::encode_text(commit)
        ));
    }

    if let Some(verdict) = &finding.triage_verdict {
        let verdict_text = match verdict {
            crate::findings::TriageVerdict::Pass => "Pass",
            crate::findings::TriageVerdict::Kill => "Kill",
            crate::findings::TriageVerdict::Downgrade { .. } => "Downgrade",
            crate::findings::TriageVerdict::ChainRequired { .. } => "Chain Required",
        };
        rows.push(format!(r#"<strong>Triage:</strong> {}"#, verdict_text));
    }

    rows
}

/// Convert markdown to HTML (shared utility).
fn markdown_to_html(md: &str) -> String {
    let normalized = md.replace("\\n", "\n");
    let escaped = html_escape::encode_text(&normalized);

    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    options.insert(pulldown_cmark::Options::ENABLE_TABLES);
    options.insert(pulldown_cmark::Options::ENABLE_FOOTNOTES);

    let parser = pulldown_cmark::Parser::new_ext(&escaped, options);
    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, parser);
    html_output
}

/// Code snippet presenter - handles code/diff rendering.
pub struct CodeSnippetPresenter {
    pub has_diff: bool,
    pub has_code: bool,
    pub diff_hunk: Option<String>,
    pub code_snippet: Option<String>,
}

impl CodeSnippetPresenter {
    pub fn new(finding: &VulnerabilityFinding) -> Self {
        Self {
            has_diff: finding.diff_hunk.is_some(),
            has_code: finding.code_snippet.is_some(),
            diff_hunk: finding.diff_hunk.clone(),
            code_snippet: finding.code_snippet.clone(),
        }
    }

    /// Render code section for HTML.
    pub fn render_html(&self, file_path: &str) -> String {
        let mut html = String::new();

        if let Some(diff) = &self.diff_hunk {
            let diff_trimmed = diff.trim();
            if !diff_trimmed.is_empty() {
                html.push_str(r#"<div class="diff-hunk">"#);
                html.push_str(
                    r#"<div class="diff-header">🔧 Recommended Fix (Unified Diff)</div>"#,
                );
                html.push_str(r#"<pre class="diff-code"><code class="language-diff">"#);
                html.push_str(&html_escape::encode_text(diff_trimmed));
                html.push_str(r#"</code></pre></div>"#);
            } else if let Some(snippet) = &self.code_snippet {
                let lang = detect_language(file_path);
                html.push_str(&format!(
                    r#"<div class="code-snippet-single"><pre><code class="language-{}">{}</code></pre></div>"#,
                    lang,
                    html_escape::encode_text(snippet)
                ));
            }
        } else if let Some(snippet) = &self.code_snippet {
            html.push_str(&format!(
                r#"<div class="code-snippet-single">{}</div>"#,
                html_escape::encode_text(snippet)
            ));
        }

        html
    }

    /// Render code section for markdown.
    pub fn render_markdown(&self, _file_path: &str) -> String {
        let mut md = String::new();

        if let Some(snippet) = &self.code_snippet {
            md.push_str("**Code:**\n\n");
            md.push_str("```text\n");
            md.push_str(snippet);
            md.push_str("\n```\n\n");
        }

        if let Some(hunk) = &self.diff_hunk {
            md.push_str("**Diff:**\n\n");
            md.push_str("```diff\n");
            md.push_str(hunk);
            md.push_str("\n```\n\n");
        }

        md
    }
}

/// Recommendation presenter.
pub struct RecommendationPresenter {
    pub recommendation: Option<String>,
}

impl RecommendationPresenter {
    pub fn new(finding: &VulnerabilityFinding) -> Self {
        Self {
            recommendation: finding.recommendation.clone(),
        }
    }

    pub fn render_html(&self) -> String {
        if let Some(rec) = &self.recommendation {
            format!(
                r#"<div class="recommendation"><strong>Recommendation:</strong> {}</div>"#,
                markdown_to_html(rec)
            )
        } else {
            String::new()
        }
    }

    pub fn render_markdown(&self) -> String {
        if let Some(rec) = &self.recommendation {
            format!("**Recommendation:**\n\n{}\n\n", rec)
        } else {
            String::new()
        }
    }
}

/// PoC/Mitigation code presenter.
pub struct CodeSectionPresenter {
    pub poc_code: Option<String>,
    pub poc_format: Option<String>,
    pub mitigation_code: Option<String>,
    pub file_path: String,
}

impl CodeSectionPresenter {
    pub fn new(finding: &VulnerabilityFinding) -> Self {
        Self {
            poc_code: finding.poc_code.clone(),
            poc_format: finding.poc_format.clone(),
            mitigation_code: finding.mitigation_code.clone(),
            file_path: finding.file_path.clone(),
        }
    }

    pub fn has_content(&self) -> bool {
        self.poc_code.is_some() || self.mitigation_code.is_some()
    }

    pub fn render_html(&self) -> String {
        if !self.has_content() {
            return String::new();
        }

        let mut html = String::from(r#"<div class="poc-section">"#);

        if let Some(poc) = &self.poc_code {
            let format_label = self
                .poc_format
                .as_deref()
                .map(|f| f.to_uppercase())
                .unwrap_or_else(|| "PoC".to_string());

            let lang = detect_language(&self.file_path);
            html.push_str(&format!(
                r#"<div class="code-panel poc">
            <div class="code-panel-header">Proof of Concept ({})</div>
            <div class="code-snippet"><pre><code class="language-{}">{}</code></pre></div>
        </div>"#,
                format_label,
                lang,
                html_escape::encode_text(poc)
            ));
        }

        if let Some(mitigation) = &self.mitigation_code {
            let lang = detect_language(&self.file_path);
            html.push_str(&format!(
                r#"<div class="code-panel mitigation">
            <div class="code-panel-header">Mitigation Example</div>
            <div class="code-snippet"><pre><code class="language-{}">{}</code></pre></div>
        </div>"#,
                lang,
                html_escape::encode_text(mitigation)
            ));
        }

        html.push_str("</div>");
        html
    }

    pub fn render_markdown(&self) -> String {
        let mut md = String::new();

        if let Some(poc) = &self.poc_code {
            md.push_str("**Proof of Concept:**\n\n");
            let poc_lang = self.poc_format.as_deref().unwrap_or("text");
            md.push_str(&format!("```{}\n", poc_lang));
            md.push_str(poc);
            md.push_str("\n```\n\n");
        }

        if let Some(mitigation) = &self.mitigation_code {
            md.push_str("**Mitigation:**\n\n");
            let lang = detect_language(&self.file_path);
            md.push_str(&format!("```{}\n", lang));
            md.push_str(mitigation);
            md.push_str("\n```\n\n");
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_class() {
        assert_eq!(severity_class(Severity::Critical), "critical");
        assert_eq!(severity_class(Severity::High), "high");
        assert_eq!(severity_class(Severity::Medium), "medium");
        assert_eq!(severity_class(Severity::Low), "low");
        assert_eq!(severity_class(Severity::Info), "info");
    }

    #[test]
    fn test_confidence_class() {
        assert_eq!(confidence_class(0.8), "confidence-high");
        assert_eq!(confidence_class(0.5), "confidence-medium");
        assert_eq!(confidence_class(0.3), "confidence-low");
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("test.py"), "python");
        assert_eq!(detect_language("test.js"), "javascript");
        assert_eq!(detect_language("test.ts"), "typescript");
        assert_eq!(detect_language("test.rs"), "rust");
        assert_eq!(detect_language("test.go"), "go");
        assert_eq!(detect_language("unknown.xyz"), "");
    }

    #[test]
    fn test_format_location() {
        assert_eq!(format_location("src/test.rs", Some(42)), "src/test.rs:42");
        assert_eq!(format_location("src/test.rs", None), "src/test.rs");
    }

    #[test]
    fn test_format_location_markdown() {
        assert_eq!(
            format_location_markdown("src/test.rs", Some(42)),
            "`src/test.rs`:42"
        );
        assert_eq!(
            format_location_markdown("src/test.rs", None),
            "`src/test.rs`"
        );
    }
}
