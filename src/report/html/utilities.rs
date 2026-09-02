/// Convert markdown to HTML
pub fn markdown_to_html(md: &str) -> String {
    // First convert literal \n to real newlines (LLM sometimes sends escaped)
    let normalized = md.replace("\\n", "\n");

    // First escape any HTML entities to prevent XSS
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

/// Severity statistics
#[derive(Debug, Default)]
pub struct SeverityStats {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Calculate severity counts from findings
pub fn calculate_severity_stats(
    findings: &[crate::findings::VulnerabilityFinding],
) -> SeverityStats {
    let mut stats = SeverityStats::default();

    for finding in findings {
        match finding.severity {
            crate::findings::Severity::Critical => stats.critical += 1,
            crate::findings::Severity::High => stats.high += 1,
            crate::findings::Severity::Medium => stats.medium += 1,
            crate::findings::Severity::Low => stats.low += 1,
            crate::findings::Severity::Info => stats.info += 1,
        }
    }

    stats
}

/// Generate summary cards HTML for severity counts
pub fn build_summary_cards(stats: &SeverityStats) -> String {
    let mut cards = Vec::new();

    if stats.critical > 0 {
        cards.push(format!(
            r#"<div class="card critical" onclick="filterFindings('critical')"><h3>{}</h3><p>Critical</p></div>"#,
            stats.critical
        ));
    }
    if stats.high > 0 {
        cards.push(format!(
            r#"<div class="card high" onclick="filterFindings('high')"><h3>{}</h3><p>High</p></div>"#,
            stats.high
        ));
    }
    if stats.medium > 0 {
        cards.push(format!(
            r#"<div class="card medium" onclick="filterFindings('medium')"><h3>{}</h3><p>Medium</p></div>"#,
            stats.medium
        ));
    }
    if stats.low > 0 {
        cards.push(format!(
            r#"<div class="card low" onclick="filterFindings('low')"><h3>{}</h3><p>Low</p></div>"#,
            stats.low
        ));
    }
    if stats.info > 0 {
        cards.push(format!(
            r#"<div class="card info" onclick="filterFindings('info')"><h3>{}</h3><p>Info</p></div>"#,
            stats.info
        ));
    }

    cards.join("\n            ")
}

/// Generate filter button HTML for severity counts
pub fn build_filter_buttons(stats: &SeverityStats) -> String {
    let mut buttons = Vec::new();

    if stats.critical > 0 {
        buttons.push(format!(
            r#"<button class="filter-btn critical" data-filter="critical" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('critical')">Critical ({})</button>"#,
            stats.critical
        ));
    }
    if stats.high > 0 {
        buttons.push(format!(
            r#"<button class="filter-btn high" data-filter="high" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('high')">High ({})</button>"#,
            stats.high
        ));
    }
    if stats.medium > 0 {
        buttons.push(format!(
            r#"<button class="filter-btn medium" data-filter="medium" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('medium')">Medium ({})</button>"#,
            stats.medium
        ));
    }
    if stats.low > 0 {
        buttons.push(format!(
            r#"<button class="filter-btn low" data-filter="low" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('low')">Low ({})</button>"#,
            stats.low
        ));
    }
    if stats.info > 0 {
        buttons.push(format!(
            r#"<button class="filter-btn info" data-filter="info" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('info')">Info ({})</button>"#,
            stats.info
        ));
    }

    buttons.join("\n            ")
}

/// Generate empty state message when no findings
pub fn build_empty_state_message() -> String {
    r#"<div class="empty-state" style="text-align: center; padding: 60px 20px; background: #f8f9fa; border-radius: 8px; margin: 30px 0;"><h3 style="color: #6c757d; margin-bottom: 10px;">✅ No Security Issues Found</h3><p style="color: #495057;">The scan completed successfully with no vulnerabilities detected.</p></div>"#.to_string()
}

#[allow(dead_code)]
/// Build recommendation section HTML
pub fn build_recommendation_section(rec: &str) -> String {
    format!(
        r#"<div class="recommendation"><strong>Recommendation:</strong> {}</div>"#,
        markdown_to_html(rec)
    )
}

/// Detect programming language from file extension
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
            _ => "",
        }
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    // ============================================================================
    // markdown_to_html Tests
    // ============================================================================

    #[test]
    fn test_markdown_to_html_heading() {
        let html = markdown_to_html("# Main Heading");
        assert!(html.contains("<h1>Main Heading</h1>"));
    }

    #[test]
    fn test_markdown_to_html_subheading() {
        let html = markdown_to_html("## Sub Heading");
        assert!(html.contains("<h2>Sub Heading</h2>"));
    }

    #[test]
    fn test_markdown_to_html_bold() {
        let html = markdown_to_html("**bold text**");
        assert!(html.contains("<strong>bold text</strong>"));
    }

    #[test]
    fn test_markdown_to_html_italic() {
        let html = markdown_to_html("*italic text*");
        assert!(html.contains("<em>italic text</em>"));
    }

    #[test]
    fn test_markdown_to_html_unordered_list() {
        let html = markdown_to_html("- item 1\n- item 2\n- item 3");
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>item 1</li>"));
        assert!(html.contains("<li>item 2</li>"));
    }

    #[test]
    fn test_markdown_to_html_ordered_list() {
        let html = markdown_to_html("1. first\n2. second");
        assert!(html.contains("<ol>"));
        assert!(html.contains("<li>first</li>"));
    }

    #[test]
    fn test_markdown_to_html_code_block() {
        let html = markdown_to_html("```rust\nfn main() {}\n```");
        assert!(html.contains("<code"));
        assert!(html.contains("fn main"));
    }

    #[test]
    fn test_markdown_to_html_inline_code() {
        let html = markdown_to_html("Use `unsafe` block");
        assert!(html.contains("<code>unsafe</code>"));
    }

    #[test]
    fn test_markdown_to_html_link() {
        let html = markdown_to_html("[CWE-79](https://cwe.mitre.org)");
        assert!(html.contains("<a href=\"https://cwe.mitre.org\">"));
        assert!(html.contains("CWE-79"));
    }

    #[test]
    fn test_markdown_to_html_empty_input() {
        let html = markdown_to_html("");
        assert!(html.is_empty());
    }

    #[test]
    fn test_markdown_to_html_xss_protection() {
        let html = markdown_to_html("<script>alert('xss')</script>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_markdown_to_html_table() {
        let html = markdown_to_html("| col1 | col2 |\n|------|------|\n| a | b |");
        assert!(html.contains("<table>"));
        assert!(html.contains("<td>"));
    }

    #[test]
    fn test_markdown_to_html_strikethrough() {
        let html = markdown_to_html("~~deleted text~~");
        assert!(html.contains("<del>deleted text</del>"));
    }

    #[test]
    fn test_markdown_to_html_escaped_newlines() {
        let html = markdown_to_html("Line 1\\nLine 2");
        assert!(html.contains("Line 1"));
        assert!(html.contains("Line 2"));
    }

    // ============================================================================
    // calculate_severity_stats Tests
    // ============================================================================

    fn make_finding(severity: Severity) -> crate::findings::VulnerabilityFinding {
        crate::findings::VulnerabilityFinding {
            id: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: Some(1),
            code_snippet: None,
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
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }
    }

    #[test]
    fn test_calculate_severity_stats_all_severities() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
            make_finding(Severity::Low),
            make_finding(Severity::Info),
        ];

        let stats = calculate_severity_stats(&findings);

        assert_eq!(stats.critical, 1);
        assert_eq!(stats.high, 1);
        assert_eq!(stats.medium, 1);
        assert_eq!(stats.low, 1);
        assert_eq!(stats.info, 1);
    }

    #[test]
    fn test_calculate_severity_stats_empty() {
        let findings: Vec<crate::findings::VulnerabilityFinding> = vec![];
        let stats = calculate_severity_stats(&findings);

        assert_eq!(stats.critical, 0);
        assert_eq!(stats.high, 0);
        assert_eq!(stats.medium, 0);
        assert_eq!(stats.low, 0);
        assert_eq!(stats.info, 0);
    }

    #[test]
    fn test_calculate_severity_stats_multiple_same_severity() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
        ];

        let stats = calculate_severity_stats(&findings);

        assert_eq!(stats.critical, 4);
        assert_eq!(stats.high, 0);
    }

    // ============================================================================
    // build_summary_cards Tests
    // ============================================================================

    #[test]
    fn test_build_summary_cards_all_severities() {
        let stats = SeverityStats {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
        };

        let cards = build_summary_cards(&stats);

        assert!(cards.contains("critical"));
        assert!(cards.contains("high"));
        assert!(cards.contains("medium"));
        assert!(cards.contains("low"));
        assert!(cards.contains("info"));
        assert!(cards.contains("1"));
        assert!(cards.contains("5"));
    }

    #[test]
    fn test_build_summary_cards_empty() {
        let stats = SeverityStats::default();
        let cards = build_summary_cards(&stats);
        assert!(cards.is_empty());
    }

    #[test]
    fn test_build_summary_cards_multiple_counts() {
        let stats = SeverityStats {
            critical: 2,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
        };

        let cards = build_summary_cards(&stats);

        assert!(cards.contains("2"));
        assert!(cards.contains("1"));
    }

    // ============================================================================
    // build_filter_buttons Tests
    // ============================================================================

    #[test]
    fn test_build_filter_buttons_all_severities() {
        let stats = SeverityStats {
            critical: 1,
            high: 2,
            medium: 0,
            low: 0,
            info: 0,
        };

        let buttons = build_filter_buttons(&stats);

        assert!(buttons.contains("Critical (1)"));
        assert!(buttons.contains("High (2)"));
        assert!(!buttons.contains("Medium"));
        assert!(!buttons.contains("Low"));
        assert!(!buttons.contains("Info"));
    }

    #[test]
    fn test_build_filter_buttons_empty() {
        let stats = SeverityStats::default();
        let buttons = build_filter_buttons(&stats);
        assert!(buttons.is_empty());
    }

    // ============================================================================
    // detect_language Tests
    // ============================================================================

    #[test]
    fn test_detect_language_python() {
        assert_eq!(detect_language("src/main.py"), "python");
        assert_eq!(detect_language("/path/to/script.py"), "python");
    }

    #[test]
    fn test_detect_language_javascript() {
        assert_eq!(detect_language("app.js"), "javascript");
    }

    #[test]
    fn test_detect_language_typescript() {
        assert_eq!(detect_language("src/app.ts"), "typescript");
        assert_eq!(detect_language("src/component.tsx"), "typescript");
    }

    #[test]
    fn test_detect_language_rust() {
        assert_eq!(detect_language("src/lib.rs"), "rust");
    }

    #[test]
    fn test_detect_language_go() {
        assert_eq!(detect_language("main.go"), "go");
    }

    #[test]
    fn test_detect_language_java() {
        assert_eq!(detect_language("src/Main.java"), "java");
    }

    #[test]
    fn test_detect_language_c() {
        assert_eq!(detect_language("src/main.c"), "c");
    }

    #[test]
    fn test_detect_language_cpp() {
        assert_eq!(detect_language("src/main.cpp"), "cpp");
        assert_eq!(detect_language("src/main.cc"), "cpp");
        assert_eq!(detect_language("src/main.cxx"), "cpp");
    }

    #[test]
    fn test_detect_language_header_files() {
        assert_eq!(detect_language("src/main.h"), "cpp");
        assert_eq!(detect_language("src/main.hpp"), "cpp");
    }

    #[test]
    fn test_detect_language_sql() {
        assert_eq!(detect_language("query.sql"), "sql");
    }

    #[test]
    fn test_detect_language_yaml() {
        assert_eq!(detect_language("config.yml"), "yaml");
        assert_eq!(detect_language("config.yaml"), "yaml");
    }

    #[test]
    fn test_detect_language_json() {
        assert_eq!(detect_language("package.json"), "json");
    }

    #[test]
    fn test_detect_language_bash() {
        assert_eq!(detect_language("script.sh"), "bash");
        assert_eq!(detect_language("script.bash"), "bash");
    }

    #[test]
    fn test_detect_language_unknown_extension() {
        assert_eq!(detect_language("src/unknown.xyz"), "");
    }

    #[test]
    fn test_detect_language_no_extension() {
        assert_eq!(detect_language("README"), "");
        assert_eq!(detect_language("Makefile"), "");
    }

    #[test]
    fn test_detect_language_case_insensitive() {
        assert_eq!(detect_language("src/main.PY"), "python");
        assert_eq!(detect_language("src/main.RS"), "rust");
        assert_eq!(detect_language("src/main.TS"), "typescript");
    }

    // ============================================================================
    // build_empty_state_message Tests
    // ============================================================================

    #[test]
    fn test_build_empty_state_message_content() {
        let message = build_empty_state_message();

        assert!(message.contains("No Security Issues Found"));
        assert!(message.contains("✅"));
        assert!(message.contains("vulnerabilities detected"));
    }

    // ============================================================================
    // build_recommendation_section Tests
    // ============================================================================

    #[test]
    fn test_build_recommendation_section() {
        let html = build_recommendation_section("Use safe alternatives");

        assert!(html.contains("Recommendation"));
        assert!(html.contains("Use safe alternatives"));
    }
}
