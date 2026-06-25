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
pub fn calculate_severity_stats(findings: &[crate::findings::VulnerabilityFinding]) -> SeverityStats {
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
