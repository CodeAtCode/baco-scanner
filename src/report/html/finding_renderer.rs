use crate::findings::VulnerabilityFinding;
use html_escape::encode_text;

use super::utilities::{detect_language, markdown_to_html};

/// Render a single finding card as HTML
pub fn render_finding(finding: &VulnerabilityFinding, finding_id: usize) -> String {
    let severity_class = match finding.severity {
        crate::findings::Severity::Critical => "critical",
        crate::findings::Severity::High => "high",
        crate::findings::Severity::Medium => "medium",
        crate::findings::Severity::Low => "low",
        crate::findings::Severity::Info => "info",
    };

    let confidence_class = if finding.confidence_score >= 0.7 {
        "confidence-high"
    } else if finding.confidence_score >= 0.4 {
        "confidence-medium"
    } else {
        "confidence-low"
    };

    let finding_div_id = format!("finding-{}", finding_id);

    let line_info = finding
        .line_number
        .map(|l| format!(":{}", l))
        .unwrap_or_default();

    // Build CWE badge if present
    let cwe_badge = if let Some(cwe) = &finding.cwe_id {
        format!(r#"<span class="cwe-badge">{}</span>"#, encode_text(cwe))
    } else {
        String::new()
    };

    let mut html = format!(
        r#"<div class="finding {}" id="{}">
    <div class="finding-header">
        <h3 class="collapsible" onclick="document.getElementById('{0}-details').style.display = document.getElementById('{0}-details').style.display === 'none' ? 'block' : 'none'">{}</h3>
        <span class="severity {}">{}</span>
        {}    </div>
    <div class="finding-details" id="{0}-details">
        <div class="finding-meta-row">
            <div class="meta">
                <strong>File:</strong> {} {}<br>
                <strong>Source:</strong> {}<br>
                <strong>Confidence:</strong> <span class="confidence-badge {}">{:.0}%</span><br>
                {}            </div>
        </div>
        <p>{}</p>
"#,
        severity_class,
        &finding_div_id,
        encode_text(&finding.title),
        severity_class,
        encode_text(&finding.severity.to_string()),
        cwe_badge,
        encode_text(&finding.file_path),
        line_info,
        encode_text(&finding.sources.join(", ")),
        confidence_class,
        finding.confidence_score * 100.0,
        // Source and agent mode info (treat empty strings as missing)
        if finding.agent_mode {
            let source = finding
                .llm_model
                .as_deref()
                .filter(|m| !m.is_empty())
                .unwrap_or("unknown");
            format!(
                r#"<br><strong>Source:</strong> {}<br><strong>Mode:</strong> <span class="agent-badge">Agent</span>"#,
                source
            )
        } else if let Some(model) = &finding.llm_model {
            if model.is_empty() {
                String::new() // Don't show source if empty
            } else {
                format!(r#"<br><strong>Source:</strong> {}"#, model)
            }
        } else {
            String::new()
        },
        // Convert markdown description to HTML
        markdown_to_html(&finding.description)
    );

    // Show diff hunk if available (unified diff format)
    if let Some(diff) = &finding.diff_hunk {
        let diff_trimmed = diff.trim();
        if !diff_trimmed.is_empty() {
            html.push_str(r#"<div class="diff-hunk">"#);
            html.push_str(r#"<div class="diff-header">🔧 Recommended Fix (Unified Diff)</div>"#);
            html.push_str(r#"<pre class="diff-code"><code class="language-diff">"#);
            html.push_str(&encode_text(diff_trimmed));
            html.push_str(r#"</code></pre></div>"#);
        } else if let Some(snippet) = &finding.code_snippet {
            let lang = detect_language(&finding.file_path);
            html.push_str(&format!(
                r#"<div class="code-snippet-single"><pre><code class="language-{}">{}</code></pre></div>"#,
                lang,
                encode_text(snippet)
            ));
        }
    } else if let Some(snippet) = &finding.code_snippet {
        html.push_str(&format!(
            r#"<div class="code-snippet-single">{}</div>"#,
            encode_text(snippet)
        ));
    }

    if let Some(rec) = &finding.recommendation {
        html.push_str(&format!(
            r#"<div class="recommendation"><strong>Recommendation:</strong> {}</div>"#,
            markdown_to_html(rec)
        ));
    }

    // PoC code snippets and mitigation examples
    let has_poc = finding.poc_code.is_some();
    let has_mitigation = finding.mitigation_code.is_some();

    if has_poc || has_mitigation {
        html.push_str(r#"<div class="poc-section">"#);

        if has_poc {
            let format_label = finding
                .poc_format
                .as_deref()
                .map(|f| f.to_uppercase())
                .unwrap_or_else(|| "PoC".to_string());

            let lang = detect_language(&finding.file_path);
            html.push_str(&format!(
                r#"<div class="code-panel poc">
            <div class="code-panel-header">Proof of Concept ({})</div>
            <div class="code-snippet"><pre><code class="language-{}">{}</code></pre></div>
        </div>"#,
                format_label,
                lang,
                encode_text(finding.poc_code.as_ref().unwrap())
            ));
        }

        if has_mitigation {
            let lang = detect_language(&finding.file_path);
            html.push_str(&format!(
                r#"<div class="code-panel mitigation">
            <div class="code-panel-header">Mitigation Example</div>
            <div class="code-snippet"><pre><code class="language-{}">{}</code></pre></div>
        </div>"#,
                lang,
                encode_text(finding.mitigation_code.as_ref().unwrap())
            ));
        }

        html.push_str("</div>");
    }

    // Additional metadata
    let mut meta_items = Vec::new();
    if let Some(cwe) = &finding.cwe_id {
        meta_items.push(format!(r#"<strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/{}.html" target="_blank">{}</a>"#, encode_text(cwe), encode_text(cwe)));
    }
    if let Some(status) = &finding.verification_status {
        meta_items.push(format!(r#"<strong>Verification:</strong> {}"#, status));
    }
    if let Some(priority) = finding.priority_score {
        meta_items.push(format!(
            r#"<strong>Priority:</strong> {:.1}"#,
            priority * 100.0
        ));
    }
    if let Some(ref refs) = finding.cross_file_references {
        if !refs.is_empty() {
            meta_items.push(format!(
                r#"<strong>Cross-file refs:</strong> {}"#,
                encode_text(&refs.join(", "))
            ));
        }
    }
    if let Some(ref ticket) = finding.ticket_reference {
        meta_items.push(format!(
            r#"<strong>Ticket:</strong> {}"#,
            encode_text(ticket)
        ));
    }

    if !meta_items.is_empty() {
        html.push_str(&format!(
            r#"<div class="meta">{}</div>"#,
            meta_items.join("<br>")
        ));
    }

    html.push_str("</div></div>");
    html
}
