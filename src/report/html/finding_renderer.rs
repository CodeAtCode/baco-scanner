use crate::findings::VulnerabilityFinding;
use html_escape::encode_text;

use super::utilities::{detect_language, markdown_to_html};

pub fn render_finding(finding: &VulnerabilityFinding, finding_id: usize) -> String {
    render_finding_with_id(finding, &format!("finding-{}", finding_id))
}

pub fn render_finding_with_id(finding: &VulnerabilityFinding, finding_id: &str) -> String {
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

    let finding_div_id = finding_id.to_string();

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

    // Build triage verdict badge
    let triage_badge = match finding.triage_verdict {
        Some(crate::findings::TriageVerdict::Kill) => {
            r#"<span class="triage-badge false-positive">FALSE POSITIVE</span>"#.to_string()
        }
        Some(crate::findings::TriageVerdict::Pass) => {
            r#"<span class="triage-badge true-positive">VERIFIED TP</span>"#.to_string()
        }
        Some(crate::findings::TriageVerdict::Downgrade { .. }) => {
            r#"<span class="triage-badge downgrade">DOWNGRADED</span>"#.to_string()
        }
        Some(crate::findings::TriageVerdict::ChainRequired { .. }) => {
            r#"<span class="triage-badge chain-required">CHAIN REQUIRED</span>"#.to_string()
        }
        None => String::new(),
    };

    // Build location span for header (file:line)
    let location_span = if let Some(line) = finding.line_number {
        format!(
            r#"<span class="finding-location">{}:{}</span>"#,
            encode_text(&finding.file_path),
            line
        )
    } else {
        encode_text(&finding.file_path).to_string()
    };

    // Build confidence badge for header
    let confidence_badge = format!(
        r#"<span class="confidence-badge {}">{:.0}%</span>"#,
        confidence_class,
        finding.confidence_score * 100.0
    );

    let mut html = format!(
        r#"<div class="finding {6}" id="{0}">
    <div class="finding-header">
        <h3 class="collapsible" style="cursor: pointer;" onclick="document.getElementById('{0}-details').style.display = document.getElementById('{0}-details').style.display === 'none' ? 'block' : 'none'">{1} {2} {3} {4} {5}</h3>
        <span class="severity {6}">{7}</span>
        </div>
    <div class="finding-details" id="{0}-details">
        <div class="finding-meta-row">
            <div class="meta">
                <strong>File:</strong> {8} {9}<br>
                <strong>Source:</strong> {10}<br>
                <strong>Confidence:</strong> {11}<br>
                {12}</div>
        </div>
        <p>{13}</p>
"#,
        finding_div_id.clone(), // For id attribute
        encode_text(&finding.title),
        triage_badge,
        location_span,
        confidence_badge,
        cwe_badge,
        severity_class,
        encode_text(&finding.severity.to_string()),
        // Removed the second cwe_badge instance here to fix duplication bug
        encode_text(&finding.file_path),
        line_info,
        encode_text(&finding.sources.join(", ")),
        confidence_badge,
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
                String::new()
            } else {
                format!(r#"<br><strong>Source:</strong> {}"#, encode_text(model))
            }
        } else {
            String::new()
        },
        markdown_to_html(&finding.description)
    );

    // Show diff hunk if available
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
    if let Some((start, end)) = finding.statement_range {
        if finding.line_number.map(|l| l != start).unwrap_or(true) {
            meta_items.push(format!(
                r#"<strong>Statement range:</strong> lines {}-{}"#,
                start, end
            ));
        }
    }
    if let Some(notes) = &finding.verification_notes {
        meta_items.push(format!(
            r#"<strong>Verification notes:</strong> {}"#,
            markdown_to_html(notes)
        ));
    }
    if let Some(err) = &finding.verification_error {
        meta_items.push(format!(
            r#"<strong>Verification error:</strong> <span class="verification-error">{}</span>"#,
            encode_text(err)
        ));
    }
    if let Some(commit) = &finding.commit_reference {
        meta_items.push(format!(
            r#"<strong>Commit:</strong> {}"#,
            encode_text(commit)
        ));
    }
    if let Some(verdict) = &finding.triage_verdict {
        let verdict_text = match verdict {
            crate::findings::TriageVerdict::Pass => "Pass",
            crate::findings::TriageVerdict::Kill => "Kill",
            crate::findings::TriageVerdict::Downgrade { .. } => "Downgrade",
            crate::findings::TriageVerdict::ChainRequired { .. } => "Chain Required",
        };
        meta_items.push(format!(r#"<strong>Triage:</strong> {}"#, verdict_text));
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
