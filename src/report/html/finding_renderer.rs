use crate::findings::VulnerabilityFinding;
use html_escape::encode_text;

pub(super) use super::utilities::markdown_to_html;

pub fn render_finding(finding: &VulnerabilityFinding, finding_id: usize) -> String {
    render_finding_with_id(finding, &format!("finding-{}", finding_id))
}

pub fn render_finding_with_id(finding: &VulnerabilityFinding, finding_id: &str) -> String {
    let severity_class = super::presenter::severity_class(finding.severity);
    let confidence_class = super::presenter::confidence_class(finding.confidence_score);
    let finding_div_id = finding_id.to_string();

    let line_info = finding
        .line_number
        .map(|l| format!(":{}", l))
        .unwrap_or_default();

    let cwe_badge = super::presenter::build_cwe_badge_html(&finding.cwe_id);

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

    let location_span = if let Some(line) = finding.line_number {
        format!(
            r#"<span class="finding-location">{}:{}</span>"#,
            encode_text(&finding.file_path),
            line
        )
    } else {
        encode_text(&finding.file_path).to_string()
    };

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
        finding_div_id.clone(),
        encode_text(&finding.title),
        triage_badge,
        location_span,
        confidence_badge,
        cwe_badge,
        severity_class,
        encode_text(&finding.severity.to_string()),
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

    let code_presenter = super::presenter::CodeSnippetPresenter::new(finding);
    html.push_str(&code_presenter.render_html(&finding.file_path));

    let rec_presenter = super::presenter::RecommendationPresenter::new(finding);
    html.push_str(&rec_presenter.render_html());

    let sections_presenter = super::presenter::CodeSectionPresenter::new(finding);
    if sections_presenter.has_content() {
        html.push_str(r#"<div class="poc-section">"#);
        html.push_str(&sections_presenter.render_html());
        html.push_str("</div>");
    }

    let meta_rows = super::presenter::build_metadata_rows(finding);
    if !meta_rows.is_empty() {
        html.push_str(&format!(
            r#"<div class="meta">{}</div>"#,
            meta_rows.join("<br>")
        ));
    }

    html.push_str("</div></div>");
    html
}
