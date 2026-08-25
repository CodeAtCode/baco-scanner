use crate::findings::VulnerabilityFinding;
use html_escape::encode_text;

use super::utilities::{detect_language, markdown_to_html};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, TriageVerdict, VerificationStatus};

    fn make_finding(severity: Severity, file: &str, line: Option<u32>) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: file.to_string(),
            line_number: line,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
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
    fn test_render_finding_critical_severity() {
        let finding = make_finding(Severity::Critical, "src/main.rs", Some(42));
        let html = render_finding(&finding, 0);

        assert!(html.contains("finding critical"));
        assert!(html.contains("Critical"));
        assert!(html.contains("src/main.rs"));
        assert!(html.contains(":42"));
    }

    #[test]
    fn test_render_finding_high_severity() {
        let finding = make_finding(Severity::High, "src/app.rs", Some(10));
        let html = render_finding(&finding, 1);

        assert!(html.contains("finding high"));
        assert!(html.contains("High"));
    }

    #[test]
    fn test_render_finding_medium_severity() {
        let finding = make_finding(Severity::Medium, "src/lib.rs", Some(5));
        let html = render_finding(&finding, 2);

        assert!(html.contains("finding medium"));
        assert!(html.contains("Medium"));
    }

    #[test]
    fn test_render_finding_low_severity() {
        let finding = make_finding(Severity::Low, "src/utils.rs", Some(100));
        let html = render_finding(&finding, 3);

        assert!(html.contains("finding low"));
        assert!(html.contains("Low"));
    }

    #[test]
    fn test_render_finding_info_severity() {
        let finding = make_finding(Severity::Info, "src/info.rs", None);
        let html = render_finding(&finding, 4);

        assert!(html.contains("finding info"));
        assert!(html.contains("Info"));
    }

    #[test]
    fn test_render_finding_without_line_number() {
        let finding = make_finding(Severity::High, "src/unknown.rs", None);
        let html = render_finding(&finding, 5);

        assert!(html.contains("src/unknown.rs"));
        assert!(!html.contains(":None"));
    }

    #[test]
    fn test_render_finding_with_cwe_id() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.cwe_id = Some("CWE-79".to_string());

        let html = render_finding(&finding, 6);

        assert!(html.contains("CWE-79"));
        assert!(html.contains("cwe-badge"));
    }

    #[test]
    fn test_render_finding_with_code_snippet() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.code_snippet = Some("unsafe code here".to_string());

        let html = render_finding(&finding, 8);

        assert!(html.contains("code-snippet-single"));
        assert!(html.contains("unsafe code here"));
    }

    #[test]
    fn test_render_finding_with_recommendation() {
        let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
        finding.recommendation = Some("Use safe alternatives".to_string());

        let html = render_finding(&finding, 9);

        assert!(html.contains("Recommendation"));
        assert!(html.contains("Use safe alternatives"));
    }

    #[test]
    fn test_render_finding_with_confidence_high() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.confidence_score = 0.95;

        let html = render_finding(&finding, 10);

        assert!(html.contains("confidence-high"));
        assert!(html.contains("95"));
    }

    #[test]
    fn test_render_finding_with_confidence_medium() {
        let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
        finding.confidence_score = 0.5;

        let html = render_finding(&finding, 11);

        assert!(html.contains("confidence-medium"));
    }

    #[test]
    fn test_render_finding_with_confidence_low() {
        let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
        finding.confidence_score = 0.3;

        let html = render_finding(&finding, 12);

        assert!(html.contains("confidence-low"));
    }

    #[test]
    fn test_render_finding_escapes_html_in_title() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.title = "<script>alert('xss')</script>".to_string();

        let html = render_finding(&finding, 13);

        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_render_finding_with_multiple_sources() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

        let html = render_finding(&finding, 14);

        assert!(html.contains("semgrep"));
        assert!(html.contains("llm"));
    }

    #[test]
    fn test_render_finding_generates_unique_id() {
        let mut finding1 = make_finding(Severity::High, "src/test.rs", Some(10));
        finding1.id = "f16".to_string();
        let mut finding2 = make_finding(Severity::High, "src/test.rs", Some(10));
        finding2.id = "f17".to_string();

        let html1 = render_finding(&finding1, 0);
        let html2 = render_finding(&finding2, 1);

        assert!(html1.contains("id=\"finding-0\""));
        assert!(html2.contains("id=\"finding-1\""));
    }

    #[test]
    fn test_render_finding_with_diff_hunk() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.diff_hunk = Some("-old line\n+new line".to_string());

        let html = render_finding(&finding, 15);

        assert!(html.contains("diff-hunk"));
        assert!(html.contains("diff-header"));
        assert!(html.contains("-old line"));
        assert!(html.contains("+new line"));
    }

    #[test]
    fn test_render_finding_with_poc_and_mitigation() {
        let mut finding = make_finding(Severity::Critical, "src/vuln.rs", Some(25));
        finding.poc_code = Some("exploit()".to_string());
        finding.mitigation_code = Some("safe_fix()".to_string());
        finding.poc_format = Some("rust".to_string());

        let html = render_finding(&finding, 16);

        assert!(html.contains("poc-section"));
        assert!(html.contains("Proof of Concept"));
        assert!(html.contains("Mitigation Example"));
        assert!(html.contains("exploit()"));
        assert!(html.contains("safe_fix()"));
    }

    #[test]
    fn test_render_finding_with_triage_verdict_pass() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.triage_verdict = Some(TriageVerdict::Pass);

        let html = render_finding(&finding, 17);

        assert!(html.contains("VERIFIED TP"));
        assert!(html.contains("triage-badge true-positive"));
    }

    #[test]
    fn test_render_finding_with_triage_verdict_kill() {
        let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
        finding.triage_verdict = Some(TriageVerdict::Kill);

        let html = render_finding(&finding, 18);

        assert!(html.contains("FALSE POSITIVE"));
        assert!(html.contains("triage-badge false-positive"));
    }

    #[test]
    fn test_render_finding_with_agent_mode() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.agent_mode = true;
        finding.llm_model = Some("gpt-4".to_string());

        let html = render_finding(&finding, 19);

        assert!(html.contains("agent-badge"));
        assert!(html.contains("Agent"));
        assert!(html.contains("gpt-4"));
    }

    #[test]
    fn test_render_finding_with_priority_score() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.priority_score = Some(0.85);

        let html = render_finding(&finding, 20);

        assert!(html.contains("Priority"));
        assert!(html.contains("85.0"));
    }

    #[test]
    fn test_render_finding_with_verification_status() {
        let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
        finding.verification_status = Some(VerificationStatus::Confirmed);

        let html = render_finding(&finding, 21);

        assert!(html.contains("Verification"));
        assert!(html.contains("confirmed"));
    }

    #[test]
    fn test_render_finding_with_ticket_reference() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.ticket_reference = Some("SEC-123".to_string());

        let html = render_finding(&finding, 22);

        assert!(html.contains("Ticket"));
        assert!(html.contains("SEC-123"));
    }

    #[test]
    fn test_render_finding_with_commit_reference() {
        let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
        finding.commit_reference = Some("abc123def".to_string());

        let html = render_finding(&finding, 23);

        assert!(html.contains("Commit"));
        assert!(html.contains("abc123def"));
    }

    #[test]
    fn test_render_finding_with_statement_range() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.statement_range = Some((15, 20));

        let html = render_finding(&finding, 24);

        assert!(html.contains("Statement range"));
        assert!(html.contains("lines 15-20"));
    }

    #[test]
    fn test_render_finding_with_verification_notes() {
        let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
        finding.verification_notes = Some("Manual review confirmed".to_string());

        let html = render_finding(&finding, 25);

        assert!(html.contains("Verification notes"));
        assert!(html.contains("Manual review confirmed"));
    }

    #[test]
    fn test_render_finding_with_verification_error() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.verification_error = Some("Connection timeout".to_string());

        let html = render_finding(&finding, 26);

        assert!(html.contains("Verification error"));
        assert!(html.contains("verification-error"));
        assert!(html.contains("Connection timeout"));
    }

    #[test]
    fn test_render_finding_with_cross_file_references() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
        finding.cross_file_references =
            Some(vec!["src/utils.rs".to_string(), "src/lib.rs".to_string()]);

        let html = render_finding(&finding, 27);

        assert!(html.contains("Cross-file refs"));
        assert!(html.contains("src/utils.rs"));
    }

    #[test]
    fn test_render_finding_with_all_metadata() {
        let finding = VulnerabilityFinding {
            id: "full-test".to_string(),
            title: "Comprehensive Test".to_string(),
            description: "Testing all fields".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/sql.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("sql.query(user_input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use parameterized queries".to_string()),
            code_location: None,
            already_reported: true,
            sources: vec!["semgrep".to_string()],
            commit_reference: Some("def456".to_string()),
            ticket_reference: Some("SEC-456".to_string()),
            priority_score: Some(0.9),
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Confirmed),
            verification_notes: Some("Confirmed by security team".to_string()),
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: Some("attack_payload()".to_string()),
            mitigation_code: Some("safe_query()".to_string()),
            poc_format: Some("python".to_string()),
            llm_model: Some("claude-3".to_string()),
            agent_mode: true,
            statement_range: Some((40, 45)),
            triage_verdict: Some(TriageVerdict::Pass),
            evidence: vec![],
            verification_tier: None,
        };

        let html = render_finding(&finding, 28);

        // Verify key elements are present
        assert!(html.contains("Comprehensive Test"));
        assert!(html.contains("Critical"));
        assert!(html.contains("CWE-89"));
        assert!(html.contains("sql.rs"));
        assert!(html.contains(":42"));
        assert!(html.contains("95"));
        assert!(html.contains("VERIFIED TP"));
        assert!(html.contains("agent-badge"));
        assert!(html.contains("claude-3"));
        assert!(html.contains("Priority"));
        assert!(html.contains("SEC-456"));
        assert!(html.contains("def456"));
        assert!(html.contains("attack_payload()"));
        assert!(html.contains("safe_query()"));
        assert!(html.contains("Statement range"));
        assert!(html.contains("Verification notes"));
    }
}
