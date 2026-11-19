//! Injection boundaries in the HTML report.
//!
//! The report renders values from a repository we did not write: the file path is
//! a filesystem path, and the CWE id is text a model produced while reading that
//! repository. Both land in HTML *attribute* contexts, where escaping for text is
//! not enough — `encode_text` leaves `"` alone, so a quote in the value closes the
//! attribute and starts a new one.
//!
//! Every test feeds a hostile value that contains only a quote, no `<` or `&`,
//! because text escaping already neutralises those. The quote is the shape an
//! attacker actually controls, and it must be escaped for the attribute context.
//!
//! The assertions read the attribute value the browser would see, not the whole
//! document: a quote is legitimate in element text, so a whole-document search
//! cannot tell the two contexts apart.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::html::finding_renderer;
use baco::report::presenter;

fn finding(cwe_id: Option<String>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id,
        file_path: "src/handler.rs".to_string(),
        line_number: Some(42),
        ..Default::default()
    }
}

/// The value of the first `name="…"` attribute — what a browser reads as that
/// attribute's value.
fn attribute_value(html: &str, name: &str) -> String {
    let marker = format!("{name}=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} attribute in:\n{html}"))
        + marker.len();
    let rest = &html[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("{name} attribute is not terminated:\n{html}"));
    rest[..end].to_string()
}

#[test]
fn a_quote_in_the_finding_id_cannot_close_the_id_attribute() {
    let hostile = "x\" onmouseover=\"alert(1)";
    let html = finding_renderer::render_finding_with_id(&finding(None), hostile);

    assert_eq!(
        attribute_value(&html, "id"),
        "x&quot; onmouseover=&quot;alert(1)",
        "the id must be escaped for the attribute context:\n{html}"
    );
}

#[test]
fn the_header_handler_does_not_depend_on_the_finding_id() {
    let plain = finding_renderer::render_finding_with_id(&finding(None), "finding-1");
    let hostile =
        finding_renderer::render_finding_with_id(&finding(None), "x\" onmouseover=\"alert(1)");

    assert_eq!(
        attribute_value(&plain, "onclick"),
        attribute_value(&hostile, "onclick"),
        "the handler interpolates the id, so untrusted text reaches a script context"
    );
}

#[test]
fn a_quote_in_the_cwe_id_cannot_close_the_href_attribute() {
    let hostile = Some("123\" onmouseover=\"alert(1)".to_string());
    let rows = presenter::build_metadata_rows(&finding(hostile)).join("<br>");

    assert_eq!(
        attribute_value(&rows, "href"),
        "https://cwe.mitre.org/data/definitions/123&quot; onmouseover=&quot;alert(1).html",
        "the cwe id must be escaped for the attribute context:\n{rows}"
    );
}

#[test]
fn the_cwe_link_escapes_its_href() {
    let hostile = Some("42\" onload=\"alert(1)".to_string());
    let html = presenter::build_cwe_link_html(&hostile);

    assert_eq!(
        attribute_value(&html, "href"),
        "https://cwe.mitre.org/data/definitions/42&quot; onload=&quot;alert(1).html",
        "the href must be escaped for the attribute context:\n{html}"
    );
}
