use crate::config::ScannerConfig;
use crate::findings::VulnerabilityFinding;
use chrono::Utc;
use std::fs;

use super::finding_renderer::render_finding;
use super::utilities::{
    build_empty_state_message, build_filter_buttons, build_summary_cards, calculate_severity_stats,
};

pub fn generate_html_report(
    findings: &[VulnerabilityFinding],
    output_path: &str,
    config: Option<&ScannerConfig>,
    llm_metrics: Option<crate::report::json::LlmMetricsSummary>,
) -> Result<(), String> {
    let scan_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let total_findings = findings.len();

    // Collect unique languages from findings for conditional Prism.js loading
    let mut languages: std::collections::HashSet<String> = std::collections::HashSet::new();
    for finding in findings {
        let lang = super::utilities::detect_language(&finding.file_path);
        if !lang.is_empty() {
            languages.insert(lang.to_string());
        }
        // Also check diff_hunk for diff language
        if finding.diff_hunk.is_some() {
            languages.insert("diff".to_string());
        }
    }

    // Generate Prism.js scripts for detected languages only
    let prism_scripts = languages
        .iter()
        .filter_map(|lang| {
            match lang.as_str() {
                "python" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-python.min.js\"></script>"),
                "javascript" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-javascript.min.js\"></script>"),
                "typescript" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-typescript.min.js\"></script>"),
                "rust" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-rust.min.js\"></script>"),
                "go" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-go.min.js\"></script>"),
                "java" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-java.min.js\"></script>"),
                "c" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-c.min.js\"></script>"),
                "cpp" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-cpp.min.js\"></script>"),
                "sql" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-sql.min.js\"></script>"),
                "yaml" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-yaml.min.js\"></script>"),
                "json" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-json.min.js\"></script>"),
                "bash" | "sh" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-bash.min.js\"></script>"),
                "diff" => Some("<script src=\"https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-diff.min.js\"></script>"),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join("\n    ");

    // Extract model names from config
    let models_html = if let Some(cfg) = config {
        let discovery_models = cfg.llm.phases.discovery.get_models();
        let verification_models = cfg.llm.phases.verification.get_models();
        let aggregation_models = cfg.llm.phases.aggregation.get_models();

        let discovery_html = if discovery_models.is_empty() {
            "Not configured".to_string()
        } else {
            discovery_models.join(", ")
        };

        let verification_html = if verification_models.is_empty() {
            "Not configured".to_string()
        } else {
            verification_models.join(", ")
        };

        let aggregation_html = if aggregation_models.is_empty() {
            "Not configured".to_string()
        } else {
            aggregation_models.join(", ")
        };

        format!(
            r#"<div class="metadata-item"><div class="metadata-label">Discovery Models</div><div class="metadata-value">{}</div></div>
                <div class="metadata-item"><div class="metadata-label">Verification Models</div><div class="metadata-value">{}</div></div>
                <div class="metadata-item"><div class="metadata-label">Aggregation Models</div><div class="metadata-value">{}</div></div>"#,
            discovery_html, verification_html, aggregation_html
        )
    } else {
        r#"<div class="metadata-item"><div class="metadata-label">AI Models</div><div class="metadata-value">Not configured</div></div>"#.to_string()
    };

    // Calculate statistics by severity
    let stats = calculate_severity_stats(findings);

    // Generate filter buttons
    let filter_buttons_html = build_filter_buttons(&stats);

    // Generate summary cards
    let summary_cards_html = build_summary_cards(&stats);

    // Calculate average confidence
    let avg_confidence = if findings.is_empty() {
        0.0
    } else {
        findings
            .iter()
            .map(|f| f.confidence_score as f64)
            .sum::<f64>()
            / findings.len() as f64
    };

    // Calculate verification stats
    let verified = findings
        .iter()
        .filter(|f| f.verification_status.is_some())
        .count();
    let already_reported = findings.iter().filter(|f| f.already_reported).count();

    // Format LLM metrics
    let llm_metrics_html = if let Some(metrics) = llm_metrics {
        let models_html: String = metrics
            .models
            .iter()
            .map(|m| {
                format!(
                    r#"<div class="metric-card">
                        <div class="metric-label">{}</div>
                        <div class="metric-value">{} requests</div>
                        <div class="metric-detail">{} successful, {} failed, {} cached</div>
                        <div class="metric-detail">{} tokens</div>
                    </div>"#,
                    html_escape::encode_text(&m.model_name),
                    m.total_requests,
                    m.successful_requests,
                    m.failed_requests,
                    m.cached_requests,
                    m.total_tokens
                )
            })
            .collect::<Vec<_>>()
            .join("");

        let operations_html: String = metrics
            .operations
            .iter()
            .map(|o| {
                format!(
                    r#"<div class="metric-card">
                        <div class="metric-label">{} ({})</div>
                        <div class="metric-value">{} requests</div>
                        <div class="metric-detail">{} successful, {} failed</div>
                    </div>"#,
                    html_escape::encode_text(&o.operation),
                    html_escape::encode_text(&o.phase),
                    o.requests,
                    o.successful,
                    o.failed
                )
            })
            .collect::<Vec<_>>()
            .join("");

        format!(
            r#"<div class="llm-metrics-section">
                <h2>LLM Usage Statistics</h2>
                <div class="metrics-summary">
                    <div class="metric-summary-item">
                        <div class="metric-label">Total Requests</div>
                        <div class="metric-value">{}</div>
                    </div>
                    <div class="metric-summary-item">
                        <div class="metric-label">Successful</div>
                        <div class="metric-value success">{}</div>
                    </div>
                    <div class="metric-summary-item">
                        <div class="metric-label">Failed</div>
                        <div class="metric-value error">{}</div>
                    </div>
                    <div class="metric-summary-item">
                        <div class="metric-label">Cached</div>
                        <div class="metric-value">{}</div>
                    </div>
                    <div class="metric-summary-item">
                        <div class="metric-label">Total Tokens</div>
                        <div class="metric-value">{}</div>
                    </div>
                    <div class="metric-summary-item">
                        <div class="metric-label">Avg Latency</div>
                        <div class="metric-value">{:.0} ms</div>
                    </div>
                </div>
                
                <h3>By Model</h3>
                <div class="metrics-grid">{}</div>
                
                <h3>By Operation</h3>
                <div class="metrics-grid">{}</div>
            </div>"#,
            metrics.total_requests,
            metrics.successful_requests,
            metrics.failed_requests,
            metrics.cached_requests,
            metrics.total_tokens,
            metrics.avg_latency_ms,
            models_html,
            operations_html
        )
    } else {
        String::new()
    };
    // Add empty state message if no findings
    let empty_state = if total_findings == 0 {
        build_empty_state_message()
    } else {
        String::new()
    };

    let mut html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BACO Security Report</title>
    <!-- Prism.js for syntax highlighting -->
    <link href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js"></script>
    {}
    <script>
        function filterFindings(severity) {{
            const findings = document.querySelectorAll('.finding');
            findings.forEach(f => {{
                if (severity === 'all' || f.classList.contains(severity)) {{
                    f.style.display = 'block';
                }} else {{
                    f.style.display = 'none';
                }}
            }});
            updateCounts();
        }}

        function toggleFinding(id) {{
            const el = document.getElementById(id);
            el.style.display = el.style.display === 'none' ? 'block' : 'none';
        }}

        function toggleAll(expand) {{
            const details = document.querySelectorAll('.finding-details');
            details.forEach(d => {{
                d.style.display = expand ? 'block' : 'none';
            }});
        }}

        function updateCounts() {{
            const activeFilter = document.querySelector('.filter-btn.active').dataset.filter;
            document.querySelectorAll('.finding').forEach(f => {{
                const isVisible = activeFilter === 'all' || f.classList.contains(activeFilter);
                f.style.display = isVisible ? 'block' : 'none';
            }});
        }}

        function searchFindings() {{
            const query = document.getElementById('search').value.toLowerCase();
            document.querySelectorAll('.finding').forEach(f => {{
                const text = f.textContent.toLowerCase();
                f.style.display = text.includes(query) ? 'block' : 'none';
            }});
        }}
    </script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a1a; background: #f0f2f5; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 15px; margin-bottom: 30px; font-size: 2rem; }}
        h2 {{ color: #333; margin-top: 40px; margin-bottom: 20px; font-size: 1.5rem; }}
        h3 {{ color: #1a1a1a; font-size: 1.1rem; margin-bottom: 12px; cursor: pointer; }}
        
        .metadata {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .metadata-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .metadata-item {{ background: white; padding: 12px; border-radius: 6px; border: 1px solid #dee2e6; }}
        .metadata-label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }}
        .metadata-value {{ font-size: 0.95rem; color: #212529; font-weight: 500; }}
        
        .stats-dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 30px 0; }}
        .stat-card {{ background: white; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-card .value {{ font-size: 2rem; font-weight: 700; color: #212529; }}
        .stat-card .label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; margin-top: 5px; }}
        
        .summary {{ display: flex; gap: 20px; margin: 30px 0; flex-wrap: wrap; }}
        .card {{ flex: 1; min-width: 150px; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.08); cursor: pointer; transition: transform 0.2s; }}
        .card:hover {{ transform: translateY(-2px); }}
        .card.critical {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; }}
        .card.high {{ background: linear-gradient(135deg, #fd7e14, #e8590c); color: white; }}
        .card.medium {{ background: linear-gradient(135deg, #ffc107, #ffb700); color: #1a1a1a; }}
        .card.low {{ background: linear-gradient(135deg, #28a745, #218838); color: white; }}
        .card.info {{ background: linear-gradient(135deg, #17a2b8, #138496); color: white; }}
        .card h3 {{ font-size: 2.5rem; margin-bottom: 5px; font-weight: 700; color: inherit; }}
        .card p {{ font-size: 0.9rem; opacity: 0.9; text-transform: capitalize; }}
        
        .filters {{ display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap; align-items: center; }}
        .filter-btn {{ padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; }}
        .filter-btn.active {{ box-shadow: 0 0 0 2px #0066cc; }}
        .filter-btn.critical {{ background: #fee2e2; color: #dc3545; }}
        .filter-btn.high {{ background: #ffebe0; color: #fd7e14; }}
        .filter-btn.medium {{ background: #fff3cd; color: #856404; }}
        .filter-btn.low {{ background: #d4edda; color: #155724; }}
        .filter-btn.info {{ background: #d1ecf1; color: #0c5460; }}
        .filter-btn.all {{ background: #e9ecef; color: #495057; }}
        
        .search-box {{ flex: 1; min-width: 200px; }}
        .search-box input {{ width: 100%; padding: 10px 15px; border: 1px solid #dee2e6; border-radius: 6px; font-size: 0.95rem; }}
        
        .toggle-btns {{ display: flex; gap: 10px; }}
        .toggle-btn {{ padding: 8px 12px; border: 1px solid #dee2e6; border-radius: 6px; background: white; cursor: pointer; }}
        
        /* LLM Metrics Section */
        .llm-metrics-section {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 25px; margin: 30px 0; }}
        .llm-metrics-section h2 {{ color: #0066cc; margin-bottom: 20px; font-size: 1.5rem; }}
        .llm-metrics-section h3 {{ color: #333; margin: 25px 0 15px 0; font-size: 1.2rem; }}
        .metrics-summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .metric-summary-item {{ background: white; padding: 15px; border-radius: 6px; border: 1px solid #dee2e6; text-align: center; }}
        .metric-summary-item .metric-label {{ font-size: 0.8rem; color: #6c757d; text-transform: uppercase; margin-bottom: 8px; }}
        .metric-summary-item .metric-value {{ font-size: 1.8rem; font-weight: 700; color: #212529; }}
        .metric-summary-item .metric-value.success {{ color: #28a745; }}
        .metric-summary-item .metric-value.error {{ color: #dc3545; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }}
        .metric-card {{ background: white; padding: 15px; border-radius: 6px; border: 1px solid #dee2e6; }}
        .metric-card .metric-label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; margin-bottom: 8px; font-weight: 600; }}
        .metric-card .metric-value {{ font-size: 1.4rem; font-weight: 700; color: #212529; margin-bottom: 5px; }}
        .metric-card .metric-detail {{ font-size: 0.85rem; color: #495057; margin-bottom: 3px; }}
        
        .finding {{ background: #fff; border-left: 5px solid #0066cc; padding: 20px; margin: 20px 0; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border: 1px solid #e9ecef; }}
        .finding.critical {{ border-left-color: var(--critical); background: #fff5f5; }}
        .finding.high {{ border-left-color: var(--high); background: #fff8f0; }}
        .finding.medium {{ border-left-color: var(--medium); background: #fffbf0; }}
        .finding.low {{ border-left-color: var(--low); background: #f0fff4; }}
        .finding.info {{ border-left-color: var(--info); background: #f0f9fb; }}
        .cwe-badge {{margin:2px}}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }}
        .finding-header h3 {{ margin: 0; flex: 1; }}
        
        .severity {{ display: inline-block; padding: 5px 12px; border-radius: 6px; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-left: 10px; white-space: nowrap; }}
        .severity.critical {{ background: var(--critical); color: white; }}
        .severity.high {{ background: var(--high); color: white; }}
        .severity.medium {{ background: var(--medium); color: #1a1a1a; }}
        .severity.low {{ background: var(--low); color: white; }}
        .severity.info {{ background: var(--info); color: white; }}
        
        .meta {{ color: #495057; font-size: 0.9rem; margin: 10px 0; background: #f8f9fa; padding: 10px; border-radius: 4px; }}
        .meta strong {{ color: #343a40; }}
        .meta a {{ color: #0066cc; }}
        
        .code-comparison {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0; }}
        @media (max-width: 768px) {{ .code-comparison {{ grid-template-columns: 1fr; }} }}
        
        .code-panel {{ background: #1e1e1e; border-radius: 6px; overflow: hidden; }}
        .code-panel.before {{ border-left: 4px solid #dc3545; }}
        .code-panel.after {{ border-left: 4px solid #28a745; }}
        .code-panel-header {{ background: #2d2d2d; padding: 8px 15px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; color: #888; }}
        .code-panel.before .code-panel-header {{ background: #3d2020; color: #f88; }}
        .code-panel.after .code-panel-header {{ background: #203d20; color: #8f8; }}
        .code-snippet {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; font-family: Consolas, Monaco, monospace; overflow-x: auto; font-size: 0.9rem; line-height: 1.5; border: 1px solid #3c3c3c; white-space: pre-wrap; word-break: break-all; }}
        
        .code-snippet-single {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; font-family: Consolas, Monaco, monospace; overflow-x: auto; margin: 15px 0; font-size: 0.9rem; line-height: 1.5; border: 1px solid #3c3c3c; white-space: pre-wrap; word-break: break-all; }}
        
        .diff-hunk {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; margin: 15px 0; overflow: hidden; }}
        .diff-header {{ background: #161b22; color: #c9d1d9; padding: 10px 15px; font-weight: 600; border-bottom: 1px solid #30363d; font-size: 0.9rem; }}
        .diff-code {{ background: #0d1117; color: #c9d1d9; padding: 15px; margin: 0; font-family: Consolas, Monaco, monospace; overflow-x: auto; font-size: 0.85rem; line-height: 1.5; white-space: pre; }}
        .diff-code .diff-context {{ color: #8b949e; }}
        .diff-code .diff-deleted {{ color: #ffeba7; background: rgba(255, 235, 167, 0.1); }}
        .diff-code .diff-added {{ color: #7ee787; background: rgba(126, 231, 135, 0.1); }}
        
        .poc-section {{ margin: 15px 0; }}
        .code-panel.poc {{ border-left: 4px solid #6f42c1; }}
        .code-panel.poc .code-panel-header {{ background: #2d2538; color: #c9b8e0; }}
        .code-panel.mitigation {{ border-left: 4px solid #28a745; }}
        .code-panel.mitigation .code-panel-header {{ background: #253828; color: #b8e0c9; }}
        
        .recommendation {{ background: #e7f3ff; border: 1px solid #b3d7ff; border-radius: 6px; padding: 15px; margin: 15px 0; color: #004085; }}
        .recommendation strong {{ color: #0056b3; }}
        .recommendation ul, .recommendation ol {{ margin: 10px 0; padding-left: 25px; }}
        .recommendation li {{ margin: 5px 0; }}
        .recommendation p {{ margin: 10px 0; }}
        
        .confidence-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
        .agent-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; background: #6f42c1; color: white; }}
        .confidence-high {{ background: #d4edda; color: #155724; }}
        .confidence-medium {{ background: #fff3cd; color: #856404; }}
        .confidence-low {{ background: #f8d7da; color: #721c24; }}
        
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 0.85rem; text-align: center; }}
        
        .finding-count {{ font-size: 0.9rem; color: #6c757d; margin-bottom: 15px; }}
        
        .finding-details {{ margin-top: 15px; }}
        .info-details ul, .info-details ol {{margin-left:20px}}
        
        .collapsible {{ cursor: pointer; user-select: none; }}
        .collapsible::before {{ content: "▼"; margin-right: 8px; font-size: 0.8rem; }}
        .collapsible.collapsed::before {{ content: "▶"; }}

        @media print {{
            body {{ background: white; padding: 0; color: black; }}
            .container {{ box-shadow: none; border: none; padding: 0; width: 100%; max-width: none; }}
            .filters, .search-box, .toggle-btns, .toggle-btn {{ display: none !important; }}
            .severity, .confidence-badge, .agent-badge, .triage-badge, .cwe-badge {{ 
                border: 1px solid #000; 
                color: black !important; 
                background: transparent !important; 
            }}
            .finding {{ 
                page-break-inside: avoid; 
                border: 1px solid #ccc; 
                background: white !important; 
                margin-bottom: 20px; 
                box-shadow: none; 
            }}
            .stat-card, .card {{ 
                page-break-inside: avoid; 
                border: 1px solid #ccc; 
                background: white !important; 
                color: black !important; 
            }}
            .card h3, .card p {{ color: black !important; }}
            .code-panel, .code-snippet, .diff-hunk {{ 
                background: #f9f9f9 !important; 
                color: black !important; 
                border: 1px solid #ccc; 
            }}
            .code-panel-header, .diff-header {{ 
                background: #eee !important; 
                color: #333 !important; 
            }}
            a {{ color: black; text-decoration: underline; }}
            h1, h2, h3 {{ color: black !important; border-color: #333; }}
        }}
    
</head>
<body>
    <div class="container">
        <h1>🔒 BACO Security Vulnerability Report</h1>
        
        <h2>Scan Metadata</h2>
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Scan Date</div>
                    <div class="metadata-value">{}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Total Findings</div>
                    <div class="metadata-value">{}</div>
                </div>
                {}
            </div>
        </div>
        
        {}
        
        <h2>Statistics Dashboard</h2>
        <div class="stats-dashboard">
            <div class="stat-card">
                <div class="value">{:.1}%</div>
                <div class="label">Avg Confidence</div>
            </div>
            <div class="stat-card">
                <div class="value">{}</div>
                <div class="label">Verified</div>
            </div>
            <div class="stat-card">
                <div class="value">{}</div>
                <div class="label">Already Reported</div>
            </div>
            <div class="stat-card">
                <div class="value">{}</div>
                <div class="label">Unique Files</div>
            </div>
        </div>
        
        <h2>Summary by Severity</h2>
        <div class="summary">
            {}
        </div>
        
        <h2>Detailed Findings</h2>
        {}
        <div class="filters">
            <button class="filter-btn all active" data-filter="all" onclick="document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active')); this.classList.add('active'); filterFindings('all')">All</button>
            {}
            <div class="search-box">
                <input type="text" id="search" placeholder="Search findings..." onkeyup="searchFindings()">
            </div>
            <div class="toggle-btns">
                <button class="toggle-btn" onclick="toggleAll(true)">Expand All</button>
                <button class="toggle-btn" onclick="toggleAll(false)">Collapse All</button>
            </div>
        </div>
        <p class="finding-count">Showing {} findings</p>
    "#,
        prism_scripts,
        scan_date,
        total_findings,
        models_html,
        llm_metrics_html,
        avg_confidence * 100.0,
        verified,
        already_reported,
        findings
            .iter()
            .map(|f| &f.file_path)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        summary_cards_html,
        empty_state,
        filter_buttons_html,
        total_findings
    );

    // Generate finding cards
    for (finding_id, finding) in findings.iter().enumerate() {
        html.push_str(&render_finding(finding, finding_id));
    }

    html.push_str(&format!(
        r#"<div class="footer">
<p>Generated by BACO Security Scanner v{} | {} findings analyzed</p>
</div>
</body>
</html>"#,
        env!("CARGO_PKG_VERSION"),
        findings.len()
    ));

    // Create parent directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    fs::write(output_path, html).map_err(|e| format!("Failed to write HTML report: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

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
        }
    }

    #[test]
    fn test_generate_html_report_creates_file() {
        let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
        let output_path = "/tmp/test_html_report.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());
        assert!(std::path::Path::new(output_path).exists());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("BACO Security Report"));
        assert!(content.contains("<!DOCTYPE html>"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_empty_findings() {
        let findings: Vec<VulnerabilityFinding> = vec![];
        let output_path = "/tmp/test_empty_html_report.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("No Security Issues Found"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_multiple_severities() {
        let findings = vec![
            make_finding(Severity::Critical, "src/critical.rs", Some(1)),
            make_finding(Severity::High, "src/high.rs", Some(2)),
            make_finding(Severity::Medium, "src/medium.rs", Some(3)),
            make_finding(Severity::Low, "src/low.rs", Some(4)),
            make_finding(Severity::Info, "src/info.rs", Some(5)),
        ];
        let output_path = "/tmp/test_multi_severity_report.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("Critical"));
        assert!(content.contains("High"));
        assert!(content.contains("Medium"));
        assert!(content.contains("Low"));
        assert!(content.contains("Info"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_contains_finding_elements() {
        let mut finding = make_finding(Severity::High, "src/test.rs", Some(42));
        finding.title = "SQL Injection Vulnerability".to_string();
        finding.cwe_id = Some("CWE-89".to_string());
        let findings = vec![finding];
        let output_path = "/tmp/test_finding_elements.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("SQL Injection Vulnerability"));
        assert!(content.contains("CWE-89"));
        assert!(content.contains("finding-0"));
        assert!(content.contains("severity high"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_creates_parent_dirs() {
        let findings = vec![make_finding(Severity::Low, "src/lib.rs", Some(5))];
        let temp_dir = std::env::temp_dir().join("baco_test_nested");
        let output_path = temp_dir.join("nested").join("report.html");

        let _ = std::fs::remove_dir_all(&temp_dir);

        let result = generate_html_report(&findings, output_path.to_str().unwrap(), None, None);

        assert!(result.is_ok());
        assert!(output_path.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_generate_html_report_with_confidence_stats() {
        let mut finding1 = make_finding(Severity::High, "src/test1.rs", Some(10));
        finding1.confidence_score = 0.95;
        let mut finding2 = make_finding(Severity::Medium, "src/test2.rs", Some(20));
        finding2.confidence_score = 0.65;
        let findings = vec![finding1, finding2];
        let output_path = "/tmp/test_confidence_stats.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("Avg Confidence"));
        assert!(content.contains("80")); // average of 95 and 65

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_contains_filter_buttons() {
        let findings = vec![
            make_finding(Severity::Critical, "src/crit.rs", Some(1)),
            make_finding(Severity::High, "src/high.rs", Some(2)),
        ];
        let output_path = "/tmp/test_filter_buttons.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("filter-btn"));
        assert!(content.contains("Critical (1)"));
        assert!(content.contains("High (1)"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_contains_summary_cards() {
        let findings = vec![
            make_finding(Severity::Critical, "src/crit.rs", Some(1)),
            make_finding(Severity::High, "src/high.rs", Some(2)),
            make_finding(Severity::Medium, "src/med.rs", Some(3)),
        ];
        let output_path = "/tmp/test_summary_cards.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("card critical"));
        assert!(content.contains("card high"));
        assert!(content.contains("card medium"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_with_python_file() {
        let mut finding = make_finding(Severity::High, "src/vuln.py", Some(42));
        finding.diff_hunk = Some("-old code\n+new code".to_string());
        let findings = vec![finding];
        let output_path = "/tmp/test_python_report.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("prism-python"));
        assert!(content.contains("language-diff"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_with_rust_file() {
        let mut finding = make_finding(Severity::Medium, "src/lib.rs", Some(100));
        finding.diff_hunk = Some("-unsafe code\n+safe code".to_string());
        let findings = vec![finding];
        let output_path = "/tmp/test_rust_report.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("prism-rust"));
        assert!(content.contains("language-diff"));

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_statistics() {
        let findings = vec![
            make_finding(Severity::Critical, "src/a.rs", Some(1)),
            make_finding(Severity::Critical, "src/b.rs", Some(2)),
            make_finding(Severity::High, "src/c.rs", Some(3)),
        ];
        let output_path = "/tmp/test_statistics.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("2")); // Critical count in card
        assert!(content.contains("1")); // High count in card
        assert!(content.contains("3 findings")); // Total findings

        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn test_generate_html_report_contains_metadata() {
        let findings = vec![make_finding(Severity::Low, "src/test.rs", Some(1))];
        let output_path = "/tmp/test_metadata.html";

        let _ = std::fs::remove_file(output_path);

        let result = generate_html_report(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("Scan Metadata"));
        assert!(content.contains("Scan Date"));
        assert!(content.contains("Total Findings"));

        let _ = std::fs::remove_file(output_path);
    }
}
