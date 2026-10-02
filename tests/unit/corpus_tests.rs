//! Regression corpus for measuring scanner precision and recall.
//!
//! This test module loads the corpus manifest, runs the scanner's refutation
//! logic on each case, and asserts that precision and recall meet minimum
//! thresholds. A regression in the refutation logic will cause metrics to move.
//!
//! **Teeth experiment**: After writing this harness, break the production
//! refutation in `src/llm_analysis.rs` (e.g., `function_names_in_title`) or
//! `src/scanner/phases/llm_phases/verification.rs` (e.g., `body_of`), run:
//!
//! ```bash
//! cargo test --test unit_tests corpus
//! ```
//!
//! The metrics should move and at least one assertion should fail. Restore the
//! file and confirm the suite is green again.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::verification::refute_with_primitive_check;
use toml::Value;

/// Extract function name at a given line (1-indexed)
fn extract_function_name_at_line(content: &str, target_line: usize) -> String {
    for (line_num, line) in content.lines().enumerate() {
        if line_num + 1 == target_line {
            // Look for function declaration patterns
            if let Some(name) = extract_php_function_name(line) {
                return name;
            }
        }
    }
    // If not on the target line, search nearby lines
    let lines: Vec<&str> = content.lines().collect();
    let start = if target_line > 1 { target_line - 2 } else { 0 };
    let end = std::cmp::min(target_line + 2, lines.len());

    for line in lines.iter().skip(start).take(end - start) {
        if let Some(name) = extract_php_function_name(line) {
            return name;
        }
    }

    "unknown".to_string()
}

fn extract_php_function_name(line: &str) -> Option<String> {
    // Match: function name(
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("function ") {
        let name_end = rest.find('(')?;
        let name = rest[..name_end].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// Corpus case from the manifest
#[expect(dead_code)]
#[derive(Debug)]
struct CorpusCase {
    id: String,
    fixture: PathBuf,
    language: String,
    description: String,
    expected_findings: Vec<ExpectedFinding>,
    expected_refutation: bool,
}

#[derive(Debug)]
struct ExpectedFinding {
    line: u32,
    cwe: String,
    description: String,
}

#[derive(Debug)]
struct Thresholds {
    precision: f64,
    recall: f64,
}

/// Load the corpus manifest
fn load_corpus(
    manifest_path: &Path,
) -> Result<(Vec<CorpusCase>, Thresholds), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(manifest_path)?;
    let parsed: Value = toml::from_str(&content)?;

    let mut cases = Vec::new();
    if let Some(Value::Array(cases_array)) = parsed.get("cases") {
        for case_value in cases_array {
            let id = case_value
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fixture = case_value
                .get("fixture")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let language = case_value
                .get("language")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let description = case_value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let expected_refutation = case_value
                .get("expected_refutation")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut expected_findings = Vec::new();
            if let Some(Value::Array(findings_array)) = case_value.get("expected_findings") {
                for finding_value in findings_array {
                    let line = finding_value
                        .get("line")
                        .and_then(|v| v.as_integer())
                        .unwrap_or(0) as u32;
                    let cwe = finding_value
                        .get("cwe")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let desc = finding_value
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    expected_findings.push(ExpectedFinding {
                        line,
                        cwe,
                        description: desc,
                    });
                }
            }

            cases.push(CorpusCase {
                id,
                fixture: PathBuf::from(fixture),
                language,
                description,
                expected_findings,
                expected_refutation,
            });
        }
    }

    // Load thresholds
    let thresholds = if let Some(thresholds_value) = parsed.get("min_thresholds") {
        let precision = thresholds_value
            .get("precision")
            .and_then(|v| v.as_float())
            .unwrap_or(0.70);
        let recall = thresholds_value
            .get("recall")
            .and_then(|v| v.as_float())
            .unwrap_or(0.80);
        Thresholds { precision, recall }
    } else {
        Thresholds {
            precision: 0.70,
            recall: 0.80,
        }
    };

    Ok((cases, thresholds))
}

/// Load primitives from the WordPress preset
fn load_primitives(
    preset_path: &Path,
) -> Result<HashMap<String, Vec<String>>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(preset_path)?;
    let parsed: Value = toml::from_str(&content)?;

    let mut primitives = HashMap::new();
    if let Some(knowledge) = parsed.get("knowledge") {
        if let Some(required_primitives) = knowledge.get("required_security_primitives") {
            if let Some(table) = required_primitives.as_table() {
                for (lang, primitives_array) in table {
                    if let Value::Array(arr) = primitives_array {
                        let vec: Vec<String> = arr
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        primitives.insert(lang.clone(), vec);
                    }
                }
            }
        }
    }

    Ok(primitives)
}

/// Create a finding from a corpus case
fn create_finding(
    fixture_path: &Path,
    case: &CorpusCase,
    finding: &ExpectedFinding,
) -> VulnerabilityFinding {
    // Extract the actual function name from the fixture based on line number
    let content = fs::read_to_string(fixture_path).unwrap_or_default();
    let function_name = extract_function_name_at_line(&content, finding.line as usize);

    VulnerabilityFinding {
        id: format!("{}-{}", case.id, finding.line),
        title: format!("{} on {}()", finding.cwe, function_name),
        description: finding.description.clone(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some(finding.cwe.clone()),
        file_path: fixture_path.to_string_lossy().to_string(),
        line_number: Some(finding.line),
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

/// Run the corpus and compute metrics
fn run_corpus(corpus_root: &Path) -> (f64, f64, Vec<String>, Thresholds) {
    let manifest_path = corpus_root.join("manifest.toml");
    let preset_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("presets/wordpress-plugin.toml");

    let (cases, thresholds) = load_corpus(&manifest_path).expect("Failed to load corpus manifest");
    let primitives = load_primitives(preset_path.as_path()).expect("Failed to load primitives");

    let mut true_positives = 0;
    let mut false_positives_survived = 0;
    let mut missed_true_positives = 0;
    let mut results = Vec::new();

    for case in &cases {
        let fixture_path = corpus_root.join(&case.fixture);

        // Create a temp directory and copy fixture there
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let temp_fixture = temp_dir
            .path()
            .join(Path::new(&case.fixture).file_name().unwrap());

        // Read the fixture content and write to temp location
        let content = fs::read_to_string(&fixture_path).expect("Failed to read fixture");
        fs::write(&temp_fixture, &content).expect("Failed to write temp fixture");

        for finding_spec in &case.expected_findings {
            let finding = create_finding(&temp_fixture, case, finding_spec);

            // Apply the refutation check
            let (status, notes) = refute_with_primitive_check(
                &finding,
                VerificationStatus::Confirmed,
                "corpus test",
                &primitives,
            );

            let is_refuted = status == VerificationStatus::FalsePositive;

            if case.expected_refutation {
                // This case SHOULD be refuted
                if is_refuted {
                    results.push(format!(
                        "✓ {}: {} correctly refuted ({})",
                        case.id, finding_spec.cwe, notes
                    ));
                } else {
                    false_positives_survived += 1;
                    results.push(format!(
                        "✗ {}: {} incorrectly survived (expected refutation)",
                        case.id, finding_spec.cwe
                    ));
                }
            } else {
                // This case should NOT be refuted (true positive)
                if is_refuted {
                    missed_true_positives += 1;
                    results.push(format!(
                        "✗ {}: {} incorrectly refuted (genuine vulnerability)",
                        case.id, finding_spec.cwe
                    ));
                } else {
                    true_positives += 1;
                    results.push(format!(
                        "✓ {}: {} correctly survived as confirmed",
                        case.id, finding_spec.cwe
                    ));
                }
            }
        }
    }

    // Compute precision and recall
    // Precision = true_positives / (true_positives + false_positives_survived)
    // Recall = true_positives / (true_positives + missed_true_positives)
    let total_positive_predictions = true_positives + false_positives_survived;
    let total_actual_positives = true_positives + missed_true_positives;

    let precision = if total_positive_predictions > 0 {
        true_positives as f64 / total_positive_predictions as f64
    } else {
        0.0
    };

    let recall = if total_actual_positives > 0 {
        true_positives as f64 / total_actual_positives as f64
    } else {
        0.0
    };

    (precision, recall, results, thresholds)
}

#[test]
fn test_corpus_precision_and_recall() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");

    let (precision, recall, results, thresholds) = run_corpus(&corpus_root);

    // Print results for human visibility
    println!("\n=== CORPUS REGRESSION TEST RESULTS ===");
    println!(
        "Precision: {:.2} (minimum: {:.2})",
        precision, thresholds.precision
    );
    println!("Recall: {:.2} (minimum: {:.2})", recall, thresholds.recall);
    println!("\nPer-case results:");
    for result in &results {
        println!("  {}", result);
    }

    // Assert minimum thresholds from manifest
    assert!(
        precision >= thresholds.precision,
        "Precision {:.2} below minimum {:.2}. The refutation logic may have regressed.",
        precision,
        thresholds.precision
    );
    assert!(
        recall >= thresholds.recall,
        "Recall {:.2} below minimum {:.2}. Genuine vulnerabilities are being missed.",
        recall,
        thresholds.recall
    );

    println!("\n✓ Corpus tests passed\n");
}

#[test]
fn test_corpus_loads_successfully() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let manifest_path = corpus_root.join("manifest.toml");

    let (cases, _) = load_corpus(&manifest_path).expect("Failed to load corpus manifest");

    assert!(!cases.is_empty(), "Corpus should contain cases");
    assert_eq!(
        cases.len(),
        11,
        "Corpus should have 11 cases (5 TP, 4 FP, 2 neutral)"
    );
}

#[test]
fn test_primitives_load_from_preset() {
    let preset_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("presets/wordpress-plugin.toml");

    let primitives = load_primitives(&preset_path).expect("Failed to load primitives");

    assert!(
        primitives.contains_key("php"),
        "PHP primitives should be loaded"
    );
    let php_primitives = primitives.get("php").unwrap();
    assert!(php_primitives.contains(&"wp_verify_nonce".to_string()));
    assert!(php_primitives.contains(&"check_admin_referer".to_string()));
    assert!(php_primitives.contains(&"check_ajax_referer".to_string()));
    assert!(php_primitives.contains(&"current_user_can".to_string()));
}
