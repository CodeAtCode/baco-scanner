//! Cross-run prior-findings store for deduplication and skip directives.
//!
//! Provides stable finding keys and persistence across scanner runs.

use crate::findings::{VerificationStatus, VulnerabilityFinding};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Compute the taxonomy rule ID for a finding.
///
/// Returns "{domain}/{cwe_id}" format (e.g., "xss/CWE-79").
/// When cwe_id is None or empty, returns "uncategorized/none".
///
/// The domain is derived from the CWE ID using a closed-rule taxonomy mapping
/// common CWE families to hunt domains:
/// - injection: CWE-78, 89, 90, 119
/// - xss: CWE-79, 80
/// - auth: CWE-287, 285, 290
/// - authz_absence: CWE-284, 862, 863, 639
/// - path_traversal: CWE-22, 23, 36, 29
/// - crypto: CWE-327, 328, 757
/// - resource: CWE-400, 770, 190
/// - deserialization: CWE-502, 503, 20
/// - memory_safety: CWE-120, 787, 125, 190, 416, 476
/// - path_traversal: CWE-22, 23, 35, 29
/// - uncategorized: unmapped CWEs
pub fn taxonomy_rule_id(f: &VulnerabilityFinding) -> String {
    let domain = cwe_id_to_hunt_domain(f.cwe_id.as_deref());
    let cwe = f.cwe_id.as_deref().unwrap_or("none");
    if cwe.is_empty() {
        "uncategorized/none".to_string()
    } else {
        format!("{}/{}", domain, cwe)
    }
}

/// Map a CWE ID to a hunt domain.
///
/// Covers the core hunt domains: injection, auth, authz_absence, xss,
/// path_traversal, crypto, resource, deserialization, memory_safety.
/// Returns "uncategorized" for unmapped CWEs.
fn cwe_id_to_hunt_domain(cwe_id: Option<&str>) -> &'static str {
    let cwe = match cwe_id {
        Some(c) => c,
        None => return "uncategorized",
    };

    match cwe {
        // Injection family
        "CWE-78" | "CWE-89" | "CWE-90" | "CWE-119" | "CWE-564" => "injection",
        // XSS family
        "CWE-79" | "CWE-80" => "xss",
        // Authentication family
        "CWE-287" | "CWE-285" | "CWE-290" | "CWE-384" | "CWE-613" => "auth",
        // Authorization absence family
        "CWE-284" | "CWE-862" | "CWE-863" | "CWE-639" => "authz_absence",
        // Path traversal family
        "CWE-22" | "CWE-23" | "CWE-35" | "CWE-29" => "path_traversal",
        // Cryptographic weaknesses
        "CWE-327" | "CWE-326" | "CWE-328" | "CWE-757" => "crypto",
        // Resource exhaustion
        "CWE-400" | "CWE-770" => "resource",
        // Deserialization
        "CWE-502" | "CWE-503" | "CWE-20" => "deserialization",
        // Memory safety
        "CWE-120" | "CWE-787" | "CWE-125" | "CWE-190" | "CWE-416" | "CWE-476" => "memory_safety",
        // Default: uncategorized
        _ => "uncategorized",
    }
}

/// Stable key for a finding, based on taxonomy rule ID, normalized snippet, and file path.
///
/// The key is a SHA256 hash of `taxonomy_rule_id + "\x00" + normalized_snippet + "\x00" + file_path`,
/// truncated to 12 hex characters. This ensures:
/// - Same finding across refactorings (whitespace/line changes) produces the same key
/// - Same snippet in different files produces different keys
/// - Same snippet with different CWE taxonomy produces different keys
/// - The key participates in the taxonomy: moving a finding across files keeps the same key
///   if domain+cwe+snippet remain unchanged (refactor-stable across file moves)
///
/// Normalization lowercases the snippet and collapses all whitespace runs to single spaces.
/// When `code_snippet` is None, uses the finding's title as the fallback.
pub fn stable_finding_key(f: &VulnerabilityFinding) -> String {
    let snippet = f.code_snippet.as_ref().map_or(&f.title, |s| s);
    let normalized = normalize_snippet(snippet);
    let taxonomy = taxonomy_rule_id(f);
    let input = format!("{}\x00{}\x00{}", taxonomy, normalized, f.file_path);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..12].to_string()
}

/// Normalize a code snippet for stable hashing.
///
/// - Converts to lowercase
/// - Collapses all whitespace runs (spaces, tabs, newlines) to single spaces
fn normalize_snippet(snippet: &str) -> String {
    snippet
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Prior knowledge loaded from previous runs.
#[derive(Debug, Clone)]
pub struct PriorKnowledge {
    /// Keys of findings to skip (known Confirmed or FalsePositive outcomes).
    pub skip_keys: Vec<String>,
    /// Total number of prior findings loaded.
    pub prior_count: usize,
}

/// Load findings from prior runs in the output directory.
///
/// Reads `{output_dir}/runs/run-*/findings.json` files, sorted by directory
/// name (most recent first), up to `max_runs` entries. Tolerates missing or
/// corrupt entries by skipping them with a debug log.
pub fn load_prior_runs(output_dir: &Path, max_runs: usize) -> Vec<VulnerabilityFinding> {
    let runs_dir = output_dir.join("runs");
    if !runs_dir.exists() {
        tracing::debug!("Prior runs directory does not exist: {:?}", runs_dir);
        return Vec::new();
    }

    // Collect run directories
    let mut run_dirs: Vec<PathBuf> = match fs::read_dir(&runs_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.path())
            .collect(),
        Err(e) => {
            tracing::debug!("Failed to read runs directory {:?}: {}", runs_dir, e);
            return Vec::new();
        }
    };

    // Sort by directory name (descending for most recent first)
    run_dirs.sort_by(|a, b| b.cmp(a));

    // Take at most max_runs
    run_dirs.truncate(max_runs);

    let mut all_findings = Vec::new();

    for run_dir in run_dirs {
        let findings_path = run_dir.join("findings.json");
        match fs::read_to_string(&findings_path) {
            Ok(content) => match serde_json::from_str::<Vec<VulnerabilityFinding>>(&content) {
                Ok(findings) => {
                    tracing::debug!(
                        "Loaded {} findings from prior run: {:?}",
                        findings.len(),
                        run_dir
                    );
                    all_findings.extend(findings);
                }
                Err(e) => {
                    tracing::debug!("Failed to parse findings.json in {:?}: {}", run_dir, e);
                }
            },
            Err(e) => {
                tracing::debug!("Failed to read {:?}: {}", findings_path, e);
            }
        }
    }

    all_findings
}

/// Build prior knowledge from a list of prior findings.
///
/// Extracts stable keys from findings with `verification_status` of
/// `Confirmed` or `FalsePositive`, as these represent known outcomes worth
/// skipping in subsequent runs.
pub fn build_prior_knowledge(prior: &[VulnerabilityFinding]) -> PriorKnowledge {
    let skip_keys: Vec<String> = prior
        .iter()
        .filter(|f| {
            matches!(
                f.verification_status,
                Some(VerificationStatus::Confirmed | VerificationStatus::FalsePositive)
            )
        })
        .map(stable_finding_key)
        .collect();

    PriorKnowledge {
        skip_keys,
        prior_count: prior.len(),
    }
}

/// Save the current run's findings to the output directory.
///
/// Writes to `{output_dir}/runs/run-{unix_timestamp_secs}/findings.json`.
/// Creates parent directories as needed. Logs on failure but does not panic.
pub fn save_run(output_dir: &Path, findings: &[VulnerabilityFinding]) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let run_dir = output_dir.join("runs").join(format!("run-{}", timestamp));
    let findings_path = run_dir.join("findings.json");

    // Create parent directories
    if let Err(e) = fs::create_dir_all(&run_dir) {
        tracing::warn!("Failed to create run directory {:?}: {}", run_dir, e);
        return;
    }

    // Serialize findings
    let json = match serde_json::to_string_pretty(findings) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Failed to serialize findings: {}", e);
            return;
        }
    };

    // Write to file
    if let Err(e) = fs::write(&findings_path, json) {
        tracing::warn!("Failed to write findings to {:?}: {}", findings_path, e);
    } else {
        tracing::debug!("Saved {} findings to {:?}", findings.len(), findings_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn make_finding(
        id: &str,
        file_path: &str,
        line_number: Option<u32>,
        code_snippet: Option<&str>,
        verification_status: Option<VerificationStatus>,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: "Test finding".to_string(),
            description: "Test description".to_string(),
            severity: crate::findings::Severity::Medium,
            confidence_score: 0.7,
            cwe_id: Some("CWE-79".to_string()),
            file_path: file_path.to_string(),
            line_number,
            code_snippet: code_snippet.map(String::from),
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status,
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
    fn test_stable_key_stable_across_line_number_change() {
        let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let x = 1;"), None);
        let finding2 = make_finding("2", "src/test.rs", Some(20), Some("let x = 1;"), None);

        let key1 = stable_finding_key(&finding1);
        let key2 = stable_finding_key(&finding2);

        assert_eq!(
            key1, key2,
            "Key should be stable across line number changes"
        );
    }

    #[test]
    fn test_stable_key_stable_across_refactor() {
        // Same logical code, different formatting
        let finding1 = make_finding(
            "1",
            "src/test.rs",
            Some(10),
            Some("let x = 1;\nlet y = 2;"),
            None,
        );
        let finding2 = make_finding(
            "2",
            "src/test.rs",
            Some(15),
            Some("let x = 1; let y = 2;"),
            None,
        );

        let key1 = stable_finding_key(&finding1);
        let key2 = stable_finding_key(&finding2);

        assert_eq!(
            key1, key2,
            "Key should be stable across whitespace refactors"
        );
    }

    #[test]
    fn test_stable_key_changes_when_snippet_changes() {
        let finding1 = make_finding("1", "src/test.rs", Some(10), Some("let x = 1;"), None);
        let finding2 = make_finding("2", "src/test.rs", Some(10), Some("let x = 2;"), None);

        let key1 = stable_finding_key(&finding1);
        let key2 = stable_finding_key(&finding2);

        assert_ne!(key1, key2, "Key should change when snippet changes");
    }

    #[test]
    fn test_stable_key_uses_title_when_snippet_none() {
        let finding1 = make_finding("1", "src/test.rs", Some(10), None, None);
        let finding2 = make_finding("2", "src/test.rs", Some(10), None, None);

        let key1 = stable_finding_key(&finding1);
        let key2 = stable_finding_key(&finding2);

        assert_eq!(key1, key2, "Key should be stable when using title fallback");
    }

    #[test]
    fn test_load_prior_runs_empty_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let output_dir = temp_dir.path();

        let findings = load_prior_runs(output_dir, 5);
        assert!(findings.is_empty(), "Should return empty vec for empty dir");
    }

    #[test]
    fn test_save_run_then_load_prior_runs_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let output_dir = temp_dir.path();

        let findings = vec![
            make_finding("1", "src/a.rs", Some(10), Some("code a"), None),
            make_finding("2", "src/b.rs", Some(20), Some("code b"), None),
        ];

        save_run(output_dir, &findings);

        // Find the run directory
        let runs_dir = output_dir.join("runs");
        let run_dirs: Vec<_> = fs::read_dir(&runs_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        assert_eq!(run_dirs.len(), 1, "Should have created one run directory");

        // Load back
        let loaded = load_prior_runs(output_dir, 5);
        assert_eq!(loaded.len(), 2, "Should load both findings");
        assert_eq!(loaded[0].id, "1");
        assert_eq!(loaded[1].id, "2");
    }

    #[test]
    fn test_build_prior_knowledge_includes_confirmed_and_fp() {
        let findings = vec![
            make_finding(
                "1",
                "src/a.rs",
                Some(10),
                Some("code a"),
                Some(VerificationStatus::Confirmed),
            ),
            make_finding(
                "2",
                "src/b.rs",
                Some(20),
                Some("code b"),
                Some(VerificationStatus::FalsePositive),
            ),
            make_finding(
                "3",
                "src/c.rs",
                Some(30),
                Some("code c"),
                Some(VerificationStatus::NeedsReview),
            ),
            make_finding("4", "src/d.rs", Some(40), Some("code d"), None),
        ];

        let prior_knowledge = build_prior_knowledge(&findings);

        assert_eq!(prior_knowledge.prior_count, 4);
        assert_eq!(
            prior_knowledge.skip_keys.len(),
            2,
            "Should include only Confirmed and FalsePositive"
        );

        // Verify the keys correspond to findings 1 and 2
        let key1 = stable_finding_key(&findings[0]);
        let key2 = stable_finding_key(&findings[1]);
        assert!(prior_knowledge.skip_keys.contains(&key1));
        assert!(prior_knowledge.skip_keys.contains(&key2));
    }

    #[test]
    fn test_corrupt_json_skipped_other_runs_loaded() {
        let temp_dir = tempfile::tempdir().unwrap();
        let output_dir = temp_dir.path();
        let runs_dir = output_dir.join("runs");

        // Create two run directories
        let run1_dir = runs_dir.join("run-1000");
        let run2_dir = runs_dir.join("run-2000");
        fs::create_dir_all(&run1_dir).unwrap();
        fs::create_dir_all(&run2_dir).unwrap();

        // Write valid JSON to run1
        let findings1 = vec![make_finding(
            "1",
            "src/a.rs",
            Some(10),
            Some("code a"),
            None,
        )];
        let json1 = serde_json::to_string(&findings1).unwrap();
        File::create(run1_dir.join("findings.json"))
            .unwrap()
            .write_all(json1.as_bytes())
            .unwrap();

        // Write corrupt JSON to run2
        File::create(run2_dir.join("findings.json"))
            .unwrap()
            .write_all(b"not valid json")
            .unwrap();

        // Load with max_runs=5 (should load both, but skip corrupt)
        let loaded = load_prior_runs(output_dir, 5);

        assert_eq!(loaded.len(), 1, "Should load only the valid run");
        assert_eq!(loaded[0].id, "1");
    }

    #[test]
    fn test_load_prior_runs_respects_max_runs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let output_dir = temp_dir.path();
        let runs_dir = output_dir.join("runs");

        // Create 5 run directories
        for i in 1..=5 {
            let run_dir = runs_dir.join(format!("run-{}", i * 1000));
            fs::create_dir_all(&run_dir).unwrap();
            let findings = vec![make_finding(
                &i.to_string(),
                "src/a.rs",
                Some(10),
                Some("code"),
                None,
            )];
            let json = serde_json::to_string(&findings).unwrap();
            File::create(run_dir.join("findings.json"))
                .unwrap()
                .write_all(json.as_bytes())
                .unwrap();
        }

        // Load with max_runs=3
        let loaded = load_prior_runs(output_dir, 3);
        assert_eq!(loaded.len(), 3, "Should load only 3 most recent runs");
    }
}
