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
