//! File-hash bookkeeping for incremental scanning.
//!
//! The indexer records a SHA256 per file, and this store is what an incremental
//! scan would compare against. **No skipping is implemented**: the indexer hashes
//! every file on every run, the store it builds is discarded at the call site, and
//! `save`/`load` have no caller.
//!
//! ## The design, before anyone wires it
//!
//! The safe shape is a **union, never a replacement**:
//!
//! 1. Before indexing, load the previous store from `<output>/file-hashes.json`
//!    and the previous run's findings from `<output>/findings.json`.
//! 2. Still hash every file: hashing is milliseconds, while the LLM phases are the
//!    expensive part. Partition into `changed` and `unchanged`.
//! 3. Analysis set = `changed` plus every file with no stored hash.
//! 4. Run the pipeline on the analysis set only.
//! 5. Seed the result with the previous findings whose `file_path` is in
//!    `unchanged`; the pipeline's own output covers only the analysis set.
//! 6. Write the new store.
//!
//! Because step 5 only *adds*, a skipped file can only ever contribute back its own
//! previous findings. What this avoids is the failure that makes the feature
//! dangerous: dropping them, so a scan of an unchanged repository reports fewer
//! findings than the run before it. A false negative is the worst outcome this
//! scanner can produce.
//!
//! ## What must be checked first, because each can break the union
//!
//! - Phases that read the whole project rather than the analysis set — cross-file
//!   analysis, aggregation, root-cause dedup. Their output spans files, so a
//!   per-file finding carried forward can duplicate or contradict it.
//! - The `indexed`/`analyzed` counts and the "analysed nothing" warning are
//!   computed from the index but reported as though the whole project ran.
//! - The join key. If `file_path` is relative in one place and absolute in
//!   another, step 5 matches nothing and the union silently collapses to the new
//!   findings — exactly the failure above. Pin the key's shape with a test.
//! - A repository-wide change (a new dependency, a rule update) that should
//!   re-verify findings in files whose bytes did not change.

//! ## The wiring (how the union is enforced end to end)
//!
//! - The orchestrator loads the previous store and the previous run's
//!   findings **before** any phase runs: the per-phase checkpoint rewrites
//!   `findings.json` during the scan, so "previous" must be snapshotted first.
//!   Previous findings come from the run store's newest complete run, never
//!   from `findings.json`.
//! - Both restrictions — the chokepoint that drops fresh findings for
//!   unchanged files, and the carry that reads them back at reporting — use
//!   the same predicate, `file_is_unchanged`. A file can never be dropped
//!   from one side and not carried from the other: that agreement is what
//!   makes the union lossless and duplicate-free.
//! - The store is saved only when a scan fully completes (no early
//!   termination, no parallel-phase failure). A dead scan must not leave
//!   behind hashes that make the next run skip files that were never
//!   analyzed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::file_hash::FileHasher;
use crate::findings::VulnerabilityFinding;

/// Stores file hashes for incremental scanning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileHashStore {
    /// Map of file path (as string) to its hash
    hashes: HashMap<String, String>,
}

impl FileHashStore {
    /// Create a new empty hash store
    pub fn new() -> Self {
        Self {
            hashes: HashMap::new(),
        }
    }

    /// Get the hash for a file path
    pub fn get_hash(&self, path: &Path) -> Option<&String> {
        let key = path.to_string_lossy().to_string();
        self.hashes.get(&key)
    }

    /// Insert or update a hash for a file path
    pub fn insert_hash(&mut self, path: &Path, hash: String) {
        let key = path.to_string_lossy().to_string();
        self.hashes.insert(key, hash);
    }

    /// Get the number of stored hashes
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

impl FileHashStore {
    /// Save hash store to a file
    ///
    /// Uses atomic write-then-rename to avoid corruption on crash.
    /// Writes to a temp file first, then renames it into place.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let target = std::path::Path::new(path);
        crate::fs_util::write_json_atomic(target, self)
            .map_err(|e| format!("Failed to write hash store: {}", e))
    }

    /// Load hash store from a file
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read hash store: {}", e))?;

        let store: FileHashStore = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse hash store: {}", e))?;

        Ok(store)
    }
}

/// Envelope for the persisted hash store (`<output>/file-hashes.json`).
///
/// The version and the rules fingerprint are bust gates: once baco ships new
/// rules or the rule-affecting config changes, the hashes from an older run no
/// longer mean "already analyzed under the current rules". A mismatched
/// envelope is rejected so every file is treated as changed for one run.
///
/// Limitation, deliberate: the fingerprint covers the rule-affecting config
/// values and the baco version, not the content of inline custom rules.
/// Editing a custom rule in place without touching any listed value will not
/// bust the store; bump `STORE_SCHEMA` to force a full re-scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedHashStore {
    pub schema: u32,
    pub baco_version: String,
    pub rules_fingerprint: String,
    #[serde(flatten)]
    pub store: FileHashStore,
}

pub const STORE_SCHEMA: u32 = 1;

/// Fingerprint of everything that decides which rules produce findings.
pub fn rules_fingerprint(
    languages: &[String],
    rulesets: &[String],
    exclude_rules: &[String],
    custom_rules: &[String],
) -> String {
    let material = serde_json::json!({
        "languages": languages,
        "rulesets": rulesets,
        "exclude_rules": exclude_rules,
        "custom_rules": custom_rules,
    });
    crate::file_hash::calculate_content_hash(material.to_string().as_bytes())
}

/// Save the store wrapped in its metadata envelope, atomically.
pub fn save_persisted_store(
    path: &str,
    store: &FileHashStore,
    fingerprint: &str,
) -> Result<(), String> {
    let envelope = PersistedHashStore {
        schema: STORE_SCHEMA,
        baco_version: env!("CARGO_PKG_VERSION").to_string(),
        rules_fingerprint: fingerprint.to_string(),
        store: store.clone(),
    };

    let target = Path::new(path);
    crate::fs_util::write_json_atomic(target, &envelope)
        .map_err(|e| format!("Failed to write persisted store: {}", e))
}

/// Load a store written by the same baco version under the same rules
/// fingerprint. Any mismatch — schema, version, fingerprint — is an error
/// naming the reason; the caller treats the store as empty, which analyzes
/// every file for one run.
pub fn load_persisted_store(path: &str, fingerprint: &str) -> Result<FileHashStore, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;

    let envelope: PersistedHashStore =
        serde_json::from_str(&content).map_err(|e| format!("parse: {}", e))?;

    if envelope.schema != STORE_SCHEMA {
        return Err(format!(
            "schema {} != {}; regenerate by scanning once",
            envelope.schema, STORE_SCHEMA
        ));
    }
    if envelope.baco_version != env!("CARGO_PKG_VERSION") {
        return Err(format!(
            "baco {} wrote it, this is {}; regenerate by scanning once",
            envelope.baco_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    if envelope.rules_fingerprint != fingerprint {
        return Err(
            "rule-affecting config changed since it was written; regenerate by scanning once"
                .to_string(),
        );
    }

    Ok(envelope.store)
}

/// Canonical form of a path, falling back to the input when the file cannot
/// be resolved (deleted mid-scan, permission, non-UTF8 ancestor). Callers
/// treat fallback as "changed", the safe direction: analyze, never skip.
fn canonical(path: &Path) -> PathBuf {
    crate::fs_util::canonical_or_as_is(path)
}

/// True when the file's current content hash matches the recorded hash for
/// the same canonical path. Every failure mode — no recorded hash, unreadable
/// file, unresolvable path — reads as `false`, i.e. changed.
pub fn file_is_unchanged(path: &Path, previous: &FileHashStore, hasher: &mut FileHasher) -> bool {
    if previous.is_empty() {
        return false;
    }
    let resolved = canonical(path);
    let Some(recorded) = previous.get_hash(&resolved) else {
        return false;
    };
    match hasher.hash_file(&resolved) {
        Ok(current) => &current == recorded,
        Err(_) => false,
    }
}

/// Drop fresh findings whose file is unchanged: the reporting phase carries
/// the previous run's findings for those files instead. One hash per distinct
/// file, however many findings it has.
pub fn keep_fresh_findings(
    findings: Vec<VulnerabilityFinding>,
    previous: &FileHashStore,
    hasher: &mut FileHasher,
) -> Vec<VulnerabilityFinding> {
    if previous.is_empty() {
        return findings;
    }
    let mut unchanged_cache: HashMap<String, bool> = HashMap::new();
    findings
        .into_iter()
        .filter(|finding| {
            *unchanged_cache
                .entry(finding.file_path.clone())
                .or_insert_with_key(|path| !file_is_unchanged(Path::new(path), previous, hasher))
        })
        .collect()
}

/// The other half of the union: previous findings whose file is unchanged
/// come back as-is, with the metadata the previous run gave them. Same
/// predicate as `keep_fresh_findings`, so the two sets are disjoint by file
/// and no finding can be both dropped fresh and not carried.
pub fn carry_previous(
    previous: &[VulnerabilityFinding],
    previous_store: &FileHashStore,
    hasher: &mut FileHasher,
) -> Vec<VulnerabilityFinding> {
    if previous_store.is_empty() {
        return Vec::new();
    }
    let mut unchanged_cache: HashMap<String, bool> = HashMap::new();
    previous
        .iter()
        .filter(|finding| {
            *unchanged_cache
                .entry(finding.file_path.clone())
                .or_insert_with_key(|path| {
                    file_is_unchanged(Path::new(path), previous_store, hasher)
                })
        })
        .cloned()
        .collect()
}

// ============================================================================
// Extracted helpers for coverage gate restoration
// ============================================================================

/// Files to analyze for LLM static analysis under incremental mode.
///
/// Returns (files_to_analyze, skipped_count).
///
/// Gating rules:
/// - None store → all files analyzed, 0 skipped
/// - Empty store → all files analyzed, 0 skipped
/// - Some store + has_previous_findings=false → all files analyzed, 0 skipped
/// - Some non-empty store + has_previous_findings=true → unchanged files skipped
pub fn analysis_files_for_incremental(
    files: &[crate::indexer::FileInfo],
    previous: Option<&FileHashStore>,
    has_previous_findings: bool,
) -> (Vec<crate::indexer::FileInfo>, usize) {
    let Some(store) = previous.filter(|s| !s.is_empty()) else {
        return (files.to_vec(), 0);
    };

    if !has_previous_findings {
        return (files.to_vec(), 0);
    }

    let mut hasher = FileHasher::new();
    let (kept, skipped): (Vec<_>, Vec<_>) = files
        .iter()
        .cloned()
        .partition(|f| !file_is_unchanged(&f.path, store, &mut hasher));

    (kept, skipped.len())
}

/// Load previous run context: hash store and findings.
///
/// Returns (store_opt, findings, warnings).
///
/// Warnings are non-empty when the store or findings fail to load.
pub fn load_previous_run_context(
    output_dir: &Path,
    fingerprint: &str,
    store_path: &Path,
) -> (
    Option<FileHashStore>,
    Vec<VulnerabilityFinding>,
    Vec<String>,
) {
    let mut warnings = Vec::new();

    let store = match load_persisted_store(&store_path.to_string_lossy(), fingerprint) {
        Ok(s) => Some(s),
        Err(reason) => {
            warnings.push(format!(
                "Incremental store unusable ({}): analyzing every file this run",
                reason
            ));
            None
        }
    };

    let findings = match crate::run_store::load_last_run_findings(output_dir) {
        Ok(Some(f)) => f,
        Ok(None) => Vec::new(),
        Err(e) => {
            warnings.push(format!(
                "Previous run unusable ({}): analyzing every file this run",
                e
            ));
            Vec::new()
        }
    };

    (store, findings, warnings)
}

/// Drop findings for unchanged files.
///
/// Returns (findings, dropped_count).
pub fn drop_findings_for_unchanged_files(
    findings: Vec<VulnerabilityFinding>,
    previous: Option<&FileHashStore>,
    _previous_findings_len: usize,
) -> (Vec<VulnerabilityFinding>, usize) {
    let Some(store) = previous.filter(|s| !s.is_empty()) else {
        return (findings, 0);
    };

    let mut hasher = FileHasher::new();
    let before = findings.len();
    let kept = keep_fresh_findings(findings, store, &mut hasher);
    let dropped = before - kept.len();

    (kept, dropped)
}

/// Persist the store after a full scan.
pub fn persist_store_after_full_scan(
    output_dir: &Path,
    store: &FileHashStore,
    fingerprint: &str,
) -> Result<(), String> {
    let store_path = output_dir.join("file-hashes.json");
    save_persisted_store(&store_path.to_string_lossy(), store, fingerprint)
}

/// Whether to persist the store.
pub fn should_persist(
    incremental_active: bool,
    no_parallel_failures: bool,
    completed_fully: bool,
) -> bool {
    incremental_active && no_parallel_failures && completed_fully
}

/// Effective analyzed files count (indexed minus incremental unchanged).
pub fn effective_analysed(indexed: u64, unchanged: u64) -> u64 {
    indexed.saturating_sub(unchanged)
}
