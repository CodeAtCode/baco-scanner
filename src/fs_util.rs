//! File system utilities: atomic writes and path canonicalization.

use std::path::{Path, PathBuf};

/// Write bytes to a file atomically.
///
/// Creates the parent directory if needed, writes to a `.tmp` sibling in the
/// same directory, flushes/syncs, then renames into place. A plain `fs::write`
/// truncates first, so a crash mid-write leaves a corrupt file that deserialises
/// on the next run. This pattern guarantees the target is either the old content
/// or the new content, never a truncation.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    // Sync the file to disk
    let file = std::fs::File::open(&tmp)?;
    file.sync_all()?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Save JSON to a file using atomic write.
///
/// Writes to a sibling temporary file and renames it into place. A plain
/// `fs::write` truncates the target first, so an interrupted write could
/// leave a corrupt file that deserializes incorrectly on the next run.
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    atomic_write(path, json.as_bytes())
}

/// Canonical form of a path, falling back to the input when the file cannot
/// be resolved (deleted mid-scan, permission, non-UTF8 ancestor). Callers
/// treat fallback as "changed", the safe direction: analyze, never skip.
///
/// Doc comment note: "cannot resolve = treat as changed / analyze, never skip"
/// because skipping an unresolvable path would silently drop files that need
/// analysis.
pub(crate) fn canonical_or_as_is(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
