pub use crate::incremental_scan::FileHashStore;
use globset::{GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub language: String,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    pub files: Vec<FileInfo>,
    pub total_size: u64,
    pub hash_store: Option<FileHashStore>,
}

impl FileIndex {
    pub fn index_project(
        project_path: &str,
        languages: &[String],
        max_size: u64,
        excludes: &[String],
        enable_file_filtering: bool,
    ) -> Result<Self, std::io::Error> {
        Self::index_project_with_incremental(
            project_path,
            languages,
            max_size,
            excludes,
            None,
            enable_file_filtering,
        )
    }

    pub fn index_project_with_incremental(
        project_path: &str,
        languages: &[String],
        max_size: u64,
        excludes: &[String],
        previous_hash_store: Option<FileHashStore>,
        _enable_file_filtering: bool,
    ) -> Result<Self, std::io::Error> {
        let mut files = Vec::new();
        let mut total_size = 0u64;

        let lang_extensions = get_language_extensions(languages);

        // Canonicalize the scan root once for symlink containment check
        let canonical_root =
            std::fs::canonicalize(project_path).unwrap_or_else(|_| PathBuf::from(project_path));

        // Build the exclusion matcher
        let exclude_matcher = ExcludeMatcher::new(excludes).unwrap_or_else(|_| {
            ExcludeMatcher::new(&[]).expect("Empty patterns should always work")
        });

        let walk = WalkDir::new(project_path).into_iter();
        for entry in walk {
            let entry = entry?;
            let entry_path = entry.path();

            // Compute relative path for matching
            let relative_path = entry_path.strip_prefix(project_path).ok();
            if exclude_matcher.is_excluded(entry_path, relative_path) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            // Symlink containment: resolve real path and check it's under the scan root
            if entry
                .path()
                .symlink_metadata()
                .ok()
                .is_some_and(|m| m.file_type().is_symlink())
            {
                if let Ok(real_path) = std::fs::canonicalize(entry.path()) {
                    if !real_path.starts_with(&canonical_root) {
                        tracing::debug!(
                            "Skipping symlink {:?} -> {:?}: escapes scan root",
                            entry_path,
                            real_path
                        );
                        continue;
                    }
                }
            }

            let metadata = entry.metadata()?;
            let size = metadata.len();
            if size > max_size {
                continue;
            }

            if let Some(ext) = entry_path
                .extension()
                .and_then(|e: &std::ffi::OsStr| e.to_str())
            {
                if let Some(lang) = lang_extensions.get(ext) {
                    let hash = if let Some(ref store) = previous_hash_store {
                        store.get_hash(entry_path).cloned()
                    } else {
                        None
                    };

                    files.push(FileInfo {
                        path: entry_path.to_path_buf(),
                        size,
                        language: lang.clone(),
                        hash,
                    });
                    total_size += size;
                }
            }
        }

        Ok(FileIndex {
            files,
            total_size,
            hash_store: previous_hash_store,
        })
    }

    pub fn index_project_incremental(
        project_path: &str,
        languages: &[String],
        max_size: u64,
        excludes: &[String],
        pb: Option<&indicatif::ProgressBar>,
        enable_file_filtering: bool,
    ) -> Result<(Self, FileHashStore), std::io::Error> {
        if !std::path::Path::new(project_path).exists() {
            tracing::error!("\u{1B}[31m[INDEXING]\u{1B}[0m ERROR: Path does not exist!");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Path not found",
            ));
        }

        let mut all_files = Vec::new();
        let mut total_size = 0u64;

        let lang_extensions = get_language_extensions(languages);
        let _enable_file_filtering = enable_file_filtering; // Capture parameter for use in loop

        // Canonicalize the scan root once for symlink containment check
        let canonical_root =
            std::fs::canonicalize(project_path).unwrap_or_else(|_| PathBuf::from(project_path));

        // Build the exclusion matcher
        let exclude_matcher = ExcludeMatcher::new(excludes).unwrap_or_else(|_| {
            ExcludeMatcher::new(&[]).expect("Empty patterns should always work")
        });

        let walk = WalkDir::new(project_path).into_iter();

        for entry in walk {
            let entry = entry?;
            let entry_path = entry.path();

            // Compute relative path for matching
            let relative_path = entry_path.strip_prefix(project_path).ok();
            if exclude_matcher.is_excluded(entry_path, relative_path) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            // Symlink containment: resolve real path and check it's under the scan root
            if entry
                .path()
                .symlink_metadata()
                .ok()
                .is_some_and(|m| m.file_type().is_symlink())
            {
                if let Ok(real_path) = std::fs::canonicalize(entry.path()) {
                    if !real_path.starts_with(&canonical_root) {
                        tracing::debug!(
                            "Skipping symlink {:?} -> {:?}: escapes scan root",
                            entry_path,
                            real_path
                        );
                        continue;
                    }
                }
            }

            let metadata = entry.metadata()?;
            let size = metadata.len();
            if size > max_size {
                continue;
            }

            if let Some(ext) = entry_path
                .extension()
                .and_then(|e: &std::ffi::OsStr| e.to_str())
            {
                if let Some(lang) = lang_extensions.get(ext) {
                    all_files.push(FileInfo {
                        path: entry_path.to_path_buf(),
                        size,
                        language: lang.clone(),
                        hash: None,
                    });
                    total_size += size;
                }
            }
        }

        tracing::info!(
            "\u{1B}[34m[INDEXING]\u{1B}[0m Indexed {} files ({} MB)",
            all_files.len(),
            total_size / (1024 * 1024)
        );

        if let Some(pb) = pb {
            pb.set_length(all_files.len() as u64);
            pb.set_position(0);
            pb.set_message("Indexing files...");
        }

        let mut hasher = crate::file_hash::FileHasher::new();
        let mut hash_store = FileHashStore::new();
        let file_count = all_files.len();

        for (i, file_info) in all_files.iter_mut().enumerate() {
            if let Ok(hash) = hasher.hash_file(&file_info.path) {
                file_info.hash = Some(hash.clone());
                hash_store.insert_hash(&file_info.path, hash);
            }
            if let Some(pb) = pb {
                pb.set_position((i + 1) as u64);
                pb.set_message(format!(
                    "Indexing [{}/{}]: {}",
                    i + 1,
                    file_count,
                    file_info.path.display()
                ));
            }
        }

        hash_store.set_last_scan(chrono::Utc::now().timestamp());

        Ok((
            FileIndex {
                files: all_files,
                total_size,
                hash_store: Some(hash_store.clone()),
            },
            hash_store,
        ))
    }

    pub fn get_files(&self) -> &[FileInfo] {
        &self.files
    }

    pub fn iter(&self) -> std::slice::Iter<'_, FileInfo> {
        self.files.iter()
    }

    pub fn get_hash_store(&self) -> Option<&FileHashStore> {
        self.hash_store.as_ref()
    }
}

pub fn get_language_extensions(languages: &[String]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();

    for lang in languages {
        let exts = match lang.to_lowercase().as_str() {
            "c" => vec!["c", "h"],
            "cpp" | "c++" => vec!["cpp", "hpp", "cc", "hh", "cxx", "hxx"],
            "rust" => vec!["rs"],
            "python" => vec!["py"],
            "javascript" => vec!["js", "jsx"],
            "typescript" => vec!["ts", "tsx"],
            "go" => vec!["go"],
            "java" => vec!["java"],
            "csharp" | "c#" => vec!["cs"],
            "ruby" => vec!["rb"],
            "php" => vec!["php"],
            _ => continue,
        };

        for ext in exts {
            map.insert(ext.to_string(), lang.clone());
        }
    }

    map
}

/// Glob-based path exclusion matcher.
///
/// # Semantics (globset defaults)
/// - Pattern "src" matches the `src` directory and everything under it (implicit `/**`)
/// - Pattern "docs/*" matches ANY path under `docs/` (globset `*` crosses `/` by default)
/// - Pattern "*.min.js" matches any file ending in `.min.js` at ANY depth
/// - Patterns are matched against the path RELATIVE to the scan root when `relative_path` is provided
/// - If `relative_path` is `None`, matches against the full absolute path
///
/// # Construction
/// Invalid glob patterns are skipped with a warning; the matcher remains functional for valid patterns.
pub struct ExcludeMatcher {
    set: GlobSet,
}

impl ExcludeMatcher {
    /// Creates a new `ExcludeMatcher` from a list of glob patterns.
    ///
    /// Invalid patterns are skipped with a warning and do not prevent construction.
    /// Empty pattern list → matcher excludes nothing.
    pub fn new(patterns: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder = GlobSetBuilder::new();

        for pat in patterns {
            if pat.is_empty() {
                continue;
            }

            // Normalize trailing slashes so "tests/" behaves like "tests"
            let pat = pat.trim_end_matches('/');

            // Add pattern as-given with case-insensitive matching
            match globset::GlobBuilder::new(pat)
                .case_insensitive(true)
                .build()
            {
                Ok(glob) => {
                    builder.add(glob);
                    // If pattern has no wildcard chars, also add implicit /** suffix
                    // so bare "src" matches src/ and everything under it
                    if !pat.contains('*') && !pat.contains('?') && !pat.contains('[') {
                        let nested_pat = format!("{}/**", pat);
                        if let Ok(glob) = globset::GlobBuilder::new(&nested_pat)
                            .case_insensitive(true)
                            .build()
                        {
                            builder.add(glob);
                        } else {
                            warn!("Failed to build nested glob pattern '{}'", nested_pat);
                        }
                    }
                }
                Err(e) => {
                    warn!("Skipping invalid glob pattern '{}': {}", pat, e);
                }
            }
        }

        let set = builder.build()?;
        Ok(Self { set })
    }

    /// Checks if a path is excluded by this matcher.
    ///
    /// # Arguments
    /// - `path`: The path to check (absolute or relative)
    /// - `relative_path`: If provided, this is the path relative to the scan root.
    ///   The matcher will use this for matching instead of `path`. Pass `Some("src/foo.rs")` for
    ///   a file at `project_root/src/foo.rs`.
    ///
    /// # Returns
    /// `true` if the path matches any exclusion pattern, `false` otherwise.
    pub fn is_excluded(&self, path: &Path, relative_path: Option<&Path>) -> bool {
        let path_to_match = relative_path.unwrap_or(path);
        let path_str = path_to_match.to_string_lossy();
        self.set.is_match(path_str.as_ref())
    }
}
