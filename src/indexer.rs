pub use crate::incremental_scan::FileHashStore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
    ) -> Result<Self, std::io::Error> {
        Self::index_project_with_incremental(project_path, languages, max_size, excludes, None)
    }

    pub fn index_project_with_incremental(
        project_path: &str,
        languages: &[String],
        max_size: u64,
        excludes: &[String],
        previous_hash_store: Option<FileHashStore>,
    ) -> Result<Self, std::io::Error> {
        let mut files = Vec::new();
        let mut total_size = 0u64;

        let lang_extensions = get_language_extensions(languages);

        let walk = WalkDir::new(project_path).into_iter();
        for entry in walk {
            let entry = entry?;
            let entry_path = entry.path();
            if should_exclude(entry_path, excludes) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
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

        let walk = WalkDir::new(project_path).into_iter();

        for entry in walk {
            let entry = entry?;
            let entry_path = entry.path();
            if should_exclude(entry_path, excludes) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
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

        let mut hasher = crate::file_hash::FileHasher::new();
        let mut hash_store = FileHashStore::new();

        for file_info in &mut all_files {
            if let Ok(hash) = hasher.hash_file(&file_info.path) {
                file_info.hash = Some(hash.clone());
                hash_store.insert_hash(&file_info.path, hash);
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

    pub fn get_file_paths(&self) -> Vec<PathBuf> {
        self.files.iter().map(|f| f.path.clone()).collect()
    }

    pub fn get_hash_store(&self) -> Option<&FileHashStore> {
        self.hash_store.as_ref()
    }
}

fn get_language_extensions(languages: &[String]) -> std::collections::HashMap<String, String> {
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

fn should_exclude(path: &Path, excludes: &[String]) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    excludes
        .iter()
        .any(|ex| path_str.contains(ex.to_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_index_single_file() {
        let temp_dir = std::env::temp_dir().join("baco_test_index");
        let _ = fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("test.c");
        fs::write(&test_file, "int main() { return 0; }").unwrap();

        let index = FileIndex::index_project(
            temp_dir.to_str().unwrap(),
            &["c".to_string()],
            1024 * 1024,
            &[],
        )
        .unwrap();

        assert_eq!(index.files.len(), 1);
        assert_eq!(index.files[0].language, "c");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_index_empty_directory() {
        let temp_dir = std::env::temp_dir().join("baco_test_empty");
        let _ = fs::create_dir_all(&temp_dir);

        let index = FileIndex::index_project(
            temp_dir.to_str().unwrap(),
            &["c".to_string()],
            1024 * 1024,
            &[],
        )
        .unwrap();

        assert_eq!(index.files.len(), 0);
        assert_eq!(index.total_size, 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_index_multiple_files() {
        let temp_dir = std::env::temp_dir().join("baco_test_multi");
        let _ = fs::create_dir_all(&temp_dir);
        fs::write(temp_dir.join("test.c"), "int x;").unwrap();
        fs::write(temp_dir.join("test.cpp"), "int y;").unwrap();
        fs::write(temp_dir.join("test.py"), "z = 1").unwrap();
        fs::write(temp_dir.join("test.rs"), "fn main() {}").unwrap();
        fs::write(temp_dir.join("test.go"), "package main").unwrap();
        fs::write(temp_dir.join("test.java"), "public class Test {}").unwrap();
        fs::write(temp_dir.join("test.cs"), "class Test {}").unwrap();
        fs::write(temp_dir.join("test.js"), "const a = 1;").unwrap();
        fs::write(temp_dir.join("test.ts"), "const b: string = \"hello\";").unwrap();
        fs::write(temp_dir.join("test.rb"), "def hello;").unwrap();
        fs::write(temp_dir.join("test.php"), "<?php echo 'hi';").unwrap();

        let index = FileIndex::index_project(
            temp_dir.to_str().unwrap(),
            &[
                "c".to_string(),
                "cpp".to_string(),
                "rust".to_string(),
                "python".to_string(),
                "go".to_string(),
                "java".to_string(),
                "csharp".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "ruby".to_string(),
                "php".to_string(),
            ],
            1024 * 1024,
            &[],
        )
        .unwrap();

        assert_eq!(index.files.len(), 11);
        assert!(index.total_size > 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_get_language_extensions() {
        let exts = get_language_extensions(&["c".to_string()]);
        assert_eq!(exts.get("c"), Some(&"c".to_string()));
        assert_eq!(exts.get("h"), Some(&"c".to_string()));

        let exts = get_language_extensions(&["cpp".to_string()]);
        assert_eq!(exts.get("cpp"), Some(&"cpp".to_string()));
        assert_eq!(exts.get("hpp"), Some(&"cpp".to_string()));

        let exts = get_language_extensions(&["python".to_string()]);
        assert_eq!(exts.get("py"), Some(&"python".to_string()));

        let exts = get_language_extensions(&["rust".to_string()]);
        assert_eq!(exts.get("rs"), Some(&"rust".to_string()));
    }

    #[test]
    fn test_get_language_extensions_unsupported() {
        let exts = get_language_extensions(&["unknown".to_string()]);
        assert!(exts.is_empty());
    }

    #[test]
    fn test_get_language_extensions_multiple() {
        let exts =
            get_language_extensions(&["c".to_string(), "python".to_string(), "rust".to_string()]);
        assert_eq!(exts.get("c"), Some(&"c".to_string()));
        assert_eq!(exts.get("py"), Some(&"python".to_string()));
        assert_eq!(exts.get("rs"), Some(&"rust".to_string()));
    }

    #[test]
    fn test_should_exclude_matches() {
        let path = std::path::Path::new("src/tests/config.toml");
        assert!(should_exclude(path, &["tests/".to_string()]));
        assert!(should_exclude(path, &["/tests/".to_string()]));
    }

    #[test]
    fn test_should_exclude_no_match() {
        let path = std::path::Path::new("src/main.rs");
        assert!(!should_exclude(path, &["tests/".to_string()]));
        assert!(!should_exclude(path, &["docs/".to_string()]));
    }

    #[test]
    fn test_should_exclude_subdirectory() {
        let path = std::path::Path::new("src/tests/utils/config.rs");
        assert!(should_exclude(path, &["tests/".to_string()]));
    }

    #[test]
    fn test_index_excludes_directories() {
        let temp_dir =
            std::env::temp_dir().join(format!("baco_test_dirs_{}", chrono::Utc::now().timestamp()));
        let _ = fs::create_dir_all(&temp_dir);

        fs::write(temp_dir.join("test.c"), "int x;").unwrap();
        let subdir = temp_dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("test2.c"), "int y;").unwrap();

        let index = FileIndex::index_project(
            temp_dir.to_str().unwrap(),
            &["c".to_string()],
            1024 * 1024,
            &[],
        )
        .unwrap();

        assert_eq!(index.files.len(), 2); // Both files included since no excludes

        let _ = fs::remove_dir_all(&temp_dir);
    }
    #[test]
    fn test_index_over_size_limit() {
        let temp_dir = std::env::temp_dir().join("baco_test_size");
        let _ = fs::create_dir_all(&temp_dir);

        let large_file = temp_dir.join("large.c");
        fs::write(&large_file, "0".repeat(2000).as_str()).unwrap();

        let index =
            FileIndex::index_project(temp_dir.to_str().unwrap(), &["c".to_string()], 1000, &[])
                .unwrap();

        assert_eq!(index.files.len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_index_with_excludes() {
        let temp_dir = std::env::temp_dir().join("baco_test_excludes");
        let _ = fs::create_dir_all(&temp_dir);
        fs::write(temp_dir.join("test.c"), "int x;").unwrap();
        let subdir = temp_dir.join("tests");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("test2.c"), "int y;").unwrap();

        let index = FileIndex::index_project(
            temp_dir.to_str().unwrap(),
            &["c".to_string()],
            1024 * 1024,
            &["tests/".to_string()],
        )
        .unwrap();

        assert_eq!(index.files.len(), 1);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_index_invalid_path() {
        let result = FileIndex::index_project(
            "/nonexistent/path/that/does/not/exist",
            &["c".to_string()],
            1024 * 1024,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_get_files_returns_empty_slice() {
        let index = FileIndex {
            files: Vec::new(),
            total_size: 0,
            hash_store: None,
        };
        assert!(index.get_files().is_empty());
        assert_eq!(index.get_files().len(), 0);
    }

    #[test]
    fn test_get_files_returns_all_files() {
        let files = vec![
            FileInfo {
                path: PathBuf::from("test1.c"),
                size: 100,
                language: "c".to_string(),
                hash: None,
            },
            FileInfo {
                path: PathBuf::from("test2.rs"),
                size: 200,
                language: "rust".to_string(),
                hash: None,
            },
        ];
        let index = FileIndex {
            files: files.clone(),
            total_size: 300,
            hash_store: None,
        };

        let result = index.get_files();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].path, PathBuf::from("test1.c"));
        assert_eq!(result[1].path, PathBuf::from("test2.rs"));
    }

    #[test]
    fn test_iter_returns_correct_iterator() {
        let files = vec![
            FileInfo {
                path: PathBuf::from("test1.c"),
                size: 100,
                language: "c".to_string(),
                hash: None,
            },
            FileInfo {
                path: PathBuf::from("test2.rs"),
                size: 200,
                language: "rust".to_string(),
                hash: None,
            },
        ];
        let index = FileIndex {
            files: files.clone(),
            total_size: 300,
            hash_store: None,
        };

        let collected: Vec<&FileInfo> = index.iter().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].path, PathBuf::from("test1.c"));
        assert_eq!(collected[1].path, PathBuf::from("test2.rs"));
    }

    #[test]
    fn test_iter_with_empty_index() {
        let index = FileIndex {
            files: Vec::new(),
            total_size: 0,
            hash_store: None,
        };

        let collected: Vec<&FileInfo> = index.iter().collect();
        assert!(collected.is_empty());
    }
}
