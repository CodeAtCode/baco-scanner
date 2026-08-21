//! Function lookup and indexing across source files.
//!
//! Indexes functions by name and exposes lookup for function body retrieval.

use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

use crate::agent_scaffold::tree_sitter_parser::{get_function_name, parse_source};
use crate::context::control_path::Language;

/// Index of functions by name across source files.
///
/// Maps function names to their full source text including signatures.
#[derive(Debug, Clone, Default)]
pub struct FunctionLookup {
    functions: HashMap<String, String>,
}

impl FunctionLookup {
    /// Create a new empty FunctionLookup.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    /// Index a single source file.
    ///
    /// Parses the file with tree-sitter and extracts all function definitions,
    /// storing name -> full node text mapping.
    pub fn index_file(&mut self, path: &Path, language: Language) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read file {:?}: {}", path, e);
                return;
            }
        };

        let parsed = match parse_source(&content, language) {
            Some(p) => p,
            None => return,
        };

        // Extract function definitions
        self.extract_functions(&parsed.root_node(), &parsed.source_bytes, &parsed.content);
    }

    fn extract_functions(&mut self, node: &tree_sitter::Node, source: &[u8], full_content: &str) {
        if let Some(func_name) = get_function_name(node, source) {
            // Get the full node text
            let start_byte = node.start_byte();
            let end_byte = node.end_byte();

            if let Some(node_text) = full_content.get(start_byte..end_byte) {
                self.functions
                    .insert(func_name.clone(), node_text.to_string());
            }
        }

        // Recurse into children
        for child in node.children(&mut node.walk()) {
            self.extract_functions(&child, source, full_content);
        }
    }

    /// Index all source files in a directory.
    ///
    /// Walks the directory tree, filters by extension for the specified languages,
    /// and calls index_file on each matching file.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory to walk
    /// * `languages` - Languages to index
    /// * `max_size` - Maximum file size in bytes to index
    /// * `exclude` - Path patterns to exclude (checked as substring matches)
    pub fn index_directory(
        &mut self,
        dir: &Path,
        languages: &[Language],
        max_size: usize,
        exclude: &[String],
    ) {
        // Build extension map for the requested languages
        let extensions = get_extensions_for_languages(languages);

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip if not a file
            if !path.is_file() {
                continue;
            }

            // Check exclusion patterns
            let path_str = path.to_string_lossy();
            if exclude.iter().any(|pattern| path_str.contains(pattern)) {
                continue;
            }

            // Check file size
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.len() > max_size as u64 {
                    tracing::debug!("Skipping large file: {:?}", path);
                    continue;
                }
            }

            // Check extension and determine language
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if let Some(&lang) = extensions.get(ext) {
                    self.index_file(path, lang);
                }
            }
        }
    }

    /// Look up a function by name.
    ///
    /// Returns the function body text if found, None otherwise.
    pub fn lookup(&self, name: &str) -> Option<&str> {
        self.functions.get(name).map(|s| s.as_str())
    }

    /// Check if a function name exists in the index.
    pub fn contains(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

}

/// Get file extensions for the specified languages.
///
/// Returns a map from extension to Language.
pub fn get_extensions_for_languages(languages: &[Language]) -> HashMap<&'static str, Language> {
    let mut ext_map = HashMap::new();

    for &lang in languages {
        match lang {
            Language::C => {
                ext_map.insert("c", Language::C);
                ext_map.insert("h", Language::C);
            }
            Language::Rust => {
                ext_map.insert("rs", Language::Rust);
            }
            Language::Python => {
                ext_map.insert("py", Language::Python);
            }
            Language::JavaScript => {
                ext_map.insert("js", Language::JavaScript);
                ext_map.insert("mjs", Language::JavaScript);
            }
        }
    }

    ext_map
}
