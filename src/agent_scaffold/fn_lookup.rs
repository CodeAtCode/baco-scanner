//! Function lookup and indexing across source files.
//!
//! Indexes functions by name and exposes lookup for function body retrieval.

use std::collections::HashMap;
use std::path::Path;
use tree_sitter::Parser;
use walkdir::WalkDir;

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

        let mut parser = Parser::new();
        let ts_lang = match language {
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        };

        if let Err(e) = parser.set_language(&ts_lang) {
            tracing::warn!("Failed to set language for {:?}: {}", path, e);
            return;
        }

        let tree = match parser.parse(&content, None) {
            Some(t) => t,
            None => {
                tracing::warn!("Failed to parse file {:?}", path);
                return;
            }
        };

        let root = tree.root_node();
        if root.has_error() {
            tracing::warn!("Parse error in file {:?}", path);
            return;
        }

        let source_bytes = content.as_bytes();

        // Extract function definitions
        self.extract_functions(&root, source_bytes, &content);
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

    /// Get the number of indexed functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Get file extensions for the specified languages.
///
/// Returns a map from extension to Language.
fn get_extensions_for_languages(languages: &[Language]) -> HashMap<&'static str, Language> {
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

/// Extract function name from a function definition node.
fn get_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let kind = node.kind();

    // Check if this is a function definition node for any supported language
    let is_func_def = matches!(
        kind,
        "function_definition"
            | "function_item"
            | "function_declaration"
            | "method_definition"
            | "declaration"
    );

    if !is_func_def {
        return None;
    }

    // Find the name child node
    for child in node.children(&mut node.walk()) {
        let child_kind = child.kind();

        // Direct identifier
        if child_kind == "identifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // Rust: visibility + name pattern
        if child_kind == "name" {
            if let Some(name_node) = child.child(0) {
                if name_node.kind() == "identifier" {
                    return name_node.utf8_text(source).ok().map(|s| s.to_string());
                }
            }
        }

        // Python/Rust function_definition with name child
        if child_kind == "function_definition" || child_kind == "declarator" {
            for name_child in child.children(&mut child.walk()) {
                if name_child.kind() == "identifier" {
                    return name_child.utf8_text(source).ok().map(|s| s.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn create_temp_file(content: &str, ext: &str) -> PathBuf {
        let mut temp_dir = std::env::temp_dir();
        temp_dir.push("baco_fn_lookup_test");
        let _ = fs::create_dir_all(&temp_dir);

        let file_path = temp_dir.join(format!("test.{}", ext));
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }

    #[test]
    fn test_new_empty() {
        let lookup = FunctionLookup::new();
        assert!(lookup.is_empty());
        assert_eq!(lookup.len(), 0);
        assert!(lookup.lookup("main").is_none());
        assert!(!lookup.contains("main"));
    }

    #[test]
    fn test_index_rust_file() {
        let content = r#"
fn main() {
    println!("Hello");
}

fn helper(x: i32) -> i32 {
    x * 2
}
"#;

        let path = create_temp_file(content, "rs");
        let mut lookup = FunctionLookup::new();
        lookup.index_file(&path, Language::Rust);

        assert!(lookup.contains("main"));
        assert!(lookup.contains("helper"));
        assert!(lookup.lookup("main").is_some());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_index_python_file() {
        let content = r#"
def main():
    print("Hello")

def helper(x):
    return x * 2
"#;

        let path = create_temp_file(content, "py");
        let mut lookup = FunctionLookup::new();
        lookup.index_file(&path, Language::Python);

        assert!(lookup.contains("main"));
        assert!(lookup.contains("helper"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_nonexistent_function() {
        let lookup = FunctionLookup::new();
        assert!(lookup.lookup("nonexistent").is_none());
        assert!(!lookup.contains("nonexistent"));
    }

    #[test]
    fn test_extensions_map() {
        let langs = vec![
            Language::C,
            Language::Rust,
            Language::Python,
            Language::JavaScript,
        ];
        let ext_map = get_extensions_for_languages(&langs);

        assert_eq!(ext_map.get("c"), Some(&Language::C));
        assert_eq!(ext_map.get("h"), Some(&Language::C));
        assert_eq!(ext_map.get("rs"), Some(&Language::Rust));
        assert_eq!(ext_map.get("py"), Some(&Language::Python));
        assert_eq!(ext_map.get("js"), Some(&Language::JavaScript));
        assert_eq!(ext_map.get("mjs"), Some(&Language::JavaScript));
        assert!(!ext_map.contains_key("txt"));
    }
}
