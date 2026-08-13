//! Shared tree-sitter parser setup for agent scaffold modules.
//!
//! Provides common utilities for parsing source files with tree-sitter across
//! call graph construction and function lookup modules.

use std::path::Path;
use tree_sitter::Parser;

use crate::context::control_path::Language;

/// Result of parsing a source file with tree-sitter.
pub struct ParsedFile {
    pub content: String,
    pub parser: Parser,
    pub tree: tree_sitter::Tree,
    pub source_bytes: Vec<u8>,
}

impl ParsedFile {
    /// Create a new ParsedFile from content and tree.
    pub fn new(content: String, parser: Parser, tree: tree_sitter::Tree) -> Self {
        let source_bytes = content.as_bytes().to_vec();
        Self {
            content,
            parser,
            tree,
            source_bytes,
        }
    }

    /// Get the root node of the parse tree.
    pub fn root_node(&self) -> tree_sitter::Node<'_> {
        self.tree.root_node()
    }
}

/// Parse a source file with the specified language.
///
/// Returns None if the file cannot be read, the language cannot be set,
/// or if parsing fails with errors.
pub fn parse_file(path: &Path, language: Language) -> Option<ParsedFile> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_source(&content, language)
}

/// Parse source code string with the specified language.
///
/// Returns None if parsing fails with errors.
pub fn parse_source(content: &str, language: Language) -> Option<ParsedFile> {
    let mut parser = Parser::new();
    let ts_lang = language.ts_language();

    if parser.set_language(&ts_lang).is_err() {
        tracing::warn!("Failed to set language");
        return None;
    }

    let tree = parser.parse(content, None)?;
    let root = tree.root_node();

    if root.has_error() {
        tracing::warn!("Parse error");
        return None;
    }

    Some(ParsedFile::new(content.to_string(), parser, tree))
}

/// Extract function name from a function definition node.
///
/// Supports multiple languages (C, Rust, Python, JavaScript) by checking
/// various node kinds and child patterns.
pub fn get_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
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
        if child_kind == "function_definition"
            || child_kind == "declarator"
            || child_kind == "function_declarator"
        {
            for name_child in child.children(&mut child.walk()) {
                if name_child.kind() == "identifier" {
                    return name_child.utf8_text(source).ok().map(|s| s.to_string());
                }
            }
        }
    }

    None
}
