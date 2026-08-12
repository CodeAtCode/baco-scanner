//! Call graph construction and path sampling for agent context.
//!
//! Builds a lightweight call graph from source files and samples random paths
//! from entry points to a target function.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::Parser;

use crate::context::control_path::Language;

/// A call graph representing function call relationships.
#[derive(Debug, Clone)]
pub struct CallGraph {
    adjacency: HashMap<String, Vec<String>>,
    entry_points: Vec<String>,
}

/// A path of function names from an entry point to a target.
#[derive(Debug, Clone)]
pub struct GraphPath(pub Vec<String>);

/// Builder for constructing a call graph from source files.
#[derive(Debug, Clone, Default)]
pub struct CallGraphBuilder {
    adjacency: HashMap<String, Vec<String>>,
    callees: HashSet<String>,
    entry_candidates: HashSet<String>,
}

impl CallGraphBuilder {
    /// Create a new CallGraphBuilder.
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            callees: HashSet::new(),
            entry_candidates: HashSet::new(),
        }
    }

    /// Add a source file to the call graph.
    ///
    /// Parses the file with tree-sitter, extracts function definitions and call sites,
    /// and adds edges to the adjacency map.
    pub fn add_source_file(&mut self, path: &Path, language: Language) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read file {:?}: {}", path, e);
                return;
            }
        };

        let mut parser = Parser::new();
        let ts_lang = language.ts_language();
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

        // Extract function definitions and their call sites
        self.extract_functions(&root, source_bytes);
    }

    fn extract_functions(&mut self, node: &tree_sitter::Node, source: &[u8]) {
        let func_name = get_function_name(node, source);
        let func_kind = get_function_node_kind(node.kind());

        if let Some(name) = func_name {
            // Add this function as an entry candidate
            self.entry_candidates.insert(name.clone());

            // Find all call sites within this function
            let _cursor = node.walk(); // Reserved for future use
            let mut calls = HashSet::new();

            // Walk the subtree to find call expressions
            if let Some(callee_names) = collect_call_sites(node, source, func_kind) {
                for callee in callee_names {
                    if callee != name {
                        calls.insert(callee.clone());
                        self.callees.insert(callee);
                    }
                }
            }

            // Add edges: function -> callees
            for callee in calls {
                self.adjacency.entry(name.clone()).or_default().push(callee);
            }
        }

        // Recurse into children
        for child in node.children(&mut node.walk()) {
            self.extract_functions(&child, source);
        }
    }

    /// Build the call graph.
    pub fn build(self) -> CallGraph {
        // Entry points are functions that are never called by others
        // plus main/_start if present
        let mut entry_points: Vec<String> = self
            .entry_candidates
            .iter()
            .filter(|name| !self.callees.contains(*name))
            .cloned()
            .collect();

        // Always include main and _start as entry points if they exist
        if self.entry_candidates.contains("main") && !entry_points.iter().any(|e| e == "main") {
            entry_points.push("main".to_string());
        }
        if self.entry_candidates.contains("_start") && !entry_points.iter().any(|e| e == "_start") {
            entry_points.push("_start".to_string());
        }

        // Sort for determinism
        entry_points.sort();

        CallGraph {
            adjacency: self.adjacency,
            entry_points,
        }
    }
}

impl CallGraph {
    /// Sample random paths from entry points to the target function.
    ///
    /// Performs a random DFS from each entry point toward the target,
    /// returning up to `count` paths. If no path is found, returns an empty vec.
    pub fn sample_paths_to(&self, target: &str, count: usize) -> Vec<GraphPath> {
        if count == 0 {
            return Vec::new();
        }

        let mut paths = Vec::new();

        for entry in &self.entry_points {
            if paths.len() >= count {
                break;
            }

            // Try random DFS from this entry point
            let mut visited = HashSet::new();
            let mut current_path = vec![entry.clone()];

            if let Some(path) = random_dfs(
                entry,
                target,
                &self.adjacency,
                &mut visited,
                &mut current_path,
                50, // max depth to avoid infinite loops
            ) {
                paths.push(GraphPath(path));
            }
        }

        paths
    }
}

/// Perform a random DFS from `current` toward `target`.
///
/// Uses a simple random walk with backtracking and a visited set to avoid cycles.
fn random_dfs(
    current: &str,
    target: &str,
    adjacency: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    path: &mut Vec<String>,
    max_depth: usize,
) -> Option<Vec<String>> {
    if current == target {
        return Some(path.clone());
    }

    if visited.contains(current) || path.len() > max_depth {
        return None;
    }

    visited.insert(current.to_string());

    if let Some(callees) = adjacency.get(current) {
        // Shuffle callees for randomness (deterministic via hash seed if rand not available)
        let mut indices: Vec<usize> = (0..callees.len()).collect();

        // Simple deterministic shuffle using LCG seeded by function name hash
        let seed = hash_string(current);
        for i in (1..indices.len()).rev() {
            let j = (seed as usize * (i + 1)) % (i + 1);
            indices.swap(i, j);
        }

        for &idx in &indices {
            let callee = &callees[idx];
            path.push(callee.clone());

            if let Some(result) = random_dfs(callee, target, adjacency, visited, path, max_depth) {
                return Some(result);
            }

            path.pop();
        }
    }

    visited.remove(current);
    None
}

/// Simple hash function for seeding random walks.
fn hash_string(s: &str) -> u32 {
    let mut hash = 0u32;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}

/// Get the function node kind for language-specific handling.
fn get_function_node_kind(kind: &str) -> &str {
    kind
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

/// Collect all call site callee names within a function body.
fn collect_call_sites(
    node: &tree_sitter::Node,
    source: &[u8],
    _func_kind: &str,
) -> Option<Vec<String>> {
    let mut callees = Vec::new();

    // Find call_expression nodes (JavaScript, C, Rust)
    // or call nodes (Python)
    let call_kinds = ["call_expression", "call", "function_call"];

    for child in node.children(&mut node.walk()) {
        if call_kinds.contains(&child.kind()) {
            // Extract the function being called
            if let Some(callee_name) = extract_callee_name(&child, source) {
                callees.push(callee_name);
            }
        }

        // Recurse into children
        if let Some(mut more) = collect_call_sites(&child, source, _func_kind) {
            callees.append(&mut more);
        }
    }

    Some(callees)
}

/// Extract the callee name from a call node.
fn extract_callee_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Look for the function child in a call expression
    for child in node.children(&mut node.walk()) {
        let kind = child.kind();

        // Direct identifier callee
        if kind == "identifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // JavaScript/TypeScript: member expression like obj.method
        if kind == "member_expression" || kind == "property_identifier" {
            if let Ok(text) = child.utf8_text(source) {
                return Some(text.to_string());
            }
        }

        // Rust: path expressions
        if kind == "path" || kind == "scoped_identifier" || kind == "scoped_use_list" {
            if let Ok(text) = child.utf8_text(source) {
                // Extract just the function name from the path
                let parts: Vec<&str> = text.split("::").collect();
                if let Some(last) = parts.last() {
                    return Some(last.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_empty() {
        let builder = CallGraphBuilder::new();
        let graph = builder.build();

        assert!(graph.entry_points.is_empty());
        assert!(graph.adjacency.is_empty());
    }

    #[test]
    fn test_sample_zero_count() {
        let graph = CallGraph {
            adjacency: HashMap::new(),
            entry_points: vec!["main".to_string()],
        };

        let paths = graph.sample_paths_to("target", 0);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = hash_string("test");
        let h2 = hash_string("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_random_dfs_no_path() {
        let mut adj = HashMap::new();
        adj.insert("a".to_string(), vec!["b".to_string()]);
        adj.insert("b".to_string(), vec!["c".to_string()]);

        let mut visited = HashSet::new();
        let mut path = vec!["a".to_string()];

        let result = random_dfs("a", "z", &adj, &mut visited, &mut path, 10);
        assert!(result.is_none());
    }

    #[test]
    fn test_random_dfs_found_path() {
        let mut adj = HashMap::new();
        adj.insert("a".to_string(), vec!["b".to_string()]);
        adj.insert("b".to_string(), vec!["c".to_string()]);

        let mut visited = HashSet::new();
        let mut path = vec!["a".to_string()];

        let result = random_dfs("a", "c", &adj, &mut visited, &mut path, 10);
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.contains(&"a".to_string()));
        assert!(path.contains(&"b".to_string()));
        assert!(path.contains(&"c".to_string()));
    }
}
