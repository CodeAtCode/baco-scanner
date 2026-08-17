use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use baco::agent_scaffold::call_graph_paths::{
    hash_string, random_dfs, CallGraph, CallGraphBuilder,
};
use baco::context::control_path::Language;

fn create_temp_file(content: &str, ext: &str) -> PathBuf {
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push("baco_call_graph_test");
    let _ = fs::create_dir_all(&temp_dir);

    let file_path = temp_dir.join(format!("test.{}", ext));
    let mut file = fs::File::create(&file_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file_path
}

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
fn test_hash_different_strings() {
    let h1 = hash_string("test1");
    let h2 = hash_string("test2");
    assert_ne!(h1, h2);
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

#[test]
fn test_random_dfs_with_cycle() {
    let mut adj = HashMap::new();
    adj.insert("a".to_string(), vec!["b".to_string()]);
    adj.insert("b".to_string(), vec!["c".to_string()]);
    adj.insert("c".to_string(), vec!["a".to_string()]); // Cycle

    let mut visited = HashSet::new();
    let mut path = vec!["a".to_string()];

    // Should find path despite cycle
    let result = random_dfs("a", "c", &adj, &mut visited, &mut path, 10);
    assert!(result.is_some());
}

#[test]
fn test_random_dfs_exceeds_max_depth() {
    let mut adj = HashMap::new();
    adj.insert("a".to_string(), vec!["b".to_string()]);
    adj.insert("b".to_string(), vec!["c".to_string()]);
    adj.insert("c".to_string(), vec!["d".to_string()]);

    let mut visited = HashSet::new();
    let mut path = vec!["a".to_string()];

    // Max depth too small to reach target
    let result = random_dfs("a", "d", &adj, &mut visited, &mut path, 2);
    assert!(result.is_none());
}

#[test]
fn test_sample_paths_to_empty_graph() {
    let graph = CallGraph {
        adjacency: HashMap::new(),
        entry_points: vec![],
    };

    let paths = graph.sample_paths_to("target", 5);
    assert!(paths.is_empty());
}

#[test]
fn test_sample_paths_to_target_not_in_graph() {
    let mut adj = HashMap::new();
    adj.insert("main".to_string(), vec!["helper".to_string()]);

    let graph = CallGraph {
        adjacency: adj,
        entry_points: vec!["main".to_string()],
    };

    let paths = graph.sample_paths_to("nonexistent", 5);
    assert!(paths.is_empty());
}

#[test]
fn test_sample_paths_to_direct_entry() {
    let graph = CallGraph {
        adjacency: HashMap::new(),
        entry_points: vec!["target".to_string()],
    };

    let paths = graph.sample_paths_to("target", 5);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].0, vec!["target".to_string()]);
}

#[test]
fn test_sample_paths_multiple_entries() {
    let mut adj = HashMap::new();
    adj.insert("main".to_string(), vec!["helper".to_string()]);
    adj.insert("_start".to_string(), vec!["init".to_string()]);
    adj.insert("init".to_string(), vec!["target".to_string()]);

    let graph = CallGraph {
        adjacency: adj,
        entry_points: vec!["main".to_string(), "_start".to_string()],
    };

    let paths = graph.sample_paths_to("target", 5);
    // Should find path from _start -> init -> target
    assert!(!paths.is_empty());
}

#[test]
fn test_sample_paths_count_limit() {
    let mut adj = HashMap::new();
    adj.insert("main".to_string(), vec!["a".to_string()]);
    adj.insert("a".to_string(), vec!["target".to_string()]);

    let graph = CallGraph {
        adjacency: adj,
        entry_points: vec!["main".to_string()],
    };

    let paths = graph.sample_paths_to("target", 2);
    assert!(paths.len() <= 2);
}

#[test]
fn test_call_graph_builder_with_rust_file() {
    let content = r#"
fn main() {
    helper();
}

fn helper() {
    println!("Hello");
}
"#;

    let path = create_temp_file(content, "rs");
    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&path, Language::Rust);
    let graph = builder.build();

    // main should be an entry point (not called by anyone)
    assert!(graph.entry_points.contains(&"main".to_string()));
    // helper should be called by main
    assert!(graph.adjacency.contains_key("main"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_call_graph_builder_with_python_file() {
    let content = r#"
def main():
    helper()

def helper():
    print("Hello")
"#;

    let path = create_temp_file(content, "py");
    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&path, Language::Python);
    let graph = builder.build();

    assert!(graph.entry_points.contains(&"main".to_string()));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_call_graph_builder_unreadable_file() {
    let mut builder = CallGraphBuilder::new();
    let invalid_path = PathBuf::from("/nonexistent/file.rs");
    builder.add_source_file(&invalid_path, Language::Rust);
    let graph = builder.build();

    // Should handle gracefully with empty graph
    assert!(graph.entry_points.is_empty());
}