use std::collections::{HashMap, HashSet};

use baco::agent_scaffold::call_graph_paths::{
    hash_string, random_dfs, CallGraph, CallGraphBuilder,
};

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
