//! Unit tests for agent_scaffold modules: call_graph_paths and fn_lookup
//!
//! Comprehensive coverage of CallGraph, GraphPath, CallGraphBuilder, and FunctionLookup APIs.

use baco::agent_scaffold::call_graph_paths::CallGraphBuilder;
use baco::agent_scaffold::fn_lookup::FunctionLookup;
use baco::context::control_path::Language;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

// ============================================================================
// CallGraphBuilder tests
// ============================================================================

#[test]
fn test_call_graph_builder_new_empty() {
    let builder = CallGraphBuilder::new();
    let graph = builder.build();

    // Empty graph has no paths to any target
    let paths = graph.sample_paths_to("anything", 10);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_builder_add_source_file_c() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void helper(int x) {
    return;
}

void main() {
    helper(42);
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // main should be an entry point - we can find paths from main to helper
    let paths = graph.sample_paths_to("helper", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_add_source_file_python() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.py");

    let content = r#"
def helper(x):
    return x * 2

def main():
    helper(42)
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::Python);
    let graph = builder.build();

    // main should be an entry point - we can find paths from main to helper
    let paths = graph.sample_paths_to("helper", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_empty_graph_no_paths() {
    let builder = CallGraphBuilder::new();
    let graph = builder.build();

    // Empty graph has no paths to any target
    let paths = graph.sample_paths_to("nonexistent", 10);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_builder_build_entry_points() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("entry.c");

    let content = r#"
void leaf() {}
void middle() { leaf(); }
void main() { middle(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // main should be the entry point - we can find paths to leaf and middle from main
    let paths_to_leaf = graph.sample_paths_to("leaf", 5);
    let paths_to_middle = graph.sample_paths_to("middle", 5);
    assert!(!paths_to_leaf.is_empty());
    assert!(!paths_to_middle.is_empty());
}

#[test]
fn test_call_graph_sample_paths_to_existing() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("paths.c");

    let content = r#"
void target() {}
void middle() { target(); }
void main() { middle(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("target", 5);

    // Should find at least one path from main to target
    assert!(!paths.is_empty());
    // Each path should contain main and target
    for path in &paths {
        assert!(path.0.contains(&"main".to_string()));
        assert!(path.0.contains(&"target".to_string()));
    }
}

#[test]
fn test_call_graph_sample_paths_to_nonexistent() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("empty.c");

    let content = r#"
void main() {}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("nonexistent_function", 10);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_sample_paths_zero_count() {
    let builder = CallGraphBuilder::new();
    let graph = builder.build();

    let paths = graph.sample_paths_to("target", 0);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_malformed_source_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("malformed.c");

    // Malformed C code - should be handled gracefully
    let content = r#"
void broken( {
    int x = ;
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    // Should not panic on malformed source
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Graph may be empty or partial, but should not crash
    let _ = graph.sample_paths_to("any", 1);
}

#[test]
fn test_call_graph_empty_file_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("empty.c");

    // Empty file
    let content = "";

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Empty file produces empty graph
    let paths = graph.sample_paths_to("any", 1);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_nonexistent_file_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("does_not_exist.c");

    let mut builder = CallGraphBuilder::new();
    // Should not panic on nonexistent file
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Graph should be empty
    let paths = graph.sample_paths_to("any", 1);
    assert!(paths.is_empty());
}

// ============================================================================
// FunctionLookup tests
// ============================================================================

#[test]
fn test_function_lookup_new_empty() {
    let lookup = FunctionLookup::new();

    assert!(lookup.is_empty());
    assert_eq!(lookup.len(), 0);
    assert!(lookup.lookup("main").is_none());
    assert!(!lookup.contains("main"));
}

#[test]
fn test_function_lookup_index_file_rust() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.rs");

    let content = r#"
fn helper(x: i32) -> i32 {
    x * 2
}

fn main() {
    let y = helper(42);
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Rust);

    assert!(lookup.contains("helper"));
    assert!(lookup.contains("main"));
    assert!(lookup.lookup("helper").is_some());
    assert!(lookup.lookup("main").is_some());
    assert_eq!(lookup.len(), 2);
}

#[test]
fn test_function_lookup_index_file_python() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.py");

    let content = r#"
def helper(x):
    return x * 2

def main():
    y = helper(42)
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Python);

    assert!(lookup.contains("helper"));
    assert!(lookup.contains("main"));
    assert!(lookup.lookup("helper").is_some());
}

#[test]
fn test_function_lookup_index_file_c() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void helper(int x) {
    return;
}

void main() {
    helper(42);
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::C);

    assert!(lookup.contains("helper"));
    assert!(lookup.contains("main"));
}

#[test]
fn test_function_lookup_index_directory() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Create multiple files
    let file1 = dir.path().join("file1.rs");
    let file2 = dir.path().join("file2.rs");

    fs::write(&file1, "fn func1() {}").expect("Failed to write file1");
    fs::write(&file2, "fn func2() {}").expect("Failed to write file2");

    let mut lookup = FunctionLookup::new();
    lookup.index_directory(dir.path(), &[Language::Rust], 1024 * 1024, &[]);

    assert!(lookup.contains("func1"));
    assert!(lookup.contains("func2"));
    assert!(lookup.lookup("func1").is_some());
    assert!(lookup.lookup("func2").is_some());
}

#[test]
fn test_function_lookup_lookup_unknown() {
    let lookup = FunctionLookup::new();

    assert!(lookup.lookup("nonexistent_function").is_none());
    assert!(!lookup.contains("nonexistent_function"));
}

#[test]
fn test_function_lookup_malformed_source_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("malformed.rs");

    let content = r#"
fn broken( {
    let x = ;
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    // Should not panic on malformed source
    lookup.index_file(&file_path, Language::Rust);

    // May or may not have functions, but should not crash
    let _ = lookup.len();
}

#[test]
fn test_function_lookup_empty_file_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("empty.py");

    let content = "";

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Python);

    // Empty file should result in no functions
    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_nonexistent_file_handled() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("does_not_exist.rs");

    let mut lookup = FunctionLookup::new();
    // Should not panic on nonexistent file
    lookup.index_file(&file_path, Language::Rust);

    // Should remain empty
    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_multiple_files_indexing() {
    let dir = tempdir().expect("Failed to create temp dir");

    let file1 = dir.path().join("lib1.rs");
    let file2 = dir.path().join("lib2.rs");

    fs::write(&file1, "fn alpha() {}").expect("Failed to write file1");
    fs::write(&file2, "fn beta() {}").expect("Failed to write file2");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file1, Language::Rust);
    lookup.index_file(&file2, Language::Rust);

    assert_eq!(lookup.len(), 2);
    assert!(lookup.contains("alpha"));
    assert!(lookup.contains("beta"));
}

#[test]
fn test_function_lookup_is_empty_transitions() {
    let mut lookup = FunctionLookup::new();

    // Initially empty
    assert!(lookup.is_empty());

    // After indexing a file with functions
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.rs");
    fs::write(&file_path, "fn foo() {}").expect("Failed to write file");

    lookup.index_file(&file_path, Language::Rust);
    assert!(!lookup.is_empty());
    assert_eq!(lookup.len(), 1);
}
