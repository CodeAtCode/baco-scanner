#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

//! Coverage tests for agent_scaffold modules.
//!
//! These tests cover edge cases and code paths not tested in agent_scaffold_tests.rs.

use baco::agent_scaffold::call_graph_paths::{CallGraphBuilder, GraphPath};
use baco::agent_scaffold::fn_lookup::FunctionLookup;
use baco::context::control_path::Language;

use std::fs;
use std::io::Write;
use tempfile::tempdir;

// ============================================================================
// CallGraphBuilder edge case tests
// ============================================================================

#[test]
fn test_call_graph_builder_add_source_file_no_functions() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("nofuncs.py");

    // Python file with no functions - just statements
    let content = r#"
x = 42
y = x * 2
print(y)
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::Python);
    let graph = builder.build();

    // No functions means no entry points
    let paths = graph.sample_paths_to("any", 1);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_builder_add_source_file_twice_same_file() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void helper() {}
void main() { helper(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    builder.add_source_file(&file_path, Language::C); // Add same file twice
    let graph = builder.build();

    // Should handle idempotently - no duplicate entries
    let paths = graph.sample_paths_to("helper", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_build_only_python() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.py");

    let content = r#"
def leaf():
    pass

def middle():
    leaf()

def main():
    middle()
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::Python);
    let graph = builder.build();

    // main should be entry point
    let paths = graph.sample_paths_to("leaf", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_build_only_rust() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.rs");

    let content = r#"
fn leaf() {}

fn middle() {
    leaf();
}

fn main() {
    middle();
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::Rust);
    let graph = builder.build();

    let paths = graph.sample_paths_to("leaf", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_build_only_c() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void leaf() {}

void middle() {
    leaf();
}

void main() {
    middle();
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("leaf", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_call_graph_builder_build_mixed_languages() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rust_file = dir.path().join("test.rs");
    let py_file = dir.path().join("test.py");
    let c_file = dir.path().join("test.c");

    let rust_content = r#"
fn rust_leaf() {}
fn rust_main() { rust_leaf(); }
"#;

    let py_content = r#"
def py_leaf():
    pass
def py_main():
    py_leaf()
"#;

    let c_content = r#"
void c_leaf() {}
void c_main() { c_leaf(); }
"#;

    fs::write(&rust_file, rust_content).expect("Failed to write rust file");
    fs::write(&py_file, py_content).expect("Failed to write py file");
    fs::write(&c_file, c_content).expect("Failed to write c file");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&rust_file, Language::Rust);
    builder.add_source_file(&py_file, Language::Python);
    builder.add_source_file(&c_file, Language::C);
    let graph = builder.build();

    // Should have entry points from all languages
    let rust_paths = graph.sample_paths_to("rust_leaf", 5);
    let py_paths = graph.sample_paths_to("py_leaf", 5);
    let c_paths = graph.sample_paths_to("c_leaf", 5);

    assert!(!rust_paths.is_empty());
    assert!(!py_paths.is_empty());
    assert!(!c_paths.is_empty());
}

#[test]
fn test_call_graph_sample_paths_nonexistent_target() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void main() {}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("completely_nonexistent", 10);
    assert!(paths.is_empty());
}

#[test]
fn test_call_graph_sample_paths_count_larger_than_available() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void target() {}
void main() { target(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Request more paths than possible (only one entry point, one path)
    let paths = graph.sample_paths_to("target", 100);

    // Should return all available paths (at least 1)
    assert!(!paths.is_empty());
    assert!(paths.len() <= 100);
}

#[test]
fn test_call_graph_recursive_chain_three_levels() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void level3() {}
void level2() { level3(); }
void level1() { level2(); }
void main() { level1(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("level3", 5);
    assert!(!paths.is_empty());

    // Path should contain all 4 functions
    for path in &paths {
        assert!(path.0.contains(&"main".to_string()));
        assert!(path.0.contains(&"level1".to_string()));
        assert!(path.0.contains(&"level2".to_string()));
        assert!(path.0.contains(&"level3".to_string()));
    }
}

#[test]
fn test_call_graph_self_recursive_function() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void recursive() { recursive(); }
void main() { recursive(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Should not infinite loop - should handle self-recursion gracefully
    let paths = graph.sample_paths_to("recursive", 5);

    // Path should exist (main -> recursive)
    assert!(!paths.is_empty());
    for path in &paths {
        assert!(path.0.contains(&"main".to_string()));
        assert!(path.0.contains(&"recursive".to_string()));
    }
}

#[test]
fn test_call_graph_diamond_pattern() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    // Diamond: main -> A, main -> B, A -> C, B -> C
    let content = r#"
void common() {}
void branch_a() { common(); }
void branch_b() { common(); }
void main() { branch_a(); branch_b(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    let paths = graph.sample_paths_to("common", 5);
    assert!(!paths.is_empty());

    // Each path should go through either branch_a or branch_b
    for path in &paths {
        assert!(path.0.contains(&"main".to_string()));
        assert!(path.0.contains(&"common".to_string()));
        // Path should contain at least one branch
        let has_branch_a = path.0.contains(&"branch_a".to_string());
        let has_branch_b = path.0.contains(&"branch_b".to_string());
        assert!(has_branch_a || has_branch_b);
    }
}

#[test]
fn test_call_graph_disconnected_functions() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    // Component A: main -> a1 -> a2
    // Component B: b1 -> b2 (disconnected from A)
    // main and b1 are both entry points (neither is called by another function).
    // sample_paths_to iterates ALL entry points, so paths to b2 are reachable from b1.
    let content = r#"
void a2() {}
void a1() { a2(); }
void b2() {}
void b1() { b2(); }
void main() { a1(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // Paths from main (entry) to a2 should exist: main -> a1 -> a2
    let paths_to_a2 = graph.sample_paths_to("a2", 5);
    assert!(!paths_to_a2.is_empty());

    // Paths to b2 should exist from entry point b1: b1 -> b2
    let paths_to_b2 = graph.sample_paths_to("b2", 5);
    assert!(!paths_to_b2.is_empty());

    // No path from any entry point to a non-existent function
    let paths_to_ghost = graph.sample_paths_to("ghost", 5);
    assert!(paths_to_ghost.is_empty());
}

#[test]
fn test_call_graph_builder_build_empty_no_files() {
    let builder = CallGraphBuilder::new();
    let graph = builder.build();

    let paths = graph.sample_paths_to("anything", 10);
    assert!(paths.is_empty());
}

// ============================================================================
// CallGraph direct tests
// ============================================================================

#[test]
fn test_graph_path_debug_display() {
    let path = GraphPath(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    let debug_str = format!("{:?}", path);

    assert!(debug_str.contains("a"));
    assert!(debug_str.contains("b"));
    assert!(debug_str.contains("c"));
}

// ============================================================================
// FunctionLookup edge case tests
// ============================================================================

#[test]
fn test_function_lookup_index_file_nonexistent() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("does_not_exist.rs");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Rust);

    // Should remain empty, no panic
    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_index_file_empty() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("empty.rs");

    let content = "";

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Rust);

    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_index_file_no_functions() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("nofuncs.rs");

    // Rust file with no functions - just type definitions
    let content = r#"
struct MyStruct {
    x: i32,
}

const MY_CONST: i32 = 42;
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Rust);

    // No functions should be indexed
    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_index_directory_empty() {
    let dir = tempdir().expect("Failed to create temp dir");

    let mut lookup = FunctionLookup::new();
    lookup.index_directory(dir.path(), &[Language::Rust], 1024 * 1024, &[]);

    assert!(lookup.is_empty());
}

#[test]
fn test_function_lookup_index_directory_nested() {
    let dir = tempdir().expect("Failed to create temp dir");
    let subdir = dir.path().join("subdir");
    let nested_subdir = subdir.join("nested");

    fs::create_dir_all(&nested_subdir).expect("Failed to create dirs");

    let file1 = dir.path().join("root.rs");
    let file2 = subdir.join("sub.rs");
    let file3 = nested_subdir.join("deep.rs");

    fs::write(&file1, "fn root_func() {}").expect("Failed to write file1");
    fs::write(&file2, "fn sub_func() {}").expect("Failed to write file2");
    fs::write(&file3, "fn deep_func() {}").expect("Failed to write file3");

    let mut lookup = FunctionLookup::new();
    lookup.index_directory(dir.path(), &[Language::Rust], 1024 * 1024, &[]);

    assert!(lookup.contains("root_func"));
    assert!(lookup.contains("sub_func"));
    assert!(lookup.contains("deep_func"));
    assert_eq!(lookup.len(), 3);
}

#[test]
fn test_function_lookup_index_directory_mixed_types() {
    let dir = tempdir().expect("Failed to create temp dir");

    let rust_file = dir.path().join("test.rs");
    let py_file = dir.path().join("test.py");
    let c_file = dir.path().join("test.c");

    fs::write(&rust_file, "fn rust_func() {}").expect("Failed to write rust");
    fs::write(&py_file, "def py_func(): pass").expect("Failed to write py");
    fs::write(&c_file, "void c_func() {}").expect("Failed to write c");

    let mut lookup = FunctionLookup::new();
    lookup.index_directory(
        dir.path(),
        &[Language::Rust, Language::Python, Language::C],
        1024 * 1024,
        &[],
    );

    assert!(lookup.contains("rust_func"));
    assert!(lookup.contains("py_func"));
    assert!(lookup.contains("c_func"));
}

#[test]
fn test_function_lookup_lookup_empty_string() {
    let lookup = FunctionLookup::new();
    assert!(lookup.lookup("").is_none());
    assert!(!lookup.contains(""));
}

#[test]
fn test_function_lookup_exact_match_only() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.rs");

    let content = r#"
fn foo() {}
fn foo_bar() {}
fn my_foo() {}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::Rust);

    // Exact match only - no substring matching
    assert!(lookup.contains("foo"));
    assert!(lookup.contains("foo_bar"));
    assert!(lookup.contains("my_foo"));

    // Lookup should be exact
    assert!(lookup.lookup("foo").is_some());
    assert!(lookup.lookup("foo_bar").is_some());
    assert!(lookup.lookup("my_foo").is_some());
}

#[test]
fn test_function_lookup_multiple_functions_same_name_different_files() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file1 = dir.path().join("lib1.rs");
    let file2 = dir.path().join("lib2.rs");

    fs::write(&file1, "fn duplicate() { println!(\"lib1\"); }").expect("Failed to write file1");
    fs::write(&file2, "fn duplicate() { println!(\"lib2\"); }").expect("Failed to write file2");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file1, Language::Rust);
    lookup.index_file(&file2, Language::Rust);

    // Second file overwrites first (HashMap behavior)
    assert!(lookup.contains("duplicate"));
    assert_eq!(lookup.len(), 1);
}

#[test]
fn test_function_lookup_contains_variations() {
    let mut lookup = FunctionLookup::new();

    // Empty lookup
    assert!(!lookup.contains("any"));
    assert!(!lookup.contains(""));

    // Add a function
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.rs");
    fs::write(&file_path, "fn test_func() {}").expect("Failed to write file");

    lookup.index_file(&file_path, Language::Rust);

    assert!(lookup.contains("test_func"));
    assert!(!lookup.contains("test"));
    assert!(!lookup.contains("func"));
}

#[test]
fn test_function_lookup_len_transitions() {
    let mut lookup = FunctionLookup::new();

    assert_eq!(lookup.len(), 0);

    let dir = tempdir().expect("Failed to create temp dir");

    let file1 = dir.path().join("file1.rs");
    let file2 = dir.path().join("file2.rs");

    fs::write(&file1, "fn f1() {}").expect("Failed to write file1");
    fs::write(&file2, "fn f2() {}").expect("Failed to write file2");

    lookup.index_file(&file1, Language::Rust);
    assert_eq!(lookup.len(), 1);

    lookup.index_file(&file2, Language::Rust);
    assert_eq!(lookup.len(), 2);
}

#[test]
fn test_function_lookup_index_file_javascript() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.js");

    let content = r#"
function helper(x) {
    return x * 2;
}

function main() {
    helper(42);
}
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file_path, Language::JavaScript);

    assert!(lookup.contains("helper") || lookup.contains("main"));
}

#[test]
fn test_function_lookup_index_directory_with_exclusions() {
    let dir = tempdir().expect("Failed to create temp dir");

    let include_file = dir.path().join("include.rs");
    let exclude_file = dir.path().join("exclude_test.rs");

    fs::write(&include_file, "fn included() {}").expect("Failed to write include");
    fs::write(&exclude_file, "fn excluded() {}").expect("Failed to write exclude");

    let mut lookup = FunctionLookup::new();
    lookup.index_directory(
        dir.path(),
        &[Language::Rust],
        1024 * 1024,
        &["exclude".to_string()],
    );

    assert!(lookup.contains("included"));
    assert!(!lookup.contains("excluded"));
}

#[test]
fn test_function_lookup_index_directory_with_max_size() {
    let dir = tempdir().expect("Failed to create temp dir");

    let small_file = dir.path().join("small.rs");
    let large_file = dir.path().join("large.rs");

    fs::write(&small_file, "fn small() {}").expect("Failed to write small");
    // Create a file larger than max_size
    fs::write(&large_file, "fn large() {} ".repeat(1000)).expect("Failed to write large");

    let mut lookup = FunctionLookup::new();
    // Max size of 50 bytes - large file should be skipped
    lookup.index_directory(dir.path(), &[Language::Rust], 50, &[]);

    assert!(lookup.contains("small"));
    // Large file should be skipped due to size
    assert!(!lookup.contains("large"));
}

// ============================================================================
// Integration tests combining both modules
// ============================================================================

#[test]
fn test_builder_and_lookup_combined_workflow() {
    let dir = tempdir().expect("Failed to create temp dir");

    let file1 = dir.path().join("lib1.rs");
    let file2 = dir.path().join("lib2.rs");

    let lib1_content = r#"
fn shared_helper() {}
fn lib1_main() { shared_helper(); }
"#;

    let lib2_content = r#"
fn shared_helper() {}
fn lib2_main() { shared_helper(); }
"#;

    fs::write(&file1, lib1_content).expect("Failed to write lib1");
    fs::write(&file2, lib2_content).expect("Failed to write lib2");

    // Use CallGraphBuilder
    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file1, Language::Rust);
    builder.add_source_file(&file2, Language::Rust);
    let graph = builder.build();

    // Use FunctionLookup
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&file1, Language::Rust);
    lookup.index_file(&file2, Language::Rust);

    // Both should have found functions
    assert!(lookup.contains("lib1_main"));
    assert!(lookup.contains("lib2_main"));
    assert!(lookup.contains("shared_helper"));

    // Graph should have entry points - verify by sampling
    let _paths = graph.sample_paths_to("lib1_main", 1);
    // May or may not find paths, but should not panic
}

#[test]
fn test_call_graph_builder_sample_paths_with_main_entry() {
    let dir = tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("test.c");

    let content = r#"
void helper() {}
void main() { helper(); }
"#;

    let mut file = fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content.as_bytes())
        .expect("Failed to write content");

    let mut builder = CallGraphBuilder::new();
    builder.add_source_file(&file_path, Language::C);
    let graph = builder.build();

    // main should be recognized as entry point
    let paths = graph.sample_paths_to("helper", 5);
    assert!(!paths.is_empty());
}
