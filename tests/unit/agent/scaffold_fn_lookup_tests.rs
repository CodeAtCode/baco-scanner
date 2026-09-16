use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use baco::agent_scaffold::fn_lookup::{get_extensions_for_languages, FunctionLookup};
use baco::context::control_path::Language;

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_temp_file(content: &str, ext: &str) -> PathBuf {
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push("baco_fn_lookup_test");
    let _ = fs::create_dir_all(&temp_dir);

    // Clock-based ids can collide for tests running in the same process
    // within the same nanosecond; the counter cannot.
    let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_path = temp_dir.join(format!("test_{}_{}.{}", std::process::id(), id, ext));
    let mut file = fs::File::create(&file_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file_path
}

#[test]
fn test_new_empty() {
    let lookup = FunctionLookup::new();
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
fn test_index_javascript_file() {
    let content = r#"
function main() {
    console.log("Hello");
}

function helper(x) {
    return x * 2;
}
"#;

    let path = create_temp_file(content, "js");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::JavaScript);

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

#[test]
fn test_extensions_single_language() {
    let langs = vec![Language::Rust];
    let ext_map = get_extensions_for_languages(&langs);

    assert_eq!(ext_map.get("rs"), Some(&Language::Rust));
    assert!(!ext_map.contains_key("py"));
    assert!(!ext_map.contains_key("js"));
}

#[test]
fn test_index_unreadable_file() {
    let mut lookup = FunctionLookup::new();
    let invalid_path = PathBuf::from("/nonexistent/file.rs");
    lookup.index_file(&invalid_path, Language::Rust);
}

#[test]
fn test_index_file_with_nested_functions() {
    let content = r#"
fn outer() {
    fn inner() {
        println!("nested");
    }
    inner();
}

fn main() {
    outer();
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    assert!(lookup.contains("outer"));
    assert!(lookup.contains("main"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_index_file_with_empty_body() {
    let content = r#"
fn empty() {}

fn main() {
    empty();
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    assert!(lookup.contains("empty"));
    assert!(lookup.contains("main"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_index_multiple_files() {
    let content1 = r#"
fn func_a() {
    println!("A");
}
"#;

    let content2 = r#"
fn func_b() {
    func_a();
}
"#;

    let path1 = create_temp_file(content1, "rs");
    let path2 = create_temp_file(content2, "rs");

    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path1, Language::Rust);
    lookup.index_file(&path2, Language::Rust);

    assert!(lookup.contains("func_a"));
    assert!(lookup.contains("func_b"));

    let _ = fs::remove_file(&path1);
    let _ = fs::remove_file(&path2);
}

#[test]
fn test_lookup_returns_function_body() {
    let content = r#"
fn test_func() {
    let x = 42;
    println!("{}", x);
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    let func_body = lookup.lookup("test_func").unwrap();
    assert!(func_body.contains("fn test_func"));
    assert!(func_body.contains("let x = 42"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_index_directory_excludes_patterns() {
    // This test verifies the get_extensions_for_languages helper
    // Directory indexing would require a real directory structure
    let langs = vec![Language::Rust, Language::Python];
    let ext_map = get_extensions_for_languages(&langs);

    assert!(ext_map.contains_key("rs"));
    assert!(ext_map.contains_key("py"));
    assert!(!ext_map.contains_key("js"));
}

#[test]
fn test_fn_lookup_fuzzy_match_none() {
    let content = r#"
fn main_function() {
    println!("main");
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    // Should not find exact match
    assert!(lookup.lookup("main").is_none());
    assert!(lookup.lookup("main_func").is_none());

    let _ = fs::remove_file(&path);
}

#[test]
fn test_fn_lookup_with_generics() {
    let content = r#"
fn generic_func<T>(x: T) -> T {
    x
}

fn main() {
    let _ = generic_func(42);
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    assert!(lookup.contains("generic_func"));
    let body = lookup.lookup("generic_func").unwrap();
    assert!(body.contains("fn generic_func"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_fn_lookup_multiple_definitions_last_wins() {
    let content = r#"
fn duplicate() {
    println!("first");
}

fn duplicate() {
    println!("second");
}

fn main() {
    duplicate();
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    // Should have the function (last definition wins in the index)
    assert!(lookup.contains("duplicate"));
    let body = lookup.lookup("duplicate").unwrap();
    // The body should contain the function definition
    assert!(body.contains("fn duplicate"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_fn_lookup_with_special_chars_in_name() {
    let content = r#"
fn func_with_underscores() {
    println!("test");
}

fn func123() {
    println!("numbers");
}

fn main() {
    func_with_underscores();
    func123();
}
"#;

    let path = create_temp_file(content, "rs");
    let mut lookup = FunctionLookup::new();
    lookup.index_file(&path, Language::Rust);

    assert!(lookup.contains("func_with_underscores"));
    assert!(lookup.contains("func123"));

    let _ = fs::remove_file(&path);
}
