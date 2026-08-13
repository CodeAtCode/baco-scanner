use std::fs;
use std::io::Write;
use std::path::PathBuf;

use baco::agent_scaffold::fn_lookup::{get_extensions_for_languages, FunctionLookup};
use baco::context::control_path::Language;

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
