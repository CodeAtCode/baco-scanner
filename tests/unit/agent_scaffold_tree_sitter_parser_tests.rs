use baco::agent_scaffold::tree_sitter_parser::{get_function_name, parse_source, ParsedFile};
use baco::context::control_path::Language;

#[test]
fn test_parse_rust_source() {
    let content = "fn main() { println!(\"Hello\"); }";
    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();
    assert!(!parsed.root_node().has_error());
}

#[test]
fn test_parse_c_source() {
    let content = "int main() { return 0; }";
    let result = parse_source(content, Language::C);
    assert!(result.is_some());
}

#[test]
fn test_parse_python_source() {
    let content = "def main():\n    print('Hello')";
    let result = parse_source(content, Language::Python);
    assert!(result.is_some());
}

#[test]
fn test_parse_javascript_source() {
    let content = "function main() { console.log('Hello'); }";
    let result = parse_source(content, Language::JavaScript);
    assert!(result.is_some());
}

#[test]
fn test_parse_empty_source() {
    let content = "";
    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
}

#[test]
fn test_parse_source_with_errors() {
    // Invalid Rust syntax - should return None or have error
    let content = "fn main() { invalid syntax here";
    let result = parse_source(content, Language::Rust);
    // tree-sitter may still parse with errors, so we check result existence
    // but the root node should have errors
    if let Some(parsed) = result {
        assert!(parsed.root_node().has_error());
    }
}

#[test]
fn test_parsed_file_source_bytes() {
    let content = "fn main() {}";
    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();

    assert_eq!(parsed.source_bytes.len(), content.len());
    assert_eq!(parsed.source_bytes, content.as_bytes());
}

#[test]
fn test_parsed_file_root_node() {
    let content = "fn main() { let x = 1; }";
    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();

    let root = parsed.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(!root.has_error());
}

#[test]
fn test_parse_source_preserves_content() {
    let content = r#"fn test() {
    let x = 42;
    println!("{}", x);
}"#;

    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();

    assert_eq!(parsed.content, content);
}

#[test]
fn test_get_function_name_rust() {
    let content = "fn my_function() {}";
    let parsed = parse_source(content, Language::Rust).unwrap();
    let root = parsed.root_node();

    // Find the function_definition node
    for child in root.children(&mut root.walk()) {
        if child.kind() == "function_item" {
            let name = get_function_name(&child, parsed.source_bytes.as_slice());
            assert_eq!(name, Some("my_function".to_string()));
            return;
        }
    }
    panic!("Function item not found");
}

#[test]
fn test_get_function_name_python() {
    let content = "def my_function():\n    pass";
    let parsed = parse_source(content, Language::Python).unwrap();
    let root = parsed.root_node();

    // Find the function_definition node
    for child in root.children(&mut root.walk()) {
        if child.kind() == "function_definition" {
            let name = get_function_name(&child, parsed.source_bytes.as_slice());
            assert_eq!(name, Some("my_function".to_string()));
            return;
        }
    }
    panic!("Function definition not found");
}

#[test]
fn test_get_function_name_c() {
    let content = "int my_function() { return 0; }";
    let parsed = parse_source(content, Language::C).unwrap();
    let root = parsed.root_node();

    // Find the function_definition node (C uses function_definition, not declaration)
    for child in root.children(&mut root.walk()) {
        if child.kind() == "function_definition" {
            let name = get_function_name(&child, parsed.source_bytes.as_slice());
            assert_eq!(name, Some("my_function".to_string()));
            return;
        }
    }
    panic!("Function definition not found");
}

#[test]
fn test_get_function_name_non_function_node() {
    let content = "let x = 42;";
    let parsed = parse_source(content, Language::Rust).unwrap();
    let root = parsed.root_node();

    // Find a non-function node (let_binding)
    for child in root.children(&mut root.walk()) {
        if child.kind() == "let_expression" {
            let name = get_function_name(&child, parsed.source_bytes.as_slice());
            assert_eq!(name, None);
            return;
        }
    }
}

#[test]
fn test_parse_with_whitespace() {
    let content = "  \n  fn main() {  \n  }\n  ";
    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();
    assert!(!parsed.root_node().has_error());
}

#[test]
fn test_parse_complex_rust_function() {
    let content = r#"
fn complex_function(x: i32, y: &str) -> Result<String, String> {
    if x > 0 {
        Ok(format!("{}: {}", x, y))
    } else {
        Err("Invalid input".to_string())
    }
}
"#;

    let result = parse_source(content, Language::Rust);
    assert!(result.is_some());
    let parsed = result.unwrap();
    assert!(!parsed.root_node().has_error());

    // Verify function name extraction
    let root = parsed.root_node();
    for child in root.children(&mut root.walk()) {
        if child.kind() == "function_item" {
            let name = get_function_name(&child, parsed.source_bytes.as_slice());
            assert_eq!(name, Some("complex_function".to_string()));
            return;
        }
    }
    panic!("Function item not found");
}

#[test]
fn test_parsed_file_new_constructor() {
    let content = "test".to_string();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&content, None).unwrap();

    let parsed = ParsedFile::new(content.clone(), parser, tree);

    assert_eq!(parsed.content, content);
    assert_eq!(parsed.source_bytes, content.as_bytes());
}
