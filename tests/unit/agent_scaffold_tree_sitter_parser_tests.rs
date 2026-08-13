use baco::agent_scaffold::tree_sitter_parser::parse_source;
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
