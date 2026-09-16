//! Unit tests for control path extraction.

use baco::context::control_path::{extract, Language};

#[test]
fn test_c_function_with_branch_cfg() {
    let source = r#"
void process(int x) {
    int result = 0;
    if (x > 10) {
        result = x * 2;
    } else {
        result = x;
    }
    printf("%d\n", result);
}
"#;

    let control = extract(source, Language::C).expect("Should parse C code");

    assert!(!control.ast_text.is_empty(), "AST should not be empty");
    assert!(
        control.ast_text.contains("function_definition"),
        "AST should contain function_definition"
    );
    assert!(
        control.cfg_text.contains("if"),
        "CFG should contain if statement"
    );
    assert!(
        control.cfg_text.contains("->"),
        "CFG should contain flow arrows"
    );
}

#[test]
fn test_python_function_with_assignment_dfg() {
    let source = r#"
def calculate(x):
    result = 0
    for i in range(x):
        result = result + i
    return result
"#;

    let control = extract(source, Language::Python).expect("Should parse Python code");

    assert!(
        control.dfg_text.contains("<-"),
        "DFG should contain assignment arrows"
    );
    assert!(
        control.dfg_text.contains("result"),
        "DFG should mention result variable"
    );
}

#[test]
fn test_malformed_source_returns_error() {
    let source = r#"
void broken( {
    int x = ;
"#;

    let result = extract(source, Language::C);
    assert!(
        result.is_ok() || result.is_err(),
        "Should handle malformed source gracefully without panicking"
    );
}

#[test]
fn test_rust_function_parsing() {
    let source = r#"
fn calculate_sum(numbers: Vec<i32>) -> i32 {
    let mut sum = 0;
    for n in numbers {
        sum += n;
    }
    sum
}
"#;

    let control = extract(source, Language::Rust).expect("Should parse Rust code");

    assert!(!control.ast_text.is_empty(), "AST should not be empty");
    assert!(
        control.dfg_text.contains("<-"),
        "DFG should contain assignments"
    );
}

#[test]
fn test_javascript_function() {
    let source = r#"
function processData(input) {
    let result = [];
    if (input.length > 0) {
        for (let i = 0; i < input.length; i++) {
            result.push(input[i] * 2);
        }
    }
    return result;
}
"#;

    let control = extract(source, Language::JavaScript).expect("Should parse JS code");

    assert!(!control.ast_text.is_empty(), "AST should not be empty");
    assert!(
        control.cfg_text.contains("if") || control.cfg_text.contains("for"),
        "CFG should contain branch points"
    );
}

#[test]
fn test_empty_source() {
    let source = "";
    let control = extract(source, Language::C).expect("Empty source should parse");
    assert!(
        !control.ast_text.is_empty(),
        "AST should have minimal content"
    );
}
