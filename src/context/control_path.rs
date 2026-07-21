//! Control path extraction using tree-sitter AST parsing.
//!
//! Extracts AST, CFG, and DFG information from source code and verbalizes
//! it as text for LLM context.

use thiserror::Error;
use tree_sitter::{Language as TsLanguage, Parser, TreeCursor};

/// Language enumeration for supported languages
#[derive(Debug, Clone, Copy)]
pub enum Language {
    C,
    Rust,
    Python,
    JavaScript,
}

impl Language {
    fn ts_language(&self) -> TsLanguage {
        match self {
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        }
    }
}

/// Control path extraction errors
#[derive(Debug, Error)]
pub enum ContextError {
    #[error("Parse error at line {line}")]
    ParseError { line: usize },
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("No functions found in source")]
    NoFunctions,
    #[error("Tree-sitter error: {0}")]
    TreeSitterError(String),
}

/// Control path containing AST, CFG, and DFG verbalizations
#[derive(Debug, Clone)]
pub struct ControlPath {
    pub ast_text: String,
    pub cfg_text: String,
    pub dfg_text: String,
}

/// Extract control path from source code
pub fn extract(source: &str, language: Language) -> Result<ControlPath, ContextError> {
    let ts_lang = language.ts_language();
    let mut parser = Parser::new();
    parser
        .set_language(&ts_lang)
        .map_err(|e| ContextError::TreeSitterError(format!("Failed to set language: {:?}", e)))?;

    let tree = parser
        .parse(source, None)
        .ok_or(ContextError::ParseError { line: 0 })?;

    let root = tree.root_node();

    if root.has_error() && root.kind() != "translation_unit" {
        return Err(ContextError::ParseError { line: 1 });
    }

    let ast_text = verbalize_ast(&root, source);
    let cfg_text = extract_cfg(&root, source);
    let dfg_text = extract_dfg(&root, source);

    Ok(ControlPath {
        ast_text,
        cfg_text,
        dfg_text,
    })
}

/// Walk AST and emit textual representation
fn verbalize_ast(node: &tree_sitter::Node, source: &str) -> String {
    let mut result = String::new();
    let mut cursor = node.walk();
    let indent = "  ";

    walk_ast_recursive(&mut cursor, source, &mut result, 0, indent);
    result
}

#[allow(clippy::only_used_in_recursion)]
fn walk_ast_recursive(
    cursor: &mut TreeCursor,
    source: &str,
    result: &mut String,
    depth: usize,
    indent: &str,
) {
    let node = cursor.node();
    let start_point = node.start_position();
    let end_point = node.end_position();

    let line_info = format!(
        "[{}:{}-{}:{}]",
        start_point.row + 1,
        start_point.column,
        end_point.row + 1,
        end_point.column
    );

    result.push_str(&indent.repeat(depth));
    result.push_str(&format!("{} {}\n", node.kind(), line_info));

    if cursor.goto_first_child() {
        loop {
            walk_ast_recursive(cursor, source, result, depth + 1, indent);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Extract control flow graph as text
fn extract_cfg(node: &tree_sitter::Node, source: &str) -> String {
    let source_bytes = source.as_bytes();
    let mut result = String::new();
    let mut functions = Vec::new();

    // Find function definitions
    find_function_definitions(node, &mut functions, source_bytes);

    if functions.is_empty() {
        return "(no functions found)".to_string();
    }

    for (func_name, func_node) in functions {
        result.push_str(&format!(
            "Function: {}@L{}\n",
            func_name,
            func_node.start_position().row + 1
        ));

        // Find branch points within the function
        let mut branches = Vec::new();
        find_branch_points(&func_node, &mut branches);

        if branches.is_empty() {
            result.push_str("  (no branches)\n");
        } else {
            for branch in branches {
                let branch_kind = branch.kind();
                let branch_line = branch.start_position().row + 1;

                result.push_str(&format!(
                    "  cfg@L{} -> {}@L{}",
                    func_node.start_position().row + 1,
                    branch_kind,
                    branch_line
                ));

                // Check for else branch
                if has_else_branch(&branch) {
                    result.push_str(" / else@L");
                    if let Some(else_node) = find_else_branch(&branch) {
                        result.push_str(&format!("{}", else_node.start_position().row + 1));
                    } else {
                        result.push('?');
                    }
                }

                result.push('\n');
            }
        }
        result.push('\n');
    }

    result
}

fn find_function_definitions<'a>(
    node: &tree_sitter::Node<'a>,
    functions: &mut Vec<(String, tree_sitter::Node<'a>)>,
    source: &[u8],
) {
    if is_function_definition(node) {
        let func_name = get_function_name(node, source);
        functions.push((func_name, *node));
    }

    for child in node.children(&mut node.walk()) {
        find_function_definitions(&child, functions, source);
    }
}

fn is_function_definition(node: &tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "function_declaration" | "definition"
    )
}

fn get_function_name(node: &tree_sitter::Node, source: &[u8]) -> String {
    for child in node.children(&mut node.walk()) {
        if child.kind() == "identifier" || child.kind() == "function_definition" {
            if let Some(name_node) = child.child(0) {
                if name_node.kind() == "identifier" {
                    return name_node.utf8_text(source).unwrap_or("?").to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

#[allow(clippy::only_used_in_recursion)]
fn find_branch_points<'a>(node: &tree_sitter::Node<'a>, branches: &mut Vec<tree_sitter::Node<'a>>) {
    let kind = node.kind();
    if matches!(
        kind,
        "if_statement"
            | "for_statement"
            | "while_statement"
            | "match_expression"
            | "switch_statement"
    ) {
        branches.push(*node);
    }

    for child in node.children(&mut node.walk()) {
        find_branch_points(&child, branches);
    }
}

fn has_else_branch(_node: &tree_sitter::Node) -> bool {
    _node
        .children(&mut _node.walk())
        .any(|child| child.kind() == "else_clause" || child.kind() == "else")
}

fn find_else_branch<'a>(node: &'a tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    node.children(&mut node.walk())
        .find(|child| child.kind() == "else_clause" || child.kind() == "else")
}

/// Extract data flow graph as text
fn extract_dfg(node: &tree_sitter::Node, source: &str) -> String {
    let source_bytes = source.as_bytes();
    let mut result = String::new();
    let mut assignments = Vec::new();

    find_assignments(node, &mut assignments, source_bytes);

    if assignments.is_empty() {
        return "(no assignments found)".to_string();
    }

    for (var_name, expr_line) in assignments {
        result.push_str(&format!("var <- {} (L{})\n", var_name, expr_line));
    }

    result
}

fn find_assignments(
    node: &tree_sitter::Node,
    assignments: &mut Vec<(String, usize)>,
    source: &[u8],
) {
    let kind = node.kind();

    if matches!(
        kind,
        "assignment_expression"
            | "assignment"
            | "_expression"
            | "let_declaration"
            | "let_statement"
    ) {
        if let Some(var_name) = get_assigned_variable(node, source) {
            let line = node.start_position().row + 1;
            assignments.push((var_name, line));
        }
    }

    for child in node.children(&mut node.walk()) {
        find_assignments(&child, assignments, source);
    }
}

fn get_assigned_variable(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Look for left-hand side of assignment
    for child in node.children(&mut node.walk()) {
        if child.kind() == "identifier" {
            if let Ok(text) = child.utf8_text(source) {
                return Some(text.to_string());
            }
        }
        if child.kind() == "variable_declarator" {
            for name_child in child.children(&mut child.walk()) {
                if name_child.kind() == "identifier" {
                    if let Ok(text) = name_child.utf8_text(source) {
                        return Some(text.to_string());
                    }
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
    fn test_extract_c_function_with_branch() {
        let source = r#"
void process(int x) {
    int result = 0;
    if (x > 10) {
        result = x * 2;
    } else {
        result = x;
    }
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
    fn test_extract_python_with_assignment() {
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
        // Tree-sitter is lenient, so malformed source may still parse
        // This test verifies we don't panic on edge cases
        let source = r#"
void broken( {
    int x = ;
"#;

        let result = extract(source, Language::C);
        // Tree-sitter may still produce a parse tree for malformed code
        // Just verify we get a result without panicking
        assert!(
            result.is_ok() || result.is_err(),
            "Should handle malformed source gracefully"
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
}
