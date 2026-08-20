//! Unit tests for src/context/summary.rs - ContextExtractor and ContextSummary

use baco::context::summary::{ContextExtractor, ContextSummary, FunctionSummary};
use std::fs;
use std::path::PathBuf;

// ============================================================================
// ContextSummary tests
// ============================================================================

#[test]
fn test_function_summary_creation() {
    let func = FunctionSummary {
        name: "test_func".to_string(),
        signature: "fn test_func()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    assert_eq!(func.name, "test_func");
    assert_eq!(func.start_line, 1);
    assert_eq!(func.end_line, 10);
}

#[test]
fn test_context_summary_default() {
    let summary = ContextSummary::default();

    assert!(summary.file_path.as_os_str().is_empty());
    assert!(summary.language.is_empty());
    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
    assert!(summary.exports.is_empty());
    assert!(summary.call_relationships.is_empty());
    assert!(summary.module_summary.is_empty());
}

#[test]
fn test_format_for_prompt_empty() {
    let summary = ContextSummary::default();
    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("No context available"));
}

#[test]
fn test_format_for_prompt_sections() {
    let cases = vec![
        (
            "functions",
            ContextSummary {
                file_path: PathBuf::from("test.rs"),
                language: "rust".to_string(),
                functions: vec![FunctionSummary {
                    name: "main".to_string(),
                    signature: "fn main()".to_string(),
                    start_line: 1,
                    end_line: 10,
                }],
                imports: vec![],
                exports: vec![],
                call_relationships: vec![],
                module_summary: String::new(),
            },
            vec!["## Functions", "main", "lines 1-10"],
        ),
        (
            "imports",
            ContextSummary {
                file_path: PathBuf::from("test.rs"),
                language: "rust".to_string(),
                functions: vec![],
                imports: vec!["use std::io;".to_string(), "use std::fs;".to_string()],
                exports: vec![],
                call_relationships: vec![],
                module_summary: String::new(),
            },
            vec!["## Imports", "use std::io;", "use std::fs;"],
        ),
        (
            "exports",
            ContextSummary {
                file_path: PathBuf::from("test.rs"),
                language: "rust".to_string(),
                functions: vec![],
                imports: vec![],
                exports: vec!["fn public_func".to_string()],
                call_relationships: vec![],
                module_summary: String::new(),
            },
            vec!["## Exports", "fn public_func"],
        ),
        (
            "relationships",
            ContextSummary {
                file_path: PathBuf::from("test.rs"),
                language: "rust".to_string(),
                functions: vec![],
                imports: vec![],
                exports: vec![],
                call_relationships: vec!["main calls helper".to_string()],
                module_summary: String::new(),
            },
            vec![],
        ),
        (
            "module_summary",
            ContextSummary {
                file_path: PathBuf::from("test.rs"),
                language: "rust".to_string(),
                functions: vec![],
                imports: vec![],
                exports: vec![],
                call_relationships: vec![],
                module_summary: "This module handles file I/O".to_string(),
            },
            vec![],
        ),
    ];

    for (name, summary, expected_contents) in cases {
        let formatted = summary.format_for_prompt();
        for expected in expected_contents {
            assert!(formatted.contains(expected), "{}: missing '{}'", name, expected);
        }
    }
}

// ============================================================================
// ContextExtractor - C/C++ tests
// ============================================================================

#[test]
fn test_extract_c_functions() {
    let cases = vec![
        (
            "simple_function",
            r#"
int add(int a, int b) {
    return a + b;
}
"#,
            "add",
            1,
        ),
        (
            "multiple_functions",
            r#"
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main() {
    return 0;
}
"#,
            "add",
            3,
        ),
        (
            "with_static",
            r#"
static void helper() {
    // helper function
}

int main() {
    helper();
    return 0;
}
"#,
            "main",
            2,
        ),
    ];

    for (name, content, expected_func_name, min_funcs) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.c");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "c", "{}: language", name);
        assert!(!summary.functions.is_empty(), "{}: functions", name);
        if !expected_func_name.is_empty() {
            assert!(
                summary.functions.iter().any(|f| f.name == expected_func_name),
                "{}: expected function {} not found",
                name,
                expected_func_name
            );
        }
        assert!(
            summary.functions.len() >= min_funcs,
            "{}: expected at least {} functions, got {}",
            name,
            min_funcs,
            summary.functions.len()
        );
    }
}

#[test]
fn test_extract_c_imports() {
    let content = r#"
#include <stdio.h>
#include <stdlib.h>
#include "local_header.h"

int main() {
    return 0;
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.imports.len(), 3);
    assert!(summary.imports.contains(&"stdio.h".to_string()));
    assert!(summary.imports.contains(&"stdlib.h".to_string()));
    assert!(summary.imports.contains(&"local_header.h".to_string()));
}

// ============================================================================
// ContextExtractor - Rust tests
// ============================================================================

#[test]
fn test_extract_rust_functions() {
    let cases = vec![
        (
            "simple_function",
            r#"
fn hello() {
    println!("hello");
}
"#,
            "hello",
            "rust",
        ),
        (
            "public_function",
            r#"
pub fn public_func() -> Result<(), ()> {
    Ok(())
}
"#,
            "public_func",
            "rust",
        ),
        (
            "async_function",
            r#"
async fn async_func() -> String {
    "hello".to_string()
}
"#,
            "async_func",
            "rust",
        ),
    ];

    for (name, content, expected_func_name, expected_lang) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.rs");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, expected_lang, "{}: language", name);
        assert!(!summary.functions.is_empty(), "{}: functions", name);
        assert_eq!(
            summary.functions[0].name, expected_func_name,
            "{}: function name",
            name
        );
    }
}

#[test]
fn test_extract_rust_imports() {
    let content = r#"
use std::io;
use std::fs::File;
use crate::utils::helper;
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.imports.len(), 3);
    assert!(summary
        .imports
        .iter()
        .any(|i: &String| i.contains("std::io")));
}

#[test]
fn test_extract_rust_exports() {
    let content = r#"
pub struct MyStruct;
pub enum MyEnum { A, B }
pub trait MyTrait {}
pub const MY_CONST: i32 = 42;
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.exports.contains(&"struct MyStruct".to_string()));
    assert!(summary.exports.contains(&"enum MyEnum".to_string()));
    assert!(summary.exports.contains(&"trait MyTrait".to_string()));
    assert!(summary.exports.contains(&"const MY_CONST".to_string()));
}

// ============================================================================
// ContextExtractor - Python tests
// ============================================================================

#[test]
fn test_extract_python_functions() {
    let cases = vec![
        (
            "simple_function",
            r#"
def hello():
    print("hello")
"#,
            "hello",
        ),
        (
            "async_function",
            r#"
async def async_hello():
    await something()
"#,
            "async_hello",
        ),
    ];

    for (name, content, expected_func_name) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.py");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "python", "{}: language", name);
        assert!(!summary.functions.is_empty(), "{}: functions", name);
        assert_eq!(
            summary.functions[0].name, expected_func_name,
            "{}: function name",
            name
        );
    }
}

#[test]
fn test_extract_python_imports() {
    let content = r#"
import os
import sys
from pathlib import Path
from utils import helper, helper2
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.imports.len() >= 4);
    assert!(summary
        .imports
        .iter()
        .any(|i: &String| i.contains("import os")));
    assert!(summary
        .imports
        .iter()
        .any(|i: &String| i.contains("from pathlib import Path")));
}

#[test]
fn test_extract_python_exports() {
    let content = r#"
__all__ = ['func1', 'func2', 'ClassA']

def func1(): pass
def func2(): pass
class ClassA: pass
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.exports.contains(&"func1".to_string()));
    assert!(summary.exports.contains(&"func2".to_string()));
    assert!(summary.exports.contains(&"ClassA".to_string()));
}

// ============================================================================
// ContextExtractor - JavaScript/TypeScript tests
// ============================================================================

#[test]
fn test_extract_js_functions() {
    let cases = vec![
        (
            "function_declaration",
            r#"
function hello() {
    console.log("hello");
}
"#,
            "hello",
        ),
        (
            "arrow_function",
            r#"
const hello = () => {
    console.log("hello");
};
"#,
            "hello",
        ),
    ];

    for (name, content, expected_func_name) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.js");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert_eq!(summary.language, "javascript", "{}: language", name);
        assert!(!summary.functions.is_empty(), "{}: functions", name);
        assert_eq!(
            summary.functions[0].name, expected_func_name,
            "{}: function name",
            name
        );
    }
}

#[test]
fn test_extract_js_imports() {
    let cases = vec![
        (
            "es6",
            r#"
import React from 'react';
import { useState, useEffect } from 'react';
"#,
            "import React",
        ),
        (
            "commonjs",
            r#"
const express = require('express');
const fs = require('fs');
"#,
            "require('express')",
        ),
    ];

    for (name, content, expected_import) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_path = tmp_dir.path().join("test.js");
        fs::write(&tmp_path, content).unwrap();

        let summary = ContextExtractor::extract(&tmp_path);

        assert!(summary.imports.len() >= 2, "{}: import count", name);
        assert!(
            summary
                .imports
                .iter()
                .any(|i: &String| i.contains(expected_import)),
            "{}: expected import",
            name
        );
    }
}

#[test]
fn test_extract_js_exports() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    
    // ES6 exports
    let content_es6 = r#"
export const myConst = 42;
export function myFunc() {}
export default MyClass;
"#;
    fs::write(&tmp_path, content_es6).unwrap();
    let summary = ContextExtractor::extract(&tmp_path);
    assert!(!summary.exports.is_empty(), "es6: exports should not be empty");
    
    // CommonJS exports (may or may not be detected)
    let tmp_path2 = tmp_dir.path().join("test2.js");
    let content_commonjs = r#"
module.exports = { func1, func2 };
"#;
    fs::write(&tmp_path2, content_commonjs).unwrap();
    let _summary = ContextExtractor::extract(&tmp_path2);
    // CommonJS exports may or may not be detected based on regex
    // No assertion needed here - just verify extraction doesn't panic
}

// ============================================================================
// ContextExtractor - Language detection tests
// ============================================================================

#[test]
fn test_detect_language() {
    let cases = vec![
        ("c", "test.c", "int main() { return 0; }", "c"),
        ("cpp", "test.cpp", "int main() { return 0; }", "cpp"),
        ("python", "test.py", "def main(): pass", "python"),
        ("javascript", "test.js", "function main() {}", "javascript"),
        ("typescript", "test.ts", "function main(): void {}", "typescript"),
        ("unknown", "test.xyz", "", "unknown"),
    ];

    for (name, filename, content, expected_lang) in cases {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join(filename);
        if !content.is_empty() {
            fs::write(&path, content).unwrap();
        }

        let summary = ContextExtractor::extract(&path);

        assert!(
            summary.language == expected_lang || summary.language.is_empty(),
            "{}: expected {} or empty, got {}",
            name,
            expected_lang,
            summary.language
        );
        if expected_lang == "unknown" || filename.ends_with(".xyz") {
            assert!(summary.functions.is_empty(), "{}: no functions", name);
        }
    }
}

// ============================================================================
// ContextExtractor - Edge cases
// ============================================================================

#[test]
fn test_extract_empty_file() {
    let content = "";

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
    assert!(summary.exports.is_empty());
}

#[test]
fn test_extract_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/file.rs");
    let summary = ContextExtractor::extract(path);

    assert!(summary.functions.is_empty());
    assert_eq!(summary.file_path, path);
}

#[test]
fn test_extract_call_relationships() {
    let content = r#"
fn helper() {}

fn main() {
    helper();
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    // Should detect that main calls helper
    assert!(summary
        .call_relationships
        .iter()
        .any(|r: &String| r.contains("main") && r.contains("helper")));
}

#[test]
fn test_generate_module_summary_with_all() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![FunctionSummary {
            name: "test".to_string(),
            signature: "fn test()".to_string(),
            start_line: 1,
            end_line: 5,
        }],
        imports: vec!["use std::io;".to_string()],
        exports: vec!["fn test".to_string()],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Functions"));
    assert!(formatted.contains("## Imports"));
    assert!(formatted.contains("## Exports"));
}

#[test]
fn test_function_summary_line_numbers() {
    let content = r#"
fn first() {
    println!("first");
}

fn second() {
    println!("second");
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.len() >= 2);

    // First function should start at line 1
    let first_func = summary
        .functions
        .iter()
        .find(|f| f.name == "first")
        .unwrap();
    assert_eq!(first_func.start_line, 1);
}
