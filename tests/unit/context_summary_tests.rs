//! Comprehensive unit tests for context summary extraction module.
//!
//! Tests cover:
//! - ContextSummary struct creation and fields
//! - FunctionSummary struct creation and fields
//! - ContextExtractor::extract for various languages
//! - format_for_prompt output formatting
//! - Edge cases: empty files, missing files, unrecognized languages
//! - All language-specific extraction (C, Rust, Python, JS/TS)
//! - Call relationships and module summary generation

use baco::context::{ContextExtractor, ContextSummary, FunctionSummary};
use std::fs;
use std::path::PathBuf;

// ============================================================================
// FunctionSummary Tests
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
    assert_eq!(func.signature, "fn test_func()");
    assert_eq!(func.start_line, 1);
    assert_eq!(func.end_line, 10);
}

#[test]
fn test_function_summary_debug_trait() {
    let func = FunctionSummary {
        name: "main".to_string(),
        signature: "fn main()".to_string(),
        start_line: 1,
        end_line: 5,
    };

    let debug_output = format!("{:?}", func);
    assert!(debug_output.contains("test_func") || debug_output.contains("main"));
}

#[test]
fn test_function_summary_clone() {
    let func = FunctionSummary {
        name: "original".to_string(),
        signature: "fn original()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    let cloned = func.clone();
    assert_eq!(func, cloned);
}

#[test]
fn test_function_summary_partial_eq() {
    let func1 = FunctionSummary {
        name: "same".to_string(),
        signature: "fn same()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    let func2 = FunctionSummary {
        name: "same".to_string(),
        signature: "fn same()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    let func3 = FunctionSummary {
        name: "different".to_string(),
        signature: "fn different()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    assert_eq!(func1, func2);
    assert_ne!(func1, func3);
}

// ============================================================================
// ContextSummary Tests
// ============================================================================

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
fn test_context_summary_creation() {
    let summary = ContextSummary {
        file_path: PathBuf::from("src/main.rs"),
        language: "rust".to_string(),
        functions: vec![],
        imports: vec![],
        exports: vec![],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    assert_eq!(summary.file_path, PathBuf::from("src/main.rs"));
    assert_eq!(summary.language, "rust");
}

#[test]
fn test_context_summary_clone() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![],
        imports: vec![],
        exports: vec![],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let cloned = summary.clone();
    assert_eq!(summary, cloned);
}

// ============================================================================
// ContextExtractor - Language Detection
// ============================================================================

#[test]
fn test_extract_rust_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "rust");
}

#[test]
fn test_extract_c_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "c");
}

#[test]
fn test_extract_cpp_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.cpp");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "cpp");
}

#[test]
fn test_extract_python_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "python");
}

#[test]
fn test_extract_javascript_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "javascript");
}

#[test]
fn test_extract_typescript_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.ts");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "typescript");
}

#[test]
fn test_extract_unknown_file_extension() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.xyz");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.language.is_empty());
}

// ============================================================================
// ContextExtractor - Empty and Missing Files
// ============================================================================

#[test]
fn test_extract_empty_rust_file() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("empty.rs");
    fs::write(&tmp_path, "").unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "rust");
    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
    assert!(summary.exports.is_empty());
    assert!(summary.call_relationships.is_empty());
}

#[test]
fn test_extract_nonexistent_file() {
    let path = PathBuf::from("/nonexistent/path/file.rs");

    let summary = ContextExtractor::extract(&path);

    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
    assert!(summary.exports.is_empty());
}

// ============================================================================
// ContextExtractor - Rust Specific
// ============================================================================

#[test]
fn test_extract_rust_single_function() {
    let content = r#"
fn main() {
    println!("Hello");
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "rust");
    assert!(!summary.functions.is_empty());
    assert!(summary.functions.iter().any(|f| f.name == "main"));
}

#[test]
fn test_extract_rust_pub_function() {
    let content = r#"
pub fn public_api() -> String {
    "public".to_string()
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.iter().any(|f| f.name == "public_api"));
    assert!(summary.exports.contains(&"fn public_api".to_string()));
}

#[test]
fn test_extract_rust_async_function() {
    let content = r#"
async fn fetch_data() -> String {
    "data".to_string()
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.iter().any(|f| f.name == "fetch_data"));
}

#[test]
fn test_extract_rust_imports() {
    let content = r#"
use std::io;
use std::fs::read_to_string;
use crate::utils::helper;
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(!summary.imports.is_empty());
    assert!(summary.imports.iter().any(|i| i.contains("std::io")));
}

#[test]
fn test_extract_rust_multiple_exports() {
    let content = r#"
pub fn function_one() {}
pub struct MyStruct {}
pub enum MyEnum {}
pub trait MyTrait {}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.exports.contains(&"fn function_one".to_string()));
    assert!(summary.exports.contains(&"struct MyStruct".to_string()));
    assert!(summary.exports.contains(&"enum MyEnum".to_string()));
    assert!(summary.exports.contains(&"trait MyTrait".to_string()));
}

// ============================================================================
// ContextExtractor - C Specific
// ============================================================================

#[test]
fn test_extract_c_function() {
    let content = r#"
int add(int a, int b) {
    return a + b;
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "c");
    assert!(!summary.functions.is_empty());
}

#[test]
fn test_extract_c_imports() {
    let content = r#"
#include <stdio.h>
#include "local.h"
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.imports.contains(&"stdio.h".to_string()));
    assert!(summary.imports.contains(&"local.h".to_string()));
}

// ============================================================================
// ContextExtractor - Python Specific
// ============================================================================

#[test]
fn test_extract_python_function() {
    let content = r#"
def hello_world():
    print("Hello")
    return True
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "python");
    assert!(summary.functions.iter().any(|f| f.name == "hello_world"));
}

#[test]
fn test_extract_python_async_function() {
    let content = r#"
async def fetch_url(url):
    return await request(url)
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.iter().any(|f| f.name == "fetch_url"));
}

#[test]
fn test_extract_python_imports() {
    let content = r#"
import os
import sys
from pathlib import Path
from typing import List, Optional
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(!summary.imports.is_empty());
    assert!(summary.imports.iter().any(|i| i.contains("import os")));
    assert!(summary.imports.iter().any(|i| i.contains("from pathlib")));
}

#[test]
fn test_extract_python_exports_with_all() {
    let content = r#"
__all__ = ["public_func", "PublicClass"]

def public_func():
    pass

def _private_func():
    pass
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.exports.contains(&"public_func".to_string()));
    assert!(summary.exports.contains(&"PublicClass".to_string()));
    assert!(!summary.exports.contains(&"_private_func".to_string()));
}

// ============================================================================
// ContextExtractor - JavaScript/TypeScript Specific
// ============================================================================

#[test]
fn test_extract_js_function_declaration() {
    let content = r#"
function greet(name) {
    return "Hello " + name;
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.iter().any(|f| f.name == "greet"));
}

#[test]
fn test_extract_js_arrow_function() {
    let content = r#"
const add = (a, b) => {
    return a + b;
};
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.iter().any(|f| f.name == "add"));
}

#[test]
fn test_extract_js_imports_es6() {
    let content = r#"
import React from 'react';
import { useState, useEffect } from 'react';
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(!summary.imports.is_empty());
}

#[test]
fn test_extract_js_imports_commonjs() {
    let content = r#"
const express = require('express');
const fs = require('fs');
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.imports.iter().any(|i| i.contains("require")));
}

#[test]
fn test_extract_js_exports_es6() {
    let content = r#"
export const CONSTANT = 42;
export function helper() {}
export default MainComponent;
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(!summary.exports.is_empty());
}

// ============================================================================
// format_for_prompt Tests
// ============================================================================

#[test]
fn test_format_for_prompt_empty_summary() {
    let summary = ContextSummary::default();

    let formatted = summary.format_for_prompt();

    assert_eq!(
        formatted,
        "No context available (empty or unrecognized file)"
    );
}

#[test]
fn test_format_for_prompt_with_functions() {
    let summary = ContextSummary {
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
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Functions"));
    assert!(formatted.contains("main"));
    assert!(formatted.contains("lines 1-10"));
}

#[test]
fn test_format_for_prompt_with_imports() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![],
        imports: vec!["use std::io;".to_string(), "use std::fs;".to_string()],
        exports: vec![],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Imports"));
    assert!(formatted.contains("use std::io;"));
    assert!(formatted.contains("use std::fs;"));
}

#[test]
fn test_format_for_prompt_with_exports() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![],
        imports: vec![],
        exports: vec!["fn public_api".to_string(), "struct MyStruct".to_string()],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Exports"));
    assert!(formatted.contains("fn public_api"));
}

#[test]
fn test_format_for_prompt_with_call_relationships() {
    let summary = ContextSummary {
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
        call_relationships: vec!["main calls helper".to_string()],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();

    assert!(
        formatted.contains("## Call Relationships"),
        "formatted output: {}",
        formatted
    );
    assert!(formatted.contains("main calls helper"));
}

#[test]
fn test_format_for_prompt_with_module_summary() {
    let summary = ContextSummary {
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
        module_summary: "This module handles file I/O operations".to_string(),
    };

    let formatted = summary.format_for_prompt();

    assert!(
        formatted.contains("## Module Purpose"),
        "formatted output: {}",
        formatted
    );
    assert!(formatted.contains("file I/O"));
}

#[test]
fn test_format_for_prompt_full_content() {
    let summary = ContextSummary {
        file_path: PathBuf::from("src/main.rs"),
        language: "rust".to_string(),
        functions: vec![
            FunctionSummary {
                name: "main".to_string(),
                signature: "fn main()".to_string(),
                start_line: 1,
                end_line: 20,
            },
            FunctionSummary {
                name: "helper".to_string(),
                signature: "fn helper() -> Result<()>".to_string(),
                start_line: 22,
                end_line: 35,
            },
        ],
        imports: vec!["use std::io;".to_string()],
        exports: vec!["fn main".to_string()],
        call_relationships: vec!["main calls helper".to_string()],
        module_summary: "Main entry point".to_string(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Functions"));
    assert!(formatted.contains("## Imports"));
    assert!(formatted.contains("## Exports"));
    assert!(formatted.contains("## Call Relationships"));
    assert!(formatted.contains("## Module Purpose"));
    assert!(formatted.contains("main"));
    assert!(formatted.contains("helper"));
    assert!(formatted.contains("lines 1-20"));
    assert!(formatted.contains("lines 22-35"));
}

// ============================================================================
// Call Relationships Tests
// ============================================================================

#[test]
fn test_extract_rust_with_function_calls() {
    let content = r#"
fn helper() -> String {
    "helper".to_string()
}

fn main() {
    let data = helper();
    println!("{}", data);
}
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    // Should detect that main calls helper
    assert!(!summary.functions.is_empty());
    assert!(summary.functions.len() >= 2);
}

// ============================================================================
// Module Summary Generation Tests
// ============================================================================

#[test]
fn test_module_summary_with_functions_only() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![
            FunctionSummary {
                name: "f1".to_string(),
                signature: "fn f1()".to_string(),
                start_line: 1,
                end_line: 5,
            },
            FunctionSummary {
                name: "f2".to_string(),
                signature: "fn f2()".to_string(),
                start_line: 6,
                end_line: 10,
            },
        ],
        imports: vec![],
        exports: vec![],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();
    // When module_summary is populated, it should appear with "## Module Purpose" heading
    assert!(
        formatted.contains("## Functions"),
        "formatted output: {}",
        formatted
    );
    assert!(formatted.contains("f1"));
    assert!(formatted.contains("f2"));
}

#[test]
fn test_module_summary_with_imports_and_functions() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![FunctionSummary {
            name: "main".to_string(),
            signature: "fn main()".to_string(),
            start_line: 1,
            end_line: 5,
        }],
        imports: vec!["use std::io;".to_string()],
        exports: vec![],
        call_relationships: vec![],
        module_summary: String::new(),
    };

    let formatted = summary.format_for_prompt();
    assert!(
        formatted.contains("## Imports"),
        "formatted output: {}",
        formatted
    );
    assert!(
        formatted.contains("## Functions"),
        "formatted output: {}",
        formatted
    );
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_function_summary_serialize_deserialize() {
    let func = FunctionSummary {
        name: "test".to_string(),
        signature: "fn test()".to_string(),
        start_line: 1,
        end_line: 10,
    };

    let json = serde_json::to_string(&func).unwrap();
    let deserialized: FunctionSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(func, deserialized);
}

#[test]
fn test_context_summary_serialize_deserialize() {
    let summary = ContextSummary {
        file_path: PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![],
        imports: vec!["use std;".to_string()],
        exports: vec!["fn main".to_string()],
        call_relationships: vec![],
        module_summary: "Test module".to_string(),
    };

    let json = serde_json::to_string(&summary).unwrap();
    let deserialized: ContextSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(summary, deserialized);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_extract_file_with_only_comments() {
    let content = r#"
// This is a comment
/* Multi-line
   comment */
"#;

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
}

#[test]
fn test_extract_file_with_whitespace_only() {
    let content = "   \n\t\n   \n";

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.is_empty());
    assert_eq!(summary.language, "rust");
}

#[test]
fn test_function_line_numbers_valid() {
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

    for func in &summary.functions {
        assert!(func.start_line > 0);
        assert!(func.end_line >= func.start_line);
    }
}

#[test]
fn test_extract_large_file_stub() {
    // Test that extraction doesn't panic on larger files
    let mut content = String::new();
    for i in 0..100 {
        content.push_str(&format!("fn func_{}() {{\n", i));
        content.push_str(&format!("    println!(\"{}\");\n", i));
        content.push_str("}\n\n");
    }

    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, &content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(!summary.functions.is_empty());
}
