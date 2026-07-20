//! Unit tests for ContextExtractor

use baco::context::{ContextExtractor, ContextSummary};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_extract_c_file_three_functions() {
    let content = r#"
#include <stdio.h>
#include <stdlib.h>

int add(int a, int b) {
    return a + b;
}

void print_result(int val) {
    printf("Result: %d\n", val);
}

int main() {
    int result = add(1, 2);
    print_result(result);
    return 0;
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "c");
    assert!(
        summary.functions.len() >= 3,
        "Expected at least 3 functions, got {}",
        summary.functions.len()
    );

    let func_names: Vec<&str> = summary.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(func_names.contains(&"add"));
    assert!(func_names.contains(&"print_result"));
    assert!(func_names.contains(&"main"));
}

#[test]
fn test_extract_rust_imports() {
    let content = r#"
use std::io;
use std::fs::read_to_string;
use crate::utils::helper;

pub fn main() {
    println!("Hello");
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "rust");
    assert!(!summary.imports.is_empty(), "Expected non-empty imports");
    assert!(summary.imports.iter().any(|i| i.contains("std::io")));
}

#[test]
fn test_extract_python_functions() {
    let content = r#"
import os
import sys

def read_file(path):
    with open(path) as f:
        return f.read()

def process_data(data):
    return data.upper()

async def fetch_url(url):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return await resp.text()
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.py");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "python");
    assert!(
        summary.functions.len() >= 3,
        "Expected at least 3 functions, got {}",
        summary.functions.len()
    );

    let func_names: Vec<&str> = summary.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(func_names.contains(&"read_file"));
    assert!(func_names.contains(&"process_data"));
    assert!(func_names.contains(&"fetch_url"));
}

#[test]
fn test_call_relationships() {
    let content = r#"
#include <stdio.h>

void helper() {
    printf("helper\n");
}

void caller() {
    helper();
    printf("done\n");
}

int main() {
    caller();
    return 0;
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.c");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(
        !summary.call_relationships.is_empty(),
        "Expected call relationships"
    );

    let has_helper_call = summary
        .call_relationships
        .iter()
        .any(|rel| rel.contains("caller") && rel.contains("helper"));
    assert!(
        has_helper_call,
        "Expected 'caller calls helper' relationship"
    );
}

#[test]
fn test_empty_file() {
    let content = "";

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.rs");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
    assert!(summary.exports.is_empty());
    assert!(summary.call_relationships.is_empty());
}

#[test]
fn test_unrecognized_language() {
    let content = "some random content";

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.xyz");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert!(summary.language.is_empty() || summary.language == "unknown");
    assert!(summary.functions.is_empty());
    assert!(summary.imports.is_empty());
}

#[test]
fn test_missing_file_no_panic() {
    // Should not panic, return empty summary
    let path = std::path::Path::new("/nonexistent/file.rs");
    let summary = ContextExtractor::extract(path);

    assert!(summary.functions.is_empty());
    assert_eq!(summary.file_path, path);
}

#[test]
fn test_format_for_prompt_includes_functions() {
    let summary = ContextSummary {
        file_path: std::path::PathBuf::from("test.rs"),
        language: "rust".to_string(),
        functions: vec![
            baco::context::FunctionSummary {
                name: "main".to_string(),
                signature: "fn main()".to_string(),
                start_line: 1,
                end_line: 10,
            },
            baco::context::FunctionSummary {
                name: "helper".to_string(),
                signature: "fn helper()".to_string(),
                start_line: 12,
                end_line: 15,
            },
        ],
        imports: vec!["use std::io;".to_string()],
        exports: vec!["fn main".to_string()],
        call_relationships: vec!["main calls helper".to_string()],
        module_summary: "Defines 2 functions, Imports 1 modules".to_string(),
    };

    let formatted = summary.format_for_prompt();

    assert!(formatted.contains("## Functions"));
    assert!(formatted.contains("main"));
    assert!(formatted.contains("helper"));
    assert!(formatted.contains("## Imports"));
    assert!(formatted.contains("## Call Relationships"));
    assert!(formatted.contains("main calls helper"));
}

#[test]
fn test_js_function_extraction() {
    let content = r#"
const fs = require('fs');

function readFile(path) {
    return fs.readFileSync(path, 'utf8');
}

const processData = (data) => {
    return data.toUpperCase();
};

async function fetchUrl(url) {
    const response = await fetch(url);
    return await response.text();
}

module.exports = { readFile, processData };
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("test.js");
    fs::write(&tmp_path, content).unwrap();

    let summary = ContextExtractor::extract(&tmp_path);

    assert_eq!(summary.language, "javascript");
    assert!(
        summary.functions.len() >= 3,
        "Expected at least 3 functions, got {}",
        summary.functions.len()
    );

    let func_names: Vec<&str> = summary.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(func_names.contains(&"readFile"));
    assert!(func_names.contains(&"processData"));
    assert!(func_names.contains(&"fetchUrl"));
}
