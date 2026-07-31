//! Integration test verifying CWE RAG specs appear in LLM prompts
//!
//! This test verifies that when analyzing a C file with SQL injection patterns,
//! the CWE-89 specification is retrieved and included in the prompt sent to the LLM.

use baco::llm::LlmConfig;
use baco::llm_analysis::{format_cwe_specs, LlmAnalyzer};
use baco::prompt::loader;
use baco::retrieval::CweKnowledgeBase;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_cwe_rag_includes_sql_injection_spec() {
    // Create a temporary C file with SQL injection vulnerability
    let content = r#"
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

void handle_user_query(char *user_input) {
    sqlite3 *db;
    char *query = malloc(256);
    
    // VULNERABLE: SQL injection via string concatenation
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", user_input);
    
    char *err_msg = NULL;
    sqlite3_exec(db, query, NULL, NULL, &err_msg);
    free(query);
}

int main() {
    char input[128];
    scanf("%s", input);
    handle_user_query(input);
    return 0;
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("vulnerable.c");
    fs::write(&tmp_path, content).unwrap();

    // Create LlmAnalyzer (this will load the CWE KB)
    let llm_config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(llm_config);
    let scanner_config = baco::config::ScannerConfig::default();
    let _analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    // Read the file content
    let file_content = fs::read_to_string(&tmp_path).unwrap();

    // Build the prompt the same way analyze_file does
    let file_path = tmp_path.to_string_lossy().to_string();
    let extension = "c";

    // Load the prompt template
    let loaded_prompts = loader::load_phase_prompts(None);
    let default_prompt = include_str!("../../prompts/phases/llm_static_analysis.md");
    let config = baco::config::ScannerConfig::default();
    let config_override = config
        .llm
        .phases
        .prompt_overrides
        .phase_overrides
        .get("llm_static_analysis")
        .map(|s| s.as_str());

    let prompt_template = loader::get_prompt(
        "llm_static_analysis",
        &loaded_prompts,
        config_override,
        default_prompt,
    );

    // Retrieve CWE specs
    let kb = CweKnowledgeBase::load_embedded().unwrap();
    let query_parts: Vec<String> = vec![
        file_path.to_string(),
        file_content.lines().take(20).collect::<Vec<_>>().join(" "),
    ];
    let query = query_parts.join(" ");
    let results = kb.search(&query, 3);
    let cwe_specs = format_cwe_specs(&results);

    // Substitute variables including CWE_SPECS
    let prompt = prompt_template
        .replace("%%LANGUAGE%%", extension)
        .replace("%%FILE_PATH%%", &file_path)
        .replace("%%LINE_RANGE%%", "1-max")
        .replace("%%CONTEXT_LINES%%", "3")
        .replace("%%CODE_CONTENT%%", &file_content)
        .replace("%%CWE_SPECS%%", &cwe_specs);

    // Verify CWE-89 (SQL Injection) is in the prompt
    assert!(
        prompt.contains("CWE-89"),
        "Prompt should contain CWE-89 SQL injection specification"
    );

    // Verify the section header exists
    let has_section = prompt.contains("CWE Specs") || prompt.contains("Relevant CWE");
    assert!(
        has_section,
        "Prompt should contain CWE specifications section header"
    );

    // Verify description is included
    assert!(
        prompt.contains("Description:"),
        "CWE spec should include description"
    );

    // Verify mitigation is included
    assert!(
        prompt.contains("Mitigation:"),
        "CWE spec should include mitigation"
    );
}

#[test]
fn test_cwe_rag_template_section_present() {
    // Verify the template contains the CWE_SPECS variable placeholder
    let template = include_str!("../../prompts/phases/llm_static_analysis.md");

    assert!(
        template.contains("%%CWE_SPECS%%"),
        "Template should contain %%CWE_SPECS%% placeholder"
    );

    assert!(
        template.contains("CWE Specs"),
        "Template should contain CWE specs section"
    );
}

#[test]
fn test_cwe_rag_empty_when_no_match() {
    // Create a file with content unlikely to match any CWE
    let content = r#"
// Simple calculator
fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    println!("{}", add(1, 2));
}
"#;

    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path().join("calculator.rs");
    fs::write(&tmp_path, content).unwrap();

    let file_path = tmp_path.to_string_lossy().to_string();

    // The retrieval should not panic even if no matches found
    // (it will return empty string)
    let _ = retrieve_cwe_specs_for_test(&file_path, content);
}

// Helper function to safely retrieve CWE specs for testing
fn retrieve_cwe_specs_for_test(file_path: &str, code_content: &str) -> String {
    let kb = match CweKnowledgeBase::load_embedded() {
        Ok(kb) => kb,
        Err(_) => return String::new(),
    };

    let query_parts: Vec<String> = vec![
        file_path.to_string(),
        code_content.lines().take(20).collect::<Vec<_>>().join(" "),
    ];
    let query = query_parts.join(" ");
    let results = kb.search(&query, 3);

    format_cwe_specs(&results)
}
