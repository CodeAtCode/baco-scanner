//! Unit tests for hunt prompt functionality in baco::prompt module
//!
//! Covers:
//! - PromptEngine hunt prompt access
//! - available_hunt_domains()
//! - select_hunt_domains() language mapping
//! - get_hunt_prompt() for non-existent domains

use baco::prompt::PromptEngine;

// ============================================================================
// PromptEngine Hunt Prompt Tests
// ============================================================================

#[test]
fn test_engine_has_hunt_domains_after_loading() {
    let engine = PromptEngine::new();
    let domains = engine.available_hunt_domains();

    // Assert contains "injection" - do NOT assert exact set as memory_safety.md
    // may be added by a parallel lane
    assert!(domains.contains(&"injection".to_string()));
}

#[test]
fn test_select_hunt_domains_c() {
    let domains = PromptEngine::select_hunt_domains(&["c".to_string()]);

    // C should map to injection, crypto, resource, memory_safety
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    assert!(domains.contains(&"memory_safety".to_string()));
}

#[test]
fn test_select_hunt_domains_javascript() {
    let domains = PromptEngine::select_hunt_domains(&["javascript".to_string()]);

    // JavaScript should map to xss, injection, auth, path_traversal
    assert!(domains.contains(&"xss".to_string()));
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    assert!(domains.contains(&"path_traversal".to_string()));
}

#[test]
fn test_select_hunt_domains_cobol_default() {
    let domains = PromptEngine::select_hunt_domains(&["cobol".to_string()]);

    // Unknown language should return default pair: injection, auth
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    // Should only have exactly these two for default
    assert_eq!(domains.len(), 2);
}

#[test]
fn test_get_hunt_prompt_nonexistent() {
    let engine = PromptEngine::new();

    let result = engine.get_hunt_prompt("nonexistent");
    assert!(result.is_none());
}

#[test]
fn test_select_hunt_domains_deduplication() {
    // Multiple languages mapping to same domain should deduplicate
    let domains = PromptEngine::select_hunt_domains(&["c".to_string(), "rust".to_string()]);

    // Both C and Rust map to injection and crypto
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    // C adds resource, memory_safety; Rust adds memory_safety (already there)
    // So we should have: injection, crypto, resource, memory_safety
    assert_eq!(domains.len(), 4);
}

#[test]
fn test_select_hunt_domains_case_insensitive() {
    // Should handle uppercase language names
    let domains_upper = PromptEngine::select_hunt_domains(&["JAVASCRIPT".to_string()]);
    let domains_lower = PromptEngine::select_hunt_domains(&["javascript".to_string()]);

    assert_eq!(domains_upper, domains_lower);
    assert!(domains_upper.contains(&"xss".to_string()));
}

#[test]
fn test_select_hunt_domains_empty_input() {
    let domains = PromptEngine::select_hunt_domains(&[]);

    // Empty input should return default pair
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    assert_eq!(domains.len(), 2);
}

#[test]
fn test_select_hunt_domains_sorted_output() {
    let domains = PromptEngine::select_hunt_domains(&["python".to_string()]);

    // Output should be sorted for determinism
    let sorted = {
        let mut d = domains.clone();
        d.sort();
        d
    };
    assert_eq!(domains, sorted);
}

#[test]
fn test_select_hunt_domains_cpp() {
    let domains = PromptEngine::select_hunt_domains(&["cpp".to_string()]);

    // C++ should map to same as C
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    assert!(domains.contains(&"resource".to_string()));
    assert!(domains.contains(&"memory_safety".to_string()));
}

#[test]
fn test_select_hunt_domains_typescript() {
    let domains = PromptEngine::select_hunt_domains(&["typescript".to_string()]);

    // TypeScript should map to same as JavaScript
    assert!(domains.contains(&"xss".to_string()));
    assert!(domains.contains(&"injection".to_string()));
}

#[test]
fn test_select_hunt_domains_java() {
    let domains = PromptEngine::select_hunt_domains(&["java".to_string()]);

    // Java should map to injection, auth, crypto, deserialization
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    assert!(domains.contains(&"deserialization".to_string()));
}

#[test]
fn test_select_hunt_domains_csharp() {
    let domains = PromptEngine::select_hunt_domains(&["csharp".to_string()]);

    // C# should map to same as Java
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    assert!(domains.contains(&"deserialization".to_string()));
}

#[test]
fn test_select_hunt_domains_go() {
    let domains = PromptEngine::select_hunt_domains(&["go".to_string()]);

    // Go should map to injection, crypto, resource
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"crypto".to_string()));
    assert!(domains.contains(&"resource".to_string()));
}

#[test]
fn test_select_hunt_domains_php() {
    let domains = PromptEngine::select_hunt_domains(&["php".to_string()]);

    // PHP should map to xss, injection, path_traversal, deserialization
    assert!(domains.contains(&"xss".to_string()));
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"path_traversal".to_string()));
    assert!(domains.contains(&"deserialization".to_string()));
}

#[test]
fn test_select_hunt_domains_python() {
    let domains = PromptEngine::select_hunt_domains(&["python".to_string()]);

    // Python should map to injection, auth, path_traversal
    assert!(domains.contains(&"injection".to_string()));
    assert!(domains.contains(&"auth".to_string()));
    assert!(domains.contains(&"path_traversal".to_string()));
}

#[test]
fn test_engine_get_hunt_prompt_injection() {
    let engine = PromptEngine::new();

    let result = engine.get_hunt_prompt("injection");
    assert!(result.is_some());
    let prompt = result.unwrap();
    assert!(!prompt.is_empty());
}
