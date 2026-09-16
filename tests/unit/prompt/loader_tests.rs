//! Migrated inline tests for baco::prompt::loader
//!
//! Previously in src/prompt/loader.rs #[cfg(test)] mod tests

use baco::prompt::{get_prompt, load_phase_prompts};
use std::collections::HashMap;

#[test]
fn test_load_phase_prompts() {
    let prompts = load_phase_prompts(None);
    assert!(prompts.contains_key("llm_static_analysis"));
    assert!(prompts.contains_key("llm_discovery"));
    assert!(prompts.contains_key("llm_verification"));
}

#[test]
fn test_get_prompt_fallback() {
    let mut loaded = HashMap::new();
    loaded.insert("test".to_string(), "from file".to_string());

    // Priority: config > file > default
    assert_eq!(
        get_prompt("test", &loaded, Some("from config"), "default"),
        "from config"
    );
    assert_eq!(get_prompt("test", &loaded, None, "default"), "from file");

    let empty = HashMap::new();
    assert_eq!(
        get_prompt("nonexistent", &empty, None, "default"),
        "default"
    );
}
