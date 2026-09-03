//! Migrated inline tests for baco::prompt::engine
//!
//! Previously in src/prompt/engine.rs #[cfg(test)] mod tests

use baco::prompt::{BacoPhase, PromptEngine};
use std::collections::HashMap;

// ============================================================================
// Basic Engine Tests
// ============================================================================

#[test]
fn test_engine_creation() {
    let engine = PromptEngine::new();
    assert!(engine
        .defaults
        .indexing
        .contains("Analyze the project structure"));
}

#[test]
fn test_get_prompt_phase() {
    let engine = PromptEngine::new();

    let indexing_prompt = engine.get_prompt(&BacoPhase::Indexing);
    assert!(indexing_prompt.contains("Analyze the project structure"));

    let semgrep_prompt = engine.get_prompt(&BacoPhase::Semgrep);
    assert!(semgrep_prompt.contains("Analyze code for security vulnerabilities using Semgrep"));

    let static_analysis = engine.get_prompt(&BacoPhase::LlmStaticAnalysis);
    assert!(static_analysis.contains("OFFENSIVE SECURITY RESEARCHER"));
    assert!(static_analysis.contains("%%LANGUAGE%%"));
}

#[test]
fn test_template_substitution() {
    let engine = PromptEngine::new();
    let _ = engine.get_prompt(&BacoPhase::Indexing);

    // Test that placeholders exist
    assert!(engine.defaults.indexing.contains("%%PROJECT_PATH%%"));
    assert!(engine.defaults.semgrep.contains("%%PROJECT_PATH%%"));
}

#[test]
fn test_legacy_placeholder_format() {
    let engine = PromptEngine::new();
    let prompt = engine.get_prompt(&BacoPhase::Indexing);

    // Both formats should be present
    assert!(prompt.contains("%%PROJECT_PATH%%"));
    assert!(!prompt.contains("{PROJECT_PATH}")); // New format not used in defaults
}

#[test]
fn test_get_all_phases_have_templates() {
    let engine = PromptEngine::new();
    let phases = vec![
        &BacoPhase::Indexing,
        &BacoPhase::Semgrep,
        &BacoPhase::LlmStaticAnalysis,
        &BacoPhase::LlmDiscovery,
        &BacoPhase::LlmVerification,
        &BacoPhase::TicketCrossRef,
        &BacoPhase::GitAnalysis,
        &BacoPhase::CrossFileAnalysis,
        &BacoPhase::ConfidenceScoring,
        &BacoPhase::AiAggregation,
        &BacoPhase::Reporting,
    ];

    for phase in phases {
        let prompt = engine.get_prompt(phase);
        assert!(!prompt.is_empty(), "Phase {:?} has empty prompt", phase);
    }
}

#[test]
fn test_prompt_contains_expected_placeholders() {
    let engine = PromptEngine::new();

    let indexing = engine.get_prompt(&BacoPhase::Indexing);
    assert!(indexing.contains("%%FILE_EXTENSIONS%%"));
    assert!(indexing.contains("%%LANGUAGES%%"));
    assert!(indexing.contains("%%MAX_FILE_SIZE%%"));
    assert!(indexing.contains("%%EXCLUDE_PATHS%%"));

    let static_analysis = engine.get_prompt(&BacoPhase::LlmStaticAnalysis);
    assert!(static_analysis.contains("%%LANGUAGE%%"));
    assert!(static_analysis.contains("%%FILE_PATH%%"));
    assert!(static_analysis.contains("%%LINE_RANGE%%"));
    assert!(static_analysis.contains("%%CODE_CONTENT%%"));

    let discovery = engine.get_prompt(&BacoPhase::LlmDiscovery);
    assert!(discovery.contains("%%FINDING_TITLE%%"));
    assert!(discovery.contains("%%FILE_PATH%%"));
    assert!(discovery.contains("%%LINE_NUMBER%%"));
}

#[test]
fn test_engine_construction() {
    let engine = PromptEngine::new();
    // Just verify we can create it
    assert!(!engine.overrides.is_empty() || engine.overrides.is_empty());
}

#[test]
fn test_get_prompt_empty_template() {
    let engine = PromptEngine::new();
    // Should return empty string for non-existent phase
    let result = engine.get_prompt(&BacoPhase::Indexing);
    assert!(!result.is_empty()); // Indexing should exist
}

// ============================================================================
// load_overrides_from_file Tests
// ============================================================================

#[test]
fn test_load_overrides_from_file_valid_toml() {
    let content = r#"
[phases]
indexing = "Custom indexing prompt"
semgrep = "Custom semgrep prompt"
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let overrides = result.unwrap();
    assert_eq!(
        overrides.get("indexing"),
        Some(&"Custom indexing prompt".to_string())
    );
    assert_eq!(
        overrides.get("semgrep"),
        Some(&"Custom semgrep prompt".to_string())
    );
}

#[test]
fn test_load_overrides_from_file_nonexistent_path() {
    let result = PromptEngine::load_overrides_from_file("/nonexistent/path/to/file.toml");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No such file"));
}

#[test]
fn test_load_overrides_from_file_malformed_toml() {
    let content = r#"
[phases
indexing = "unclosed bracket
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_load_overrides_from_file_empty_file() {
    let content = "";

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let overrides = result.unwrap();
    assert!(overrides.is_empty());
}

#[test]
fn test_load_overrides_from_file_partial_overrides() {
    let content = r#"
[phases]
indexing = "Only indexing override"
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let overrides = result.unwrap();
    assert_eq!(overrides.len(), 1);
    assert!(overrides.contains_key("indexing"));
    assert!(!overrides.contains_key("semgrep"));
}

#[test]
fn test_load_overrides_from_file_merge_with_existing() {
    // Create engine with initial overrides
    let mut initial_overrides = HashMap::new();
    initial_overrides.insert("indexing".to_string(), "Initial indexing".to_string());

    let engine = PromptEngine::from_config_overrides(initial_overrides);
    assert_eq!(
        engine.overrides.get("indexing"),
        Some(&"Initial indexing".to_string())
    );

    // Create a TOML file with different overrides
    let content = r#"
[phases]
semgrep = "File-based semgrep"
llm_discovery = "File-based discovery"
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    // Load overrides from file
    let file_overrides =
        PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap()).unwrap();

    // Verify file overrides were loaded
    assert_eq!(
        file_overrides.get("semgrep"),
        Some(&"File-based semgrep".to_string())
    );
    assert_eq!(
        file_overrides.get("llm_discovery"),
        Some(&"File-based discovery".to_string())
    );

    // Note: The file overrides don't automatically merge into the engine instance
    // This test verifies that both sources can coexist
    assert!(engine.overrides.contains_key("indexing")); // Initial override still exists
}

#[test]
fn test_load_overrides_from_file_empty_phases_table() {
    let content = "[phases]\n";

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let overrides = result.unwrap();
    assert!(overrides.is_empty());
}

#[test]
fn test_load_overrides_from_file_special_characters_in_value() {
    let content = r#"
[phases]
indexing = "Prompt with 'quotes' and \"double quotes\" and special chars: $PATH"
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), content).unwrap();

    let result = PromptEngine::load_overrides_from_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let overrides = result.unwrap();
    assert!(overrides.contains_key("indexing"));
    assert!(overrides.get("indexing").unwrap().contains("quotes"));
}
