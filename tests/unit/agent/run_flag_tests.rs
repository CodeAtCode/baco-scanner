/// Tests for run_compiled_code flag behavior
use baco::agent::tool_schema::default_tools;

#[test]
fn test_default_tools_with_run_enabled() {
    // When run_compiled_code is true, all 5 tools should be registered
    let registry = default_tools(true);
    let defs = registry.get_definitions();

    assert_eq!(
        defs.len(),
        5,
        "Should have 5 tool definitions when run is enabled"
    );
    assert!(registry.get("file_read").is_some());
    assert!(registry.get("pattern_search").is_some());
    assert!(registry.get("file_write").is_some());
    assert!(registry.get("test_compile").is_some());
    assert!(
        registry.get("test_run").is_some(),
        "test_run should be registered when run is enabled"
    );
}

#[test]
fn test_default_tools_with_run_disabled() {
    // When run_compiled_code is false, only 4 tools should be registered (no test_run)
    let registry = default_tools(false);
    let defs = registry.get_definitions();

    assert_eq!(
        defs.len(),
        4,
        "Should have 4 tool definitions when run is disabled"
    );
    assert!(registry.get("file_read").is_some());
    assert!(registry.get("pattern_search").is_some());
    assert!(registry.get("file_write").is_some());
    assert!(registry.get("test_compile").is_some());
    assert!(
        registry.get("test_run").is_none(),
        "test_run should NOT be registered when run is disabled"
    );
}
