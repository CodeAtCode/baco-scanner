//! Migrated inline tests for baco::prompt::sanitize
//!
//! Previously in src/prompt/sanitize.rs #[cfg(test)] mod tests

use baco::prompt::{
    sanitize_prompt_override, validate_prompt_override, MAX_PROMPT_OVERRIDE_LENGTH,
};

// ============================================================================
// Sanitize Tests
// ============================================================================

#[test]
fn test_sanitize_null_bytes() {
    let input = "Hello\0World\0Test";
    let result = sanitize_prompt_override(input);
    assert_eq!(result, "HelloWorldTest");
}

#[test]
fn test_sanitize_max_length() {
    let long_input = "a".repeat(MAX_PROMPT_OVERRIDE_LENGTH + 1000);
    let result = sanitize_prompt_override(&long_input);
    assert_eq!(result.len(), MAX_PROMPT_OVERRIDE_LENGTH + 1000);
    // sanitize doesn't truncate, validate does
}

// ============================================================================
// Validate Injection Tests
// ============================================================================

#[test]
fn test_validate_injection_patterns() {
    // Safe prompts
    assert!(validate_prompt_override("Analyze for SQL injection vulnerabilities").is_ok());
    assert!(validate_prompt_override("Check XSS patterns").is_ok());

    // Unsafe prompts
    assert!(validate_prompt_override("'; DROP TABLE users").is_err());
    assert!(validate_prompt_override("<script>alert('xss')</script>").is_err());
    assert!(validate_prompt_override("; rm -rf /").is_err());
}

// ============================================================================
// SQL Injection Tests
// ============================================================================

#[test]
fn test_validate_sql_drop_table_single_quote() {
    let input = "'; DROP TABLE users; --";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Potential SQL injection pattern detected"));
}

#[test]
fn test_validate_sql_delete_single_quote() {
    let input = "'; DELETE FROM users WHERE";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_sql_insert_single_quote() {
    let input = "'; INSERT INTO users VALUES";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_sql_update_single_quote() {
    let input = "'; UPDATE users SET admin=1";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_sql_case_insensitive() {
    let input = "'; drop table users";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_legitimate_sql_terms_allowed() {
    assert!(validate_prompt_override("Check for SQL injection vulnerabilities").is_ok());
    assert!(validate_prompt_override("Review DROP TABLE usage in code").is_ok());
}

// ============================================================================
// Script Injection Tests
// ============================================================================

#[test]
fn test_validate_script_tag_open_and_close() {
    let input = "<script>alert('xss')</script>";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Script tags not allowed"));
}

#[test]
fn test_validate_script_tag_case_insensitive() {
    let input = "<SCRIPT>alert('xss')</SCRIPT>";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_script_tag_open_only_allowed() {
    assert!(validate_prompt_override("Reference: <script> tag usage").is_ok());
}

#[test]
fn test_validate_script_tag_close_only_allowed() {
    assert!(validate_prompt_override("End with </script> marker").is_ok());
}

// ============================================================================
// Shell Injection Tests
// ============================================================================

#[test]
fn test_validate_shell_semicolon_rm_rf() {
    let input = "; rm -rf /tmp/test";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Potential shell injection pattern detected"));
}

#[test]
fn test_validate_shell_pipe_rm_rf() {
    let input = "| rm -rf /";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_shell_and_rm_rf() {
    let input = "&& rm -rf /var/log";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_shell_backtick_rm_rf() {
    let input = "`rm -rf`";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_shell_dollar_paren_rm_rf() {
    let input = "$(rm -rf)";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

// ============================================================================
// Length Validation Tests
// ============================================================================

#[test]
fn test_validate_exceeds_max_length() {
    let input = "a".repeat(MAX_PROMPT_OVERRIDE_LENGTH + 1);
    let result = validate_prompt_override(&input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("exceeds maximum length"));
}

#[test]
fn test_validate_at_max_length() {
    let input = "a".repeat(MAX_PROMPT_OVERRIDE_LENGTH);
    let result = validate_prompt_override(&input);
    assert!(result.is_ok());
}

// ============================================================================
// Null Byte Tests
// ============================================================================

#[test]
fn test_validate_null_byte_detected() {
    let input = "safe prompt\0with null";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Null bytes not allowed"));
}

#[test]
fn test_validate_null_byte_at_start() {
    let input = "\0at start";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

#[test]
fn test_validate_null_byte_at_end() {
    let input = "at end\0";
    let result = validate_prompt_override(input);
    assert!(result.is_err());
}

// ============================================================================
// Valid Prompt Tests
// ============================================================================

#[test]
fn test_validate_empty_string_allowed() {
    let input = "";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_simple_safe_prompt() {
    let input = "Analyze this code for security vulnerabilities";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_prompt_with_whitespace_allowed() {
    let input = "  Analyze   code   with   spaces  ";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_prompt_with_newlines_allowed() {
    let input = "Line 1\nLine 2\nLine 3";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}

#[test]
fn test_validate_prompt_with_tabs_allowed() {
    let input = "Column1\tColumn2\tColumn3";
    let result = validate_prompt_override(input);
    assert!(result.is_ok());
}
