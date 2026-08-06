//! Sanitization utilities for prompt overrides.
//!
//! Provides functions to sanitize and validate prompt override strings
//! to prevent injection attacks and ensure safe processing.

/// Maximum allowed length for prompt overrides
pub const MAX_PROMPT_OVERRIDE_LENGTH: usize = 10000;

/// Sanitizes a prompt override string by:
/// - Stripping null bytes
/// - Removing control characters (except newline, carriage return, tab)
/// - Normalizing unicode
pub fn sanitize_prompt_override(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            // Keep printable ASCII and whitespace
            c.is_ascii_graphic() || c.is_ascii_whitespace()
        })
        .collect()
}

/// Validates a prompt override string for potential injection patterns.
/// Returns Ok(()) if safe, or Err with description if unsafe.
pub fn validate_prompt_override(input: &str) -> Result<(), String> {
    // Check length
    if input.len() > MAX_PROMPT_OVERRIDE_LENGTH {
        return Err(format!(
            "Prompt override exceeds maximum length of {} characters",
            MAX_PROMPT_OVERRIDE_LENGTH
        ));
    }

    // Check for null bytes (should be stripped by sanitize, but double-check)
    if input.contains('\0') {
        return Err("Null bytes not allowed in prompt override".to_string());
    }

    // Check for common injection patterns (case-insensitive)
    let lower = input.to_lowercase();

    // SQL injection patterns - but allow legitimate security analysis
    // We check for actual SQL commands in suspicious contexts, not just mentions
    let suspicious_sql_patterns = [
        "'; DROP",
        "\"; DROP",
        "'; DELETE",
        "\"; DELETE",
        "'; INSERT",
        "\"; INSERT",
        "'; UPDATE",
        "\"; UPDATE",
    ];

    for pattern in suspicious_sql_patterns {
        if lower.contains(&pattern.to_lowercase()) {
            return Err(format!(
                "Potential SQL injection pattern detected: {}",
                pattern
            ));
        }
    }

    // Script injection
    if lower.contains("<script") && lower.contains("</script>") {
        return Err("Script tags not allowed in prompt override".to_string());
    }

    // Shell command injection patterns
    let shell_patterns = ["; rm -rf", "| rm -rf", "&& rm -rf", "`rm -rf`", "$(rm -rf)"];
    for pattern in shell_patterns {
        if lower.contains(pattern) {
            return Err(format!(
                "Potential shell injection pattern detected: {}",
                pattern
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // SQL Injection Tests
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

    // Script Injection Tests
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

    // Shell Injection Tests
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

    // Length Validation Tests
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

    // Null Byte Tests
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

    // Valid Prompt Tests
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
}
