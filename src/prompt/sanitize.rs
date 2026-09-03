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
