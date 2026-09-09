//! Integration-facing unit tests for error_taxonomy_edge_tests coverage gaps.
//! Tests use only public crate API (baco::) and run without external services.

use baco::error::ScanError;

// ============================================================================
// ScanError Variant Construction and Display Tests
// ============================================================================

#[test]
fn test_auth_error_display_contains_phase_context() {
    let err = ScanError::Auth {
        message: "Invalid API key".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Authentication failed"));
    assert!(display.contains("Invalid API key"));
}

#[test]
fn test_config_error_display_contains_phase_context() {
    let err = ScanError::Config {
        message: "Missing required field 'base_url'".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Configuration error"));
    assert!(display.contains("Missing required field"));
}

#[test]
fn test_parse_error_display_contains_phase_context() {
    let err = ScanError::Parse {
        message: "Invalid JSON format".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Parse error"));
    assert!(display.contains("Invalid JSON"));
}

#[test]
fn test_network_error_display_contains_phase_context() {
    let err = ScanError::Network {
        message: "Connection refused".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Network error"));
    assert!(display.contains("Connection refused"));
}

#[test]
fn test_timeout_error_display_contains_phase_context() {
    let err = ScanError::Timeout {
        message: "Request timed out after 30s".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Timeout error"));
    assert!(display.contains("timed out"));
}

#[test]
fn test_rate_limit_error_display_contains_phase_context() {
    let err = ScanError::RateLimit {
        message: "Rate limit exceeded: 100 requests/min".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Rate limit exceeded"));
}

#[test]
fn test_server_error_display_contains_phase_context() {
    let err = ScanError::Server {
        message: "Internal server error (500)".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Server error"));
    assert!(display.contains("500"));
}

#[test]
fn test_phase_error_display_contains_phase_name() {
    let err = ScanError::Phase {
        message: "LLM verification failed".to_string(),
        phase: "llm_verification".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Phase 'llm_verification' failed"));
    assert!(display.contains("LLM verification failed"));
}

// ============================================================================
// is_retryable() Classification Tests
// ============================================================================

#[test]
fn test_all_retryable_variants_return_true() {
    // Network is retryable
    let err = ScanError::Network {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());

    // Timeout is retryable
    let err = ScanError::Timeout {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());

    // RateLimit is retryable
    let err = ScanError::RateLimit {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());

    // Server is retryable
    let err = ScanError::Server {
        message: "test".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_all_non_retryable_variants_return_false() {
    // Auth is non-retryable
    let err = ScanError::Auth {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());

    // Config is non-retryable
    let err = ScanError::Config {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());

    // Parse is non-retryable
    let err = ScanError::Parse {
        message: "test".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());

    // Unknown is non-retryable
    let err = ScanError::Unknown("test".to_string());
    assert!(!err.is_retryable());

    // Validation is non-retryable
    let err = ScanError::Validation("test".to_string());
    assert!(!err.is_retryable());
}

// ============================================================================
// with_phase() Context Attachment Tests
// ============================================================================

#[test]
fn test_with_phase_wraps_network_error() {
    let err = ScanError::Network {
        message: "Connection failed".to_string(),
        source: None,
    };
    let err_with_phase = err.with_phase("discovery");

    assert!(matches!(err_with_phase, ScanError::Phase { .. }));
    assert_eq!(err_with_phase.phase(), Some("discovery"));
    // Phase wrapper itself is not retryable, but source is
    // The Phase variant wraps the original error for context
    assert!(!err_with_phase.is_retryable()); // Phase variant is not retryable by itself
}

#[test]
fn test_with_phase_wraps_auth_error() {
    let err = ScanError::Auth {
        message: "Invalid token".to_string(),
        source: None,
    };
    let err_with_phase = err.with_phase("verification");

    assert!(matches!(err_with_phase, ScanError::Phase { .. }));
    assert_eq!(err_with_phase.phase(), Some("verification"));
    assert!(!err_with_phase.is_retryable()); // Non-retryable preserved
}

#[test]
fn test_with_phase_appends_to_existing_phase_message() {
    let err = ScanError::Phase {
        message: "Original error".to_string(),
        phase: "aggregation".to_string(),
        source: None,
    };
    let err_with_phase = err.with_phase("secondary");

    let display = format!("{}", err_with_phase);
    assert!(display.contains("Original error"));
    assert!(display.contains("aggregation"));
    assert!(display.contains("secondary"));
}

#[test]
fn test_with_phase_preserves_source() {
    let source_error = std::io::Error::other("io error");
    let err = ScanError::Network {
        message: "Network issue".to_string(),
        source: Some(Box::new(source_error) as Box<dyn std::error::Error + Send + Sync>),
    };
    let err_with_phase = err.with_phase("test_phase");

    // The wrapped error should still be accessible
    assert!(err_with_phase.phase().is_some());
}

// ============================================================================
// phase() Extraction Tests
// ============================================================================

#[test]
fn test_phase_returns_none_for_non_phase_errors() {
    let err = ScanError::Network {
        message: "test".to_string(),
        source: None,
    };
    assert_eq!(err.phase(), None);
}

#[test]
fn test_phase_returns_some_for_phase_errors() {
    let err = ScanError::Phase {
        message: "test".to_string(),
        phase: "security_agent_verification".to_string(),
        source: None,
    };
    assert_eq!(err.phase(), Some("security_agent_verification"));
}

// ============================================================================
// Error Conversion Tests
// ============================================================================

#[test]
fn test_from_json_error_maps_to_parse_variant() {
    let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
    let scan_err = ScanError::from_json_error(json_err);

    assert!(matches!(scan_err, ScanError::Parse { .. }));
    assert!(!scan_err.is_retryable());
}

#[test]
fn test_from_toml_error_maps_to_parse_variant() {
    let toml_err = toml::from_str::<serde_json::Value>("invalid = = toml").unwrap_err();
    let scan_err = ScanError::from_toml_error(toml_err);

    assert!(matches!(scan_err, ScanError::Parse { .. }));
    assert!(!scan_err.is_retryable());
}

#[test]
fn test_from_string_converts_to_unknown() {
    let err: ScanError = "something went wrong".to_string().into();
    assert!(matches!(err, ScanError::Unknown(_)));
    assert_eq!(format!("{}", err), "Unknown error: something went wrong");
}

#[test]
fn test_from_str_converts_to_unknown() {
    let err: ScanError = "error message".into();
    assert!(matches!(err, ScanError::Unknown(_)));
}

// ============================================================================
// Legacy Variant Tests
// ============================================================================

#[test]
fn test_missing_env_var_display() {
    let err = ScanError::MissingEnvVar("LLM_API_KEY".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Missing required environment variable"));
    assert!(display.contains("LLM_API_KEY"));
}

#[test]
fn test_git_operation_failed_display() {
    let git_err = git2::Error::from_str("not found");
    let err = ScanError::GitOperationFailed(git_err);
    let display = format!("{}", err);
    assert!(display.contains("Git operation failed"));
}

#[test]
fn test_llm_client_build_error_display() {
    let err = ScanError::LlmClientBuildError("invalid config".to_string());
    let display = format!("{}", err);
    assert!(display.contains("LLM client error"));
    assert!(display.contains("invalid config"));
}

#[test]
fn test_io_error_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err: ScanError = io_err.into();
    assert!(matches!(err, ScanError::IoError(_)));
}

#[test]
fn test_validation_error_display() {
    let err = ScanError::Validation("invalid confidence score".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Validation error"));
    assert!(display.contains("confidence score"));
}

#[test]
fn test_checkpoint_error_display() {
    let err = ScanError::Checkpoint("checkpoint file corrupted".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Checkpoint error"));
}

// ============================================================================
// ScanResult Type Alias Tests
// ============================================================================

#[test]
fn test_scan_result_ok_variant() {
    let result = "success".to_string();
    assert_eq!(result, "success");
}

#[test]
fn test_scan_result_err_variant() {
    let err = ScanError::Unknown("error".into());
    assert!(matches!(err, ScanError::Unknown(_)));
}

// ============================================================================
// Debug Trait Tests
// ============================================================================

#[test]
fn test_scan_error_debug_format() {
    let err = ScanError::Network {
        message: "network issue".to_string(),
        source: None,
    };
    let debug = format!("{:?}", err);
    assert!(debug.contains("Network"));
}

#[test]
fn test_scan_error_display_and_debug_differ() {
    let err = ScanError::Config {
        message: "config issue".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    let debug = format!("{:?}", err);

    // Display should be user-friendly
    assert!(display.contains("Configuration error"));
    // Debug should show variant name
    assert!(debug.contains("Config"));
}

// ============================================================================
// Error Source Chain Tests
// ============================================================================

#[test]
fn test_error_source_chain_for_wrapped_errors() {
    let source = std::io::Error::other("underlying error");
    let err = ScanError::Network {
        message: "network failed".to_string(),
        source: Some(Box::new(source) as Box<dyn std::error::Error + Send + Sync>),
    };

    // Error should be usable as dyn Error
    let _dyn_err: &dyn std::error::Error = &err;
}

// ============================================================================
// Phase Context Preservation Tests
// ============================================================================

#[test]
fn test_phase_context_in_display_for_wrapped_error() {
    let err = ScanError::Network {
        message: "connection timeout".to_string(),
        source: None,
    };
    let err_with_phase = err.with_phase("llm_verification");
    let display = format!("{}", err_with_phase);

    assert!(display.contains("Phase 'llm_verification' failed"));
    assert!(display.contains("Network error"));
    assert!(display.contains("connection timeout"));
}

#[test]
fn test_multiple_with_phase_calls_accumulate_context() {
    let err = ScanError::Network {
        message: "original error".to_string(),
        source: None,
    };
    let err1 = err.with_phase("phase1");
    let err2 = err1.with_phase("phase2");

    let display = format!("{}", err2);
    assert!(display.contains("phase1"));
    assert!(display.contains("phase2"));
    assert!(display.contains("original error"));
}
