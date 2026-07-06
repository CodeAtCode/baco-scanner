//! Unit tests for error handling in BACO scanner
//!
//! Tests cover all error types, display formatting, and error conversion.

use baco::error::{LlmError, PhaseError, ScanError, SemgrepError};

// ============================================================================
// ScanError Tests
// ============================================================================

#[test]
fn test_scan_error_config() {
    let err = ScanError::Config("invalid config".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Configuration error"));
    assert!(display.contains("invalid config"));
}

#[test]
fn test_scan_error_phase() {
    let phase_err = PhaseError::Indexing("indexing failed".to_string());
    let err = ScanError::Phase {
        phase: "indexing".to_string(),
        source: phase_err,
    };
    let display = format!("{}", err);
    assert!(display.contains("Phase execution failed"));
    assert!(display.contains("indexing"));
}

#[test]
fn test_scan_error_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err: ScanError = io_err.into();
    let display = format!("{}", err);
    assert!(display.contains("I/O error"));
}

#[test]
fn test_scan_error_json() {
    let json_str = "not json";
    let json_err: serde_json::Error = serde_json::from_str::<()>(json_str).unwrap_err();
    let err: ScanError = json_err.into();
    let display = format!("{}", err);
    assert!(display.contains("JSON error"));
}

#[test]
fn test_scan_error_toml_direct() {
    // Test TOML error conversion directly
    #[derive(Debug, serde::Deserialize)]
    struct Config {
        _field: String,
    }
    let toml_content = "invalid = toml = content";
    let result: Result<Config, toml::de::Error> = toml::from_str(toml_content);
    let toml_err = result.unwrap_err();
    let err: ScanError = toml_err.into();
    let display = format!("{}", err);
    assert!(display.contains("TOML error"));
}

#[test]
fn test_scan_error_toml_from_str() {
    // Alternative TOML test using a different invalid format
    #[derive(Debug, serde::Deserialize)]
    struct Empty;
    let toml_content = "key = "; // incomplete value
    let result: Result<Empty, toml::de::Error> = toml::from_str(toml_content);
    assert!(result.is_err());
    let err: ScanError = result.unwrap_err().into();
    let display = format!("{}", err);
    assert!(display.contains("TOML error"));
}

#[test]
fn test_scan_error_llm() {
    let llm_err = LlmError::ApiCall("API call failed".to_string());
    let err = ScanError::Llm(llm_err);
    let display = format!("{}", err);
    assert!(display.contains("LLM error"));
}

#[test]
fn test_scan_error_semgrep() {
    let semgrep_err = SemgrepError::NotFound("semgrep not found".to_string());
    let err = ScanError::Semgrep(semgrep_err);
    let display = format!("{}", err);
    assert!(display.contains("Semgrep error"));
}

#[test]
fn test_scan_error_git() {
    let err = ScanError::Git("git operation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Git error"));
    assert!(display.contains("git operation failed"));
}

#[test]
fn test_scan_error_validation() {
    let err = ScanError::Validation("validation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Validation error"));
    assert!(display.contains("validation failed"));
}

#[test]
fn test_scan_error_checkpoint() {
    let err = ScanError::Checkpoint("checkpoint failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Checkpoint error"));
    assert!(display.contains("checkpoint failed"));
}

#[test]
fn test_scan_error_unknown() {
    let err = ScanError::Unknown("something went wrong".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Unknown error"));
    assert!(display.contains("something went wrong"));
}

// Note: reqwest::Error is difficult to construct in unit tests.
// The Http variant conversion is tested through integration tests.
#[test]
fn test_scan_error_http_variant_placeholder() {
    // Placeholder test - real HTTP error testing happens in integration tests
    // This just verifies the test suite structure is complete
}

// ============================================================================
// PhaseError Tests
// ============================================================================

#[test]
fn test_phase_error_indexing() {
    let err = PhaseError::Indexing("indexing failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Indexing failed"));
}

#[test]
fn test_phase_error_semgrep() {
    let err = PhaseError::Semgrep("semgrep scan failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Semgrep scan failed"));
}

#[test]
fn test_phase_error_llm_analysis() {
    let err = PhaseError::LlmAnalysis("LLM analysis failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("LLM analysis failed"));
}

#[test]
fn test_phase_error_llm_discovery() {
    let err = PhaseError::LlmDiscovery("LLM discovery failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("LLM discovery failed"));
}

#[test]
fn test_phase_error_llm_verification() {
    let err = PhaseError::LlmVerification("LLM verification failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("LLM verification failed"));
}

#[test]
fn test_phase_error_ticket_cross_ref() {
    let err = PhaseError::TicketCrossRef("ticket cross ref failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Ticket cross-reference failed"));
}

#[test]
fn test_phase_error_git_analysis() {
    let err = PhaseError::GitAnalysis("git analysis failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Git analysis failed"));
}

#[test]
fn test_phase_error_cross_file_analysis() {
    let err = PhaseError::CrossFileAnalysis("cross-file analysis failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Cross-file analysis failed"));
}

#[test]
fn test_phase_error_confidence_scoring() {
    let err = PhaseError::ConfidenceScoring("confidence scoring failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Confidence scoring failed"));
}

#[test]
fn test_phase_error_ai_aggregation() {
    let err = PhaseError::AiAggregation("AI aggregation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("AI aggregation failed"));
}

#[test]
fn test_phase_error_reporting() {
    let err = PhaseError::Reporting("reporting failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Reporting failed"));
}

#[test]
fn test_phase_error_context() {
    let err = PhaseError::Context("context error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Phase context error"));
}

// ============================================================================
// LlmError Tests
// ============================================================================

#[test]
fn test_llm_error_api_call() {
    let err = LlmError::ApiCall("API call failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("API call failed"));
}

#[test]
fn test_llm_error_timeout() {
    let err = LlmError::Timeout("request timed out".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Timeout"));
}

#[test]
fn test_llm_error_rate_limit() {
    let err = LlmError::RateLimit("rate limit exceeded".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Rate limit exceeded"));
}

#[test]
fn test_llm_error_invalid_response() {
    let err = LlmError::InvalidResponse("invalid response format".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Invalid response"));
}

#[test]
fn test_llm_error_model() {
    let err = LlmError::Model("model not available".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Model error"));
}

#[test]
fn test_llm_error_authentication() {
    let err = LlmError::Authentication("invalid API key".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Authentication failed"));
}

#[test]
fn test_llm_error_endpoint_not_configured() {
    let err = LlmError::EndpointNotConfigured("no endpoint configured".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Endpoint not configured"));
}

// ============================================================================
// SemgrepError Tests
// ============================================================================

#[test]
fn test_semgrep_error_not_found() {
    let err = SemgrepError::NotFound("semgrep binary not found".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Semgrep not found"));
}

#[test]
fn test_semgrep_error_execution() {
    let err = SemgrepError::Execution("semgrep execution failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Semgrep execution failed"));
}

#[test]
fn test_semgrep_error_json_parse() {
    let err = SemgrepError::JsonParse("invalid JSON output".to_string());
    let display = format!("{}", err);
    assert!(display.contains("JSON parse error"));
}

#[test]
fn test_semgrep_error_cache() {
    let err = SemgrepError::Cache("cache operation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Cache error"));
}

#[test]
fn test_semgrep_error_config() {
    let err = SemgrepError::Config("invalid semgrep config".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Configuration error"));
}

// ============================================================================
// Error Conversion Tests
// ============================================================================

#[test]
fn test_phase_error_into_scan_error() {
    let phase_err = PhaseError::Indexing("test error".to_string());
    let scan_err: ScanError = phase_err.into();

    match scan_err {
        ScanError::Phase { phase, source } => {
            assert!(matches!(source, PhaseError::Indexing(_)));
            // Note: phase is set to empty string in the From impl
            assert!(phase.is_empty());
        }
        _ => panic!("Expected Phase variant"),
    }
}

#[test]
fn test_io_error_into_scan_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let scan_err: ScanError = io_err.into();
    assert!(matches!(scan_err, ScanError::Io(_)));
}

#[test]
fn test_json_error_into_scan_error() {
    let json_str = "not json";
    let json_err: serde_json::Error = serde_json::from_str::<()>(json_str).unwrap_err();
    let scan_err: ScanError = json_err.into();
    assert!(matches!(scan_err, ScanError::Json(_)));
}

#[test]
fn test_toml_error_into_scan_error() {
    #[derive(Debug, serde::Deserialize)]
    struct DummyConfig;
    let toml_str = "invalid toml";
    let result: Result<DummyConfig, toml::de::Error> = toml::from_str(toml_str);
    let toml_err = result.unwrap_err();
    let scan_err: ScanError = toml_err.into();
    assert!(matches!(scan_err, ScanError::Toml(_)));
}

// ============================================================================
// Debug Trait Tests
// ============================================================================

#[test]
fn test_scan_error_debug() {
    let err = ScanError::Config("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("Config"));
}

#[test]
fn test_phase_error_debug() {
    let err = PhaseError::Indexing("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("Indexing"));
}

#[test]
fn test_llm_error_debug() {
    let err = LlmError::Timeout("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("Timeout"));
}

#[test]
fn test_semgrep_error_debug() {
    let err = SemgrepError::NotFound("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("NotFound"));
}
