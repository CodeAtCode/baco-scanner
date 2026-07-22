use thiserror::Error;

/// Top-level error type for BACO scanner operations
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Git operation failed: {0}")]
    GitOperationFailed(#[from] git2::Error),

    #[error("LLM client error: {0}")]
    LlmClientBuildError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    // Existing variants preserved
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("LLM error: {0}")]
    Llm(LlmError),

    #[error("Semgrep error: {0}")]
    Semgrep(SemgrepError),

    #[error("Git error: {0}")]
    Git(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Checkpoint error: {0}")]
    Checkpoint(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    // Phase-specific errors
    #[error("Phase execution failed: {phase} - {source}")]
    Phase {
        phase: String,
        #[source]
        source: PhaseError,
    },
}

/// Phase-specific errors
#[derive(Error, Debug)]
pub enum PhaseError {
    #[error("Indexing failed: {0}")]
    Indexing(String),

    #[error("Semgrep scan failed: {0}")]
    Semgrep(String),

    #[error("LLM analysis failed: {0}")]
    LlmAnalysis(String),

    #[error("LLM discovery failed: {0}")]
    LlmDiscovery(String),

    #[error("LLM verification failed: {0}")]
    LlmVerification(String),

    #[error("Ticket cross-reference failed: {0}")]
    TicketCrossRef(String),

    #[error("Git analysis failed: {0}")]
    GitAnalysis(String),

    #[error("Cross-file analysis failed: {0}")]
    CrossFileAnalysis(String),

    #[error("Confidence scoring failed: {0}")]
    ConfidenceScoring(String),

    #[error("AI aggregation failed: {0}")]
    AiAggregation(String),

    #[error("Reporting failed: {0}")]
    Reporting(String),

    #[error("Phase context error: {0}")]
    Context(String),
}

/// LLM client errors
#[derive(Error, Debug)]
pub enum LlmError {
    #[error("API call failed: {0}")]
    ApiCall(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Model error: {0}")]
    Model(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Endpoint not configured: {0}")]
    EndpointNotConfigured(String),
}

/// Semgrep-specific errors
#[derive(Error, Debug)]
pub enum SemgrepError {
    #[error("Semgrep not found: {0}")]
    NotFound(String),

    #[error("Semgrep execution failed: {0}")]
    Execution(String),

    #[error("JSON parse error: {0}")]
    JsonParse(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl From<PhaseError> for ScanError {
    fn from(err: PhaseError) -> Self {
        ScanError::Phase {
            phase: String::new(),
            source: err,
        }
    }
}

// Convenience impls for common conversions
impl From<String> for ScanError {
    fn from(s: String) -> Self {
        ScanError::Unknown(s)
    }
}

impl From<&str> for ScanError {
    fn from(s: &str) -> Self {
        ScanError::Unknown(s.to_string())
    }
}

/// Type alias for Result with ScanError
pub type ScanResult<T> = Result<T, ScanError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_error_missing_env_var() {
        let err = ScanError::MissingEnvVar("API_KEY".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Missing required environment variable"));
        assert!(display.contains("API_KEY"));
    }

    #[test]
    fn test_scan_error_config_error() {
        let err = ScanError::ConfigError("invalid config".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Configuration error"));
        assert!(display.contains("invalid config"));
    }

    #[test]
    fn test_scan_error_llm_error() {
        let err = ScanError::Llm(LlmError::ApiCall("connection failed".to_string()));
        let display = format!("{}", err);
        assert!(display.contains("LLM error"));
    }

    #[test]
    fn test_scan_error_semgrep_error() {
        let err = ScanError::Semgrep(SemgrepError::NotFound("semgrep not in PATH".to_string()));
        let display = format!("{}", err);
        assert!(display.contains("Semgrep error"));
    }

    #[test]
    fn test_scan_error_phase_error() {
        let phase_err = PhaseError::Indexing("failed to index".to_string());
        let err = ScanError::Phase {
            phase: "Indexing".to_string(),
            source: phase_err,
        };
        let display = format!("{}", err);
        assert!(display.contains("Phase execution failed"));
        assert!(display.contains("Indexing"));
    }

    #[test]
    fn test_scan_error_from_string() {
        let err: ScanError = "something went wrong".into();
        match err {
            ScanError::Unknown(msg) => assert_eq!(msg, "something went wrong"),
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_scan_error_from_str() {
        let err: ScanError = "error message".into();
        match err {
            ScanError::Unknown(msg) => assert_eq!(msg, "error message"),
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_llm_error_display() {
        let err = LlmError::Timeout("request timed out".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Timeout"));
        assert!(display.contains("request timed out"));
    }

    #[test]
    fn test_llm_error_authentication() {
        let err = LlmError::Authentication("invalid API key".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Authentication failed"));
    }

    #[test]
    fn test_semgrep_error_execution() {
        let err = SemgrepError::Execution("semgrep exited with error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Semgrep execution failed"));
    }

    #[test]
    fn test_semgrep_error_json_parse() {
        let err = SemgrepError::JsonParse("invalid JSON".to_string());
        let display = format!("{}", err);
        assert!(display.contains("JSON parse error"));
    }

    #[test]
    fn test_phase_error_indexing() {
        let err = PhaseError::Indexing("indexing failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Indexing failed"));
    }

    #[test]
    fn test_phase_error_llm_analysis() {
        let err = PhaseError::LlmAnalysis("LLM analysis failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("LLM analysis failed"));
    }

    #[test]
    fn test_phase_error_git_analysis() {
        let err = PhaseError::GitAnalysis("git operation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Git analysis failed"));
    }

    #[test]
    fn test_phase_error_confidence_scoring() {
        let err = PhaseError::ConfidenceScoring("calculation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Confidence scoring failed"));
    }

    #[test]
    fn test_phase_error_from() {
        let phase_err = PhaseError::Reporting("report failed".to_string());
        let scan_err: ScanError = phase_err.into();
        match scan_err {
            ScanError::Phase { phase, source } => {
                assert!(phase.is_empty());
                match source {
                    PhaseError::Reporting(msg) => assert_eq!(msg, "report failed"),
                    _ => panic!("Expected Reporting variant"),
                }
            }
            _ => panic!("Expected Phase variant"),
        }
    }

    #[test]
    fn test_scan_error_debug() {
        let err = ScanError::Validation("invalid value".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Validation"));
    }

    #[test]
    fn test_scan_error_is_error() {
        let err = ScanError::Unknown("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_phase_error_is_error() {
        let err = PhaseError::Context("context error".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_llm_error_is_error() {
        let err = LlmError::Model("model not found".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_semgrep_error_is_error() {
        let err = SemgrepError::Cache("cache error".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_scan_result_type_alias() {
        let result: ScanResult<String> = Ok("success".to_string());
        match result {
            Ok(s) => assert_eq!(s, "success"),
            Err(_) => panic!("Expected Ok"),
        }

        let result: ScanResult<String> = Err(ScanError::Unknown("error".to_string()));
        match result {
            Ok(_) => panic!("Expected Err"),
            Err(e) => assert_eq!(e.to_string(), "Unknown error: error"),
        }
    }
}
