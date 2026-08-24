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
