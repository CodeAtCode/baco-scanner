use thiserror::Error;

/// Retryability classification for pipeline errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryable {
    /// Retryable error (Network/Timeout/RateLimit)
    Yes,
    /// Non-retryable error (Auth/Config/Parse)
    No,
}

/// Top-level error type for BACO scanner operations
///
/// Provides typed error taxonomy with retryability classification and phase context.
/// Use `is_retryable()` to check if an error should be retried, and `with_phase()`
/// to attach phase context to errors.
#[derive(Error, Debug)]
pub enum ScanError {
    /// Authentication failure (401/403) - non-retryable
    #[error("Authentication failed: {message}")]
    Auth {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Configuration error - non-retryable
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Parse/serialization error - non-retryable
    #[error("Parse error: {message}")]
    Parse {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Network error - retryable
    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Timeout error - retryable
    #[error("Timeout error: {message}")]
    Timeout {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Rate limit error (429) - retryable
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Server error (5xx) - retryable
    #[error("Server error: {message}")]
    Server {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Phase-specific error context
    #[error("Phase '{phase}' failed: {message}")]
    Phase {
        message: String,
        phase: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Legacy variants for backward compatibility
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Git operation failed: {0}")]
    GitOperationFailed(#[from] git2::Error),

    #[error("LLM client error: {0}")]
    LlmClientBuildError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

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

impl ScanError {
    /// Check if this error is retryable.
    ///
    /// Retryable errors: Network, Timeout, RateLimit, Server
    /// Non-retryable errors: Auth, Config, Parse
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScanError::Network { .. }
                | ScanError::Timeout { .. }
                | ScanError::RateLimit { .. }
                | ScanError::Server { .. }
        )
    }

    /// Attach phase context to this error.
    ///
    /// Wraps the error in a Phase variant if it doesn't already have phase context.
    pub fn with_phase(self, phase: &str) -> Self {
        // If already a Phase error, just append to the message
        if let ScanError::Phase {
            message,
            source,
            phase: existing_phase,
        } = self
        {
            return ScanError::Phase {
                message: format!("{} (phase: {})", message, phase),
                phase: existing_phase,
                source,
            };
        }

        // Otherwise wrap in Phase
        let message = self.to_string();
        let source = match self {
            ScanError::Auth { source, .. } => source,
            ScanError::Config { source, .. } => source,
            ScanError::Parse { source, .. } => source,
            ScanError::Network { source, .. } => source,
            ScanError::Timeout { source, .. } => source,
            ScanError::RateLimit { source, .. } => source,
            ScanError::Server { source, .. } => source,
            ScanError::Phase { source, .. } => source, // Already handled above
            ScanError::MissingEnvVar(e) => {
                Some(Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send + Sync>)
            }
            ScanError::GitOperationFailed(e) => Some(Box::new(e) as _),
            ScanError::LlmClientBuildError(e) => Some(Box::new(std::io::Error::other(e)) as _),
            ScanError::IoError(e) => Some(Box::new(e) as _),
            ScanError::Json(e) => Some(Box::new(e) as _),
            ScanError::Toml(e) => Some(Box::new(e) as _),
            ScanError::Git(e) => Some(Box::new(std::io::Error::other(e)) as _),
            ScanError::Http(e) => Some(Box::new(e) as _),
            ScanError::Validation(e) => Some(Box::new(std::io::Error::other(e)) as _),
            ScanError::Checkpoint(e) => Some(Box::new(std::io::Error::other(e)) as _),
            ScanError::Unknown(e) => Some(Box::new(std::io::Error::other(e)) as _),
        };

        ScanError::Phase {
            message,
            phase: phase.to_string(),
            source,
        }
    }

    /// Extract the phase name if this error has phase context.
    pub fn phase(&self) -> Option<&str> {
        match self {
            ScanError::Phase { phase, .. } => Some(phase),
            _ => None,
        }
    }

    /// Classify a reqwest error into a typed ScanError variant.
    ///
    /// Maps HTTP status codes and error kinds to appropriate variants:
    /// - 401/403 → Auth (non-retryable)
    /// - 429 → RateLimit (retryable)
    /// - 5xx → Server (retryable)
    /// - Timeout/Network → Network/Timeout (retryable)
    /// - Other → Parse (non-retryable)
    pub fn from_reqwest(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            return ScanError::Timeout {
                message: "Request timeout".to_string(),
                source: Some(Box::new(err) as _),
            };
        }

        if err.is_connect() || err.is_request() || err.is_body() || err.is_decode() {
            return ScanError::Network {
                message: "Network operation failed".to_string(),
                source: Some(Box::new(err) as _),
            };
        }

        // Check status code if available
        if let Some(status) = err.status() {
            let code = status.as_u16();
            match code {
                401 | 403 => ScanError::Auth {
                    message: format!("HTTP {} authentication error", code),
                    source: Some(Box::new(err) as _),
                },
                429 => ScanError::RateLimit {
                    message: "Rate limit exceeded (HTTP 429)".to_string(),
                    source: Some(Box::new(err) as _),
                },
                500..=599 => ScanError::Server {
                    message: format!("HTTP {} server error", code),
                    source: Some(Box::new(err) as _),
                },
                _ => ScanError::Network {
                    message: format!("HTTP {} error", code),
                    source: Some(Box::new(err) as _),
                },
            }
        } else {
            ScanError::Network {
                message: "HTTP error (no status)".to_string(),
                source: Some(Box::new(err) as _),
            }
        }
    }

    /// Classify a serde_json error into a Parse variant.
    pub fn from_json_error(err: serde_json::Error) -> Self {
        ScanError::Parse {
            message: "JSON parse error".to_string(),
            source: Some(Box::new(err) as _),
        }
    }

    /// Classify a toml error into a Parse variant.
    pub fn from_toml_error(err: toml::de::Error) -> Self {
        ScanError::Parse {
            message: "TOML parse error".to_string(),
            source: Some(Box::new(err) as _),
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
        let err = ScanError::Config {
            message: "invalid config".to_string(),
            source: None,
        };
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
