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
