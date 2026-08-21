//! Shared phase helpers for tests.

pub mod helpers;

/// Error type for phase execution failures.
#[derive(Debug, Clone)]
pub struct PhaseError {
    pub phase_name: &'static str,
    pub message: String,
}

impl std::fmt::Display for PhaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Phase '{}' failed: {}", self.phase_name, self.message)
    }
}

impl std::error::Error for PhaseError {}

/// Context passed to phase execution.
pub struct PhaseContext<'a> {
    pub scanner: &'a mut crate::scanner::Scanner,
    pub analyzed_files: &'a mut Vec<String>,
}

