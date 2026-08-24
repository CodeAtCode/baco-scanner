//! Shared phase helpers for tests.

pub mod helpers;

/// Context passed to phase execution.
pub struct PhaseContext<'a> {
    pub scanner: &'a mut crate::scanner::Scanner,
    pub analyzed_files: &'a mut Vec<String>,
}
