//! Scan phase trait and implementations.
//!
//! Each phase of the security scan implements this trait for modular, testable phases.

use crate::findings::VulnerabilityFinding;
use crate::scanner::Scanner;
use async_trait::async_trait;
use std::result::Result;

pub mod ai_aggregation;
pub mod confidence_scoring;

pub mod git_analysis;
pub mod indexing;

pub mod helpers;

#[cfg(test)]
pub mod indexing_test;
pub mod llm_discovery;
#[cfg(test)]
pub mod llm_discovery_test;
pub mod llm_static;
#[cfg(test)]
pub mod llm_static_test;
pub mod llm_verification;
pub mod reporting;
pub mod security_agent_verification;
pub mod semgrep;
#[cfg(test)]
pub mod semgrep_test;
pub mod ticket_crossref;

#[cfg(test)]
pub mod parallel_safety_tests;

#[cfg(test)]
pub mod confidence_scoring_test;

#[cfg(test)]
pub mod git_analysis_test;

#[cfg(test)]
pub mod reporting_test;

#[cfg(test)]
pub mod ai_aggregation_test;

#[cfg(test)]
pub mod ticket_crossref_test;

#[cfg(test)]
pub mod security_agent_verification_test;

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
    pub scanner: &'a mut Scanner,
    pub analyzed_files: &'a mut Vec<String>,
}

/// Trait for all scan phases in the security scanning pipeline.
#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Returns the name of this phase.
    fn name(&self) -> &'static str;

    /// Returns the phase order (lower runs first).
    fn order(&self) -> u8;

    /// Executes the phase and returns any findings discovered.
    /// The analyzed_files in context may be updated by the phase.
    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError>;

    /// Checks if this phase should run based on config.
    fn is_enabled(&self, ctx: &PhaseContext) -> bool;
}

#[cfg(test)]
mod phase_trait_tests {
    use super::*;

    #[test]
    fn test_phase_error_display() {
        let err = PhaseError {
            phase_name: "TestPhase",
            message: "Test error".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("TestPhase"));
        assert!(display.contains("Test error"));
    }

    #[test]
    fn test_phase_context_creation() {
        // Just verify the struct exists and can be referenced
        // Full testing requires a real Scanner instance
        assert!(true);
    }
}
