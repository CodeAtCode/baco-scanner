//! Integration tests for the BACO security scanner
//!
//! This module contains end-to-end integration tests that verify the complete
//! security scanning pipeline from indexing through reporting.
//!
//! # Test Categories
//!
//! 1. **Full Pipeline Tests**: Complete scans with checkpoint/resume
//! 2. **Report Validation Tests**: JSON/HTML/SARIF output verification
//! 3. **Cross-Phase Data Flow**: Finding preservation and metric aggregation
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration_tests
//!
//! # Run specific test category
//! cargo test --test integration_tests full_pipeline
//! cargo test --test integration_tests report_validation
//! cargo test --test integration_tests cross_phase
//!
//! # Run with verbose output
//! cargo test --test integration_tests -- --nocapture
//! ```
//!
//! # Test Isolation
//!
//! All tests use:
//! - `tempfile::TempDir` for project/output isolation
//! - Unique scan IDs to prevent checkpoint conflicts
//! - Mock LLM responses via mockito for deterministic behavior
//! - Cleanup on test completion (via TempDir drop)

pub mod fixtures;
pub mod helpers;

pub mod cross_phase;
pub mod full_pipeline;
pub mod report_validation;
