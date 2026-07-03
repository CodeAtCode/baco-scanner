//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.

// Include git_analysis module tests
mod git_analysis;

// Include agent module tests
mod agent;
// Include centralized fixtures - copy from tests/fixtures.rs
mod agent_executor;
mod confidence_refinement;
mod config;
mod cross_file_analysis;
mod llm;
mod llm_analysis;
mod poc_generation;
mod project_type;
mod report_ai_aggregation;
mod semgrep;
mod staging;
mod incremental_scan_tests;
// tickets module has both tickets.rs and tickets/ directory - skip to avoid conflict

// Error handling tests
mod error_tests;

// Checkpoint save/load tests
mod scanner_checkpoint_tests;

// Scanner core tests
mod scanner_core_tests;
