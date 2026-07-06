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
mod incremental_scan_tests;
mod llm;
mod llm_analysis;
mod poc_generation;
mod project_type;
mod report_ai_aggregation;
mod semgrep;
mod staging;

// Tickets tests - covers extract_meaningful_words and TicketSearcher
mod tickets;

// Error handling tests
mod error_tests;

// Checkpoint save/load tests
mod scanner_checkpoint_tests;

// Scanner core tests
mod scanner_core_tests;
