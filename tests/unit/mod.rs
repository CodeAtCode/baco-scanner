//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.

// Include agent module tests
mod agent;
// Include centralized fixtures - copy from tests/fixtures.rs
mod agent_executor;
mod confidence_refinement;
mod config;
mod cross_file_analysis;
mod llm;
mod llm_analysis;
mod phases;
mod poc_generation;
mod project_type;
mod report_ai_aggregation;
mod semgrep;
mod staging;
// tickets module has both tickets.rs and tickets/ directory - skip to avoid conflict
