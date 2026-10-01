//! Unit tests for scanner module
//!
//! Tests cover Scanner initialization and scan phases.

mod hook_primitive_phase_tests;
mod scanner_init_tests;

// Scanner phase tests
mod checkpoint_tests;
mod core_tests;
mod env_tests;
mod helpers_tests;
mod mod_tests;
mod orchestrator_inline_tests;
mod other_phases_tests;
mod parallel_error_tests;
mod parallel_tests;
mod phases;
mod sequential_tests;
mod static_analysis_tests;
mod triage_discard_fallback_tests;
mod triage_unnamed_reconciliation_tests;
mod types_tests;
