//! Unit tests for SemgrepRunner and related functionality
//!
//! Covers:
//! - Settings parsing and configuration
//! - Semgrep execution (mocked)
//! - Rule matching and exclusion logic
//! - Result parsing and aggregation
//! - Edge cases: missing config, invalid rules, empty results

// Include prefix normalization tests
mod rule_prefix_normalization_tests;

// Include edge case tests
mod parsing_edge_cases_tests;

// Include migrated inline tests
mod core_tests;

// Include multi-hit aggregation path tests
mod aggregate_path_tests;
mod custom_rules_tests;
mod inline_migrated_tests;
mod severity_mapping_tests;
