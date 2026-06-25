//! Security agent verification tests
//!
//! This module contains comprehensive tests covering:
//! - Agent loop execution with real tool calls
//! - file_read tool working correctly on test files
//! - pattern_search finding vulnerabilities
//! - file_write generating test code
//! - run_test executing cargo test and parsing results
//! - Edge cases: empty description, no code snippet
//! - False positive detection (tests pass → finding removed)
//! - True positive detection (tests fail → finding kept)
//! - Tool usage tracking

pub mod agent_loop;
pub mod edge_cases;
pub mod false_positive;
pub mod fixtures;
pub mod test_helpers;
pub mod tool_usage;
