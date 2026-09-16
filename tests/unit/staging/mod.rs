//! Unit tests for src/staging.rs
//!
//! Covers:
//! - StagingArea operations (create, apply_patch, validate, cleanup, rollback)
//! - AutoPatcher operations (generate_patch, validate_patch, apply_and_validate)
//! - Error handling
//! - PatchValidationResult logic
//! - PatchingConfig defaults

mod compiler_tests;
mod core_tests;
mod error_tests;
mod inline_migrated_tests;
