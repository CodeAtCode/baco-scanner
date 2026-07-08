//! Git worktree staging utilities for safe auto-patching
//!
//! Provides safe patch application and validation in isolated git worktrees.

pub mod compiler;
pub mod core;
pub mod error;

// Re-export main types for convenience
pub use compiler::{AutoPatcher, PatchingConfig};
pub use core::StagingArea;
pub use error::{
    AutoPatchError, AutoPatchResult, PatchValidationResult, StagingError, StagingResult,
};
