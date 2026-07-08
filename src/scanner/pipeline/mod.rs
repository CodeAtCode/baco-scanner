//! Scanner pipeline orchestration module.
//!
//! Provides data-driven phase orchestration with:
//! - Orchestrator: manages phase execution with checkpointing
//! - Resumption: handles checkpoint save/load for long-running scans

pub mod orchestrator;
pub mod resumption;

// Re-export main types (currently unused, available for future use)
#[allow(unused_imports)]
pub use orchestrator::PhaseGraph;
#[allow(unused_imports)]
pub use resumption::CheckpointManager;
