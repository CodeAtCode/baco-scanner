//! Scanner types module
//!
//! This module contains all types used by the scanner:
//! - Severity rubric and scoring
//! - CVE data structures
//! - Patch candidates
//! - PoC compilation results
//! - Project and dependency information

pub mod cve;
pub mod patch;
pub mod poc;
pub mod project;
pub mod severity;

// Re-export commonly used types at the module level for convenience
pub use cve::{CveCluster, CveEntry, CveSource, RootCauseGroup};
pub use patch::{PatchCandidate, PatchValidationResult};
pub use poc::{PoCCompileResult, VerifierVerdict};
pub use project::{Dependency, DependencyEcosystem, MajorityVerdict, ProjectStack};
pub use severity::{
    AccessType, BlastRadius, RubricDimensions, RubricScore, SeverityRubric, V3Severity,
};
