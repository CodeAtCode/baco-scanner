//! Prompt Template Engine for BACO
//!
//! Provides template-based prompts for all 11 scanner phases with:
//! - Default prompts loaded from `prompts/phases/*.md` files
//! - Config override support via [phases.phase_name] sections
//! - Template variable substitution
//! - Validation (null bytes, max length)
//!
//! Prompt files are stored in `prompts/phases/` directory as markdown files.
//! View them on GitHub: prompts/phases/

pub mod engine;
pub mod loader;
pub mod templates;

pub use engine::{PromptEngine, PromptOverrides};
pub use loader::load_phase_prompts;
pub use templates::{BacoPhase, DefaultPrompts, ProjectType};
