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
pub mod sanitize;
pub mod templates;

pub use engine::{PromptEngine, PromptOverrides};
pub use loader::{get_prompt, load_phase_prompts};
pub use sanitize::{
    sanitize_prompt_override, validate_prompt_override, MAX_PROMPT_OVERRIDE_LENGTH,
};
pub use templates::{
    auth_hunt_prompt, crypto_hunt_prompt, deserialization_hunt_prompt, get_all_defaults,
    get_default_prompt, injection_hunt_prompt, path_traversal_hunt_prompt, resource_hunt_prompt,
    xss_hunt_prompt, BacoPhase, DefaultPrompts, ProjectType, TemplateVariables,
};
