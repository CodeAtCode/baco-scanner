//! AgentFlow multi-agent harness synthesis.
//!
//! Represents a multi-agent harness as a typed graph DSL. Five components:
//! A (agent set), G (communication topology), Σ (message schemas),
//! Φ (tool allocation), Ψ (coordination protocol).
//!
//! The full loop is implemented: `typecheck` validates well-formedness,
//! `executor` runs the harness via `LlmClient::chat`, `diagnoser` localises
//! failures from the feedback bundle, and `proposer` drives the search loop
//! by asking the LLM for harness rewrites.

pub mod diagnoser;
pub mod dsl;
pub mod executor;
pub mod proposer;
pub mod typecheck;

pub use diagnoser::{Diagnostic, FeedbackSignal, diagnose, format_diagnostic};
pub use dsl::{Agent, AgentFlowHarness, Edge, EdgeKind, FeedbackChannel, Node, NodeKind};
pub use executor::{AgentOutput, ExecutionResult, execute};
pub use proposer::{
    HarnessEdit, RewriteProposal, apply_rewrite, build_harness_summary, parse_rewrite_proposal,
    parse_single_edit, propose_rewrite,
};
pub use typecheck::{TypeError, TypeResult, typecheck};
