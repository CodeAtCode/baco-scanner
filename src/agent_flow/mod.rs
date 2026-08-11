//! AgentFlow multi-agent harness synthesis (P5).
//!
//! Represents a multi-agent harness as a typed graph DSL. Five components:
//! A (agent set), G (communication topology), Σ (message schemas),
//! Φ (tool allocation), Ψ (coordination protocol).
//!
//! Scaffolding only — types and well-formedness checker. Runtime executor,
//! diagnoser, and proposer are future work (P5.3-P5.5).

pub mod diagnoser;
pub mod dsl;
pub mod executor;
pub mod proposer;
pub mod typecheck;

pub use diagnoser::{diagnose, format_diagnostic, Diagnostic, FeedbackSignal};
pub use dsl::{Agent, AgentFlowHarness, Edge, EdgeKind, FeedbackChannel, Node, NodeKind};
pub use executor::{execute, AgentOutput, ExecutionResult};
pub use proposer::{apply_rewrite, propose_rewrite, HarnessEdit, RewriteProposal};
pub use typecheck::{typecheck, TypeError, TypeResult};
