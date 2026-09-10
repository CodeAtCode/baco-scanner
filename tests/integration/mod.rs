//! Integration tests for baco
//!
//! These tests verify interactions between multiple components.

pub mod common;

mod agent;
mod cli;
mod cross_scan_merge;
mod cwe_rag_in_prompt;
mod cwe_rag_pipeline;
mod determinism;
mod moe_pipeline;
mod rule_synth;
mod semgrep;
mod sv_trusteval;
mod wp_detection;

// Triple path context integration tests (T2.2)
mod triple_path;

// T3.1: CPG-guided slicing integration tests
mod cpg_pipeline;

// C++ preset detection tests
mod cpp_detection;

// Eval harness oracle scoring tests
mod eval_oracle;
