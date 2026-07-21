//! Integration tests for baco
//!
//! These tests verify interactions between multiple components.

mod agent;
mod cli;
mod context_in_prompt;
mod cross_scan_merge;
mod cwe_rag_in_prompt;
mod cwe_rag_pipeline;
mod determinism;
mod moe_pipeline;
mod semgrep;
mod sv_trusteval;
mod triage_pipeline;

// TGI integration tests
mod tgi_integration;

// Triple path context integration tests (T2.2)
mod triple_path;

// T2.5 six-phase orchestration integration tests
mod six_phase;

// T3.1: CPG-guided slicing integration tests
mod cpg_pipeline;
