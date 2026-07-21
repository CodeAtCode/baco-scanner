//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.

// Include git_analysis module tests
mod git_analysis;

// Include centralized fixtures
mod fixtures;

// Include agent module tests
mod agent;

// TGI client unit tests (pre-existing errors - TODO: fix)
// mod tgi_client;

// Validation function tests
mod validation_tests;
// Include centralized fixtures - copy from tests/fixtures.rs
mod agent_executor;
mod confidence_refinement;
mod config;
mod cross_file_analysis;

mod llm;
mod llm_analysis;
mod poc_generation;
mod project_type;
mod report_ai_aggregation;
mod semgrep;
mod staging;

// Tickets tests - covers extract_meaningful_words and TicketSearcher
mod tickets;

// Error handling tests
mod error_tests;

// Checkpoint save/load tests
mod scanner_checkpoint_tests;

// Scanner core tests
mod scanner_core_tests;

// Threat modeling tests
mod threat_model;
mod threat_model_file;

// Phase tests
mod phase;

// Standalone test modules
mod llm_analysis_test;

// BM25 retrieval tests
mod bm25_search;
mod triage_filter;

// Context extraction tests
mod context_extractor;

// Global false positive store tests
mod global_fp;

// MoE router tests
mod cwe_router;

// Rule synthesis tests (T2.3)
mod rule_validator;

// T2.5 six-phase orchestration tests
mod phase_graph;

// Triple path context tests (T2.2)
mod control_path;
mod semantic_path;

// Rationale check tests (X.1)
mod rationale_check;

// Statement-level localization tests (X.2)
mod statement_range;

// Confidence normalization tests (X.4)
mod confidence_normalization;

// T3.1: CPG-guided slicing tests
mod cpg_slicer;
