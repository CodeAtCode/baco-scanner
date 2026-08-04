//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.

pub mod common;

// Include git_analysis module tests
mod git_analysis;

// Include centralized fixtures
mod fixtures;

// Report test fixtures
mod report_fixtures;

// Include agent module tests
mod agent;

// TGI client unit tests (pre-existing errors - TODO: fix)
// mod tgi_client;

// Validation function tests
mod validation_success_path_tests;
mod validation_tests;
// Include centralized fixtures - copy from tests/fixtures.rs
mod agent_executor;
mod agent_session;
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

// Checkpoint resume functionality tests
mod checkpoint_resume_tests;

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

// CWE Routing phase tests
mod cwe_routing_tests;

// CWE Routing phase integration tests
mod cwe_routing_phase_tests;

// Router unit tests
mod router_tests;

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

// Report module tests (non-aggregation)
mod report_tests;

// Tools module tests
mod tools_tests;

// Additional coverage: scanner_types, cpg, retrieval, exploit
mod cpg_tests;
mod exploit_tests;
mod retrieval_tests;
mod scanner_types_tests;

// Additional coverage: scanner phases, pipeline, report/html
mod pipeline_tests;
mod report_html_tests;
mod root_cause_dedup_phase_tests;

// Exploit test helpers
mod exploit_test_helpers;

// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities

// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities
mod agent_sandbox_tests;
mod chain_analysis_tests;
mod core_utils_tests;
mod cve_misc_tests;

// Additional coverage: prompt templates, context summary, report aggregation, rulesynth
mod context_summary_tests;
mod prompt_templates_tests;
mod report_aggregation_tests;
mod rulesynth_tests;

// Additional coverage: worktree staging, cve_client, scanner/sequential
mod cve_client_tests;
mod scanner_sequential_tests;
mod worktree_staging_tests;

// Additional coverage: enrichment, exploit harness, tgi, parallel
mod ai_aggregation_enrichment_tests;
mod exploit_harness_tests;
mod html_report_dir_creation_tests;
mod llm_tgi_tests;
mod scanner_parallel_tests;

// Final coverage push: cve_client deep coverage
mod cve_client_deep_tests;

// Deep rulesynth tests - comprehensive coverage for rulesynth module
mod rulesynth_deep_tests;

// Free function tests for rulesynth
mod rulesynth_free_fns_tests;

// Phase dispatch tests - verify all ScanPhase variants have match arms
mod phase_dispatch_tests;

// Coverage gap closure — variant_search and diff_analysis edge cases
mod diff_analysis_edge_tests;
mod variant_search_edge_tests;

// Pipeline ordering and phase sequence tests
mod pipeline_ordering_tests;

// Pipeline test helpers (shared between phase_dispatch and pipeline_ordering)
mod pipeline_test_helpers;

// Prompt test fixtures (shared between prompt_tests and prompt_templates_tests)
mod prompt_test_fixtures;

// Findings module tests
mod findings_tests;

// LLM verification phase tests
mod llm_verification_phase_tests;

// MultiVerifier phase tests
mod multi_verifier_phase_tests;
