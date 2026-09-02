//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.

pub mod common;

// Error taxonomy tests (T27)
mod error_taxonomy_tests;

// Include centralized fixtures
mod fixtures;
pub use fixtures::*;

// Glob-based exclusion matcher tests
mod glob_exclude_tests;
mod prompt_prefix_stability_tests;
mod router_hunt_wiring_tests;
mod triage_rag_tests;

// Include git_analysis module tests
mod git_analysis;

// Report test fixtures
mod report_fixtures;

// Include agent module tests
mod agent;

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

// Checkpoint save/load tests
mod scanner_checkpoint_tests;

// Checkpoint resume functionality tests
mod checkpoint_resume_tests;

// Checkpoint save/load/resume round-trip tests
mod checkpoint_tests;

// Scanner orchestrator integration tests
mod orchestrator_integration_tests;

// Scanner core tests
mod scanner_core_tests;

// Scanner env tests - standalone function tests
mod scanner_env_tests;

// Threat modeling tests
mod threat_model;
mod threat_model_file;

// Phase tests
mod phase;

// Standalone test modules
mod llm_analysis_test;

// BM25 retrieval tests
mod bm25_search;

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

// Six-phase orchestration tests
mod phase_graph;

// Triple path context tests (T2.2)
mod control_path;
mod semantic_path;

// Statement-level localization tests
mod statement_range;

// Confidence normalization tests
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
mod dry_run_tests;
mod eval_tests;
mod html_report_assets_tests;
mod llm_request_count_tests;
mod php_support_tests;
mod pipeline_tests;
mod rejected_findings_tests;
mod report_html_tests;
mod root_cause_dedup_phase_tests;
mod scan_diff_tests;
mod semgrep_ruleset_cpe_tests;

// Exploit test helpers
mod exploit_test_helpers;

// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities

// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities
mod agent_sandbox_tests;
mod chain_analysis_tests;
mod core_utils_tests;
mod cve_misc_tests;

// Additional coverage: report aggregation, rulesynth
mod report_aggregation_tests;
mod rulesynth_tests;

// Additional coverage: worktree staging, cve_client, scanner/sequential
mod cve_client_tests;
mod scanner_sequential_tests;
mod worktree_staging_tests;

// Additional coverage: enrichment, exploit harness
mod ai_aggregation_enrichment_tests;
mod exploit_harness_tests;
mod html_report_dir_creation_tests;

// CVE client network tests using mockito
mod cve_client_network_tests;

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

// Prompt templates tests - covers BacoPhase/ProjectType enums, default prompts, template rendering
mod prompt_templates_tests;

// Findings module tests
mod findings_tests;

// MultiVerifier phase tests
mod multi_verifier_phase_tests;

// Inline tests migrated from source files (reduces file sizes below 1000 lines)
// mod agent_session_inline_tests; // File missing - pre-existing issue
mod confidence_refinement_inline_tests;
// mod llm_verification_inline_tests; // File missing - pre-existing issue
mod scanner_orchestrator_inline_tests;
mod scanner_other_phases_tests;
// mod tickets_inline_tests; // File missing - pre-existing issue

// Additional exploit coverage
mod exploit_coverage;

// P1-P5 paper integration module tests
mod agent_flow_tests;
mod agent_scaffold_call_graph_paths_tests;
// agent_scaffold_coverage_tests merged into agent_scaffold_tests
mod agent_scaffold_fn_lookup_tests;
mod agent_scaffold_tests;
mod agent_scaffold_tree_sitter_parser_tests;
mod context_pacvd_tests;
mod rulesynth_validator_tests;

// Standalone unit test modules for core types
mod analysis_context_tests;
mod confidence_tests;
mod severity_rubric_tests;

// Context module tests
mod context_callee_walker_tests;
mod context_control_path_tests;
mod context_knowledge_path_tests;
mod context_pacvd_extractor_tests;
mod context_semantic_path_tests;
mod context_triple_path_tests;

// HTML renderer unit tests
mod html_finding_renderer_tests;
mod html_renderer_tests;

// Markdown report unit tests
mod markdown_report_tests;

// Coverage gap closure: indexer, file_hash, incremental_scan, rate_limiter, phases
mod confidence_aggregation_tests;
mod file_hash_tests;
mod incremental_scan_tests;
mod indexer_tests;
mod rate_limiter_tests;
mod ticket_git_cross_tests;

// VulInSpec module tests
mod vuln_spec_tests;

// Inert config field wiring tests
mod inert_config_wiring_tests;

// Phase scheduling tests
mod phase_scheduling_tests;

// Evidence-gating classification tests
mod evidence_tests;

// End-to-end evidence-gating pipeline tests
mod evidence_gate_e2e_tests;

// CVE bootstrap tests
mod cve_bootstrap_tests;

// Verification verdict parsing tests
mod verification_verdict_tests;

// Prompt golden tests
mod prompt_golden_tests;

// truncate_code UTF-8 boundary tests
mod truncate_code_tests;

// LLM client infrastructure tests (cache, retry policy)
mod llm_client_infra_tests;

// Structured output and unified config tests (T16, T26)
mod llm_structured_output_tests;

// Structural dedup tests
mod structural_dedup_tests;

// Citation verification gate tests
mod citation_verification_tests;

// Cross-run prior-findings store tests
mod run_store_tests;

// Hunt-prompt engine wiring tests
mod prompt_hunt_tests;

// Org-context profile and symlink containment tests
mod org_context_tests;

// Hunt-module scope/skeptical-gate prompt structure tests
mod prompt_scope_tests;

// Batch LLM processing tests (T14)
mod batch_llm_phases_tests;
mod discovery_skip_baseline_tests;

// Priority, budget, and chunking tests (T18, T19)
mod budget_chunk_tests;

// Preset system tests (T39-T42)
mod preset_tests;
