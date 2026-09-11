//! Unit tests for baco
//!
//! These tests focus on isolated functionality without external dependencies.
pub mod common;
pub mod helpers;
pub mod hook_registry_tests;
// Error taxonomy tests (T27)
// Include centralized fixtures
pub use fixtures::*;
// Glob-based exclusion matcher tests
// Include git_analysis module tests
// Report test fixtures
// Include agent module tests
// Validation function tests
// Include centralized fixtures - copy from tests/fixtures.rs
// Tickets tests - covers extract_meaningful_words and TicketSearcher
// Checkpoint save/load tests
// Checkpoint resume functionality tests
// Checkpoint save/load/resume round-trip tests
// Scanner orchestrator integration tests
// Scanner core tests
// Scanner env tests - standalone function tests
// Threat modeling tests
// Threat generation tests (coverage gaps)
// Phase tests
// Standalone test modules
// BM25 retrieval tests
// Global false positive store tests
// MoE router tests
// CWE Routing phase tests
// CWE Routing phase integration tests
// Router unit tests
// Rule synthesis tests (T2.3)
// Six-phase orchestration tests
// Triple path context tests (T2.2)
// Statement-level localization tests
// Confidence normalization tests
// T3.1: CPG-guided slicing tests
// Report module tests (non-aggregation)
// Tools module tests
// Additional coverage: scanner_types, cpg, retrieval, exploit
// Additional coverage: scanner phases, pipeline, report/html
// Exploit test helpers
// Exploit module inline-migrated tests
// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities
// Additional coverage: agent sandbox/session/tools, cve+misc, chain analysis, core utilities
// Additional coverage: report aggregation, rulesynth
// Additional coverage: worktree staging, cve_client, scanner/sequential
// Additional coverage: enrichment, exploit harness
// CVE client network tests using mockito
// Deep rulesynth tests - comprehensive coverage for rulesynth module
// Free function tests for rulesynth
// Phase dispatch tests - verify all ScanPhase variants have match arms
// Coverage gap closure — variant_search and diff_analysis edge cases
// Pipeline ordering and phase sequence tests
// Pipeline test helpers (shared between phase_dispatch and pipeline_ordering)
// Prompt test fixtures (shared between prompt_tests and prompt_templates_tests)
// Prompt templates tests - covers BacoPhase/ProjectType enums, default prompts, template rendering
// Findings module tests
// Severity ordering regression tests
// MultiVerifier phase tests
// Inline tests migrated from source files (reduces file sizes below 1000 lines)
// mod agent_session_inline_tests; // File missing - pre-existing issue
// mod llm_verification_inline_tests; // File missing - pre-existing issue
// mod tickets_inline_tests; // File missing - pre-existing issue
// Additional exploit coverage
// P1-P5 paper integration module tests
// agent_scaffold_coverage_tests merged into agent_scaffold_tests
// Standalone unit test modules for core types
// Context module tests
// HTML renderer unit tests
// Markdown report unit tests
// Coverage gap closure: indexer, file_hash, incremental_scan, rate_limiter, phases
// VulInSpec module tests
// Inert config field wiring tests
// Phase scheduling tests
// Evidence-gating classification tests
// End-to-end evidence-gating pipeline tests
// CVE bootstrap tests
// Verification verdict parsing tests
// Prompt golden tests
// truncate_code UTF-8 boundary tests
// Structured output and unified config tests (T16, T26)
// Structural dedup tests
// Citation verification gate tests
// Cross-run prior-findings store tests
// Hunt-prompt engine wiring tests
// Org-context profile and symlink containment tests
// Hunt-module scope/skeptical-gate prompt structure tests
// Batch LLM processing tests (T14)
// Wave 2 migrated modules: report rendering, prompts, CPG, retrieval, scanner
mod agent;
mod agent_executor;
mod agent_flow_tests;
mod agent_sandbox_tests;
mod agent_scaffold_call_graph_paths_tests;
mod agent_scaffold_fn_lookup_tests;
mod agent_scaffold_tests;
mod agent_scaffold_tree_sitter_parser_tests;
mod agent_session;
mod ai_aggregation_enrichment_tests;
mod analysis_context_tests;
mod batch_llm_phases_tests;
mod bm25_search;
mod budget_chunk_tests;
mod chain_analysis_tests;
mod checkpoint_resume_tests;
mod checkpoint_tests;
mod chunked_analysis_tests;
mod citation_verification_tests;
mod confidence_aggregation_tests;
mod confidence_normalization;
mod confidence_refinement;
mod confidence_refinement_inline_tests;
mod config;
mod context_callee_walker_tests;
mod context_control_path_tests;
mod context_knowledge_path_tests;
mod context_pacvd_extractor_tests;
mod context_pacvd_tests;
mod context_path_tests;
mod context_semantic_path_tests;
mod context_triple_path_tests;
mod control_path;
mod cost_estimate_tests;
mod cpg_joern_tests;
mod cpg_queries_tests;
mod cpg_slicer;
mod cpg_slicer_tests;
mod cpg_tests;
mod cross_file_analysis;
mod cve_bootstrap_tests;
mod cve_client_network_tests;
mod cve_client_tests;
mod cve_misc_tests;
mod cwe_router;
mod cwe_routing_phase_tests;
mod cwe_routing_tests;
mod deployment_marker_tests;
mod diff_analysis_edge_tests;
mod discovery_partition_tests;
mod discovery_routing_tests;
mod discovery_skip_baseline_tests;
mod dry_run_tests;
mod error_taxonomy_edge_tests;
mod error_taxonomy_tests;
mod eval_tests;
mod evidence_gate_e2e_tests;
mod evidence_tests;
mod exploit_coverage;
mod exploit_harness_execution_tests;
mod exploit_harness_tests;
mod exploit_mod_tests;
mod exploit_prompt_tests;
mod exploit_test_helpers;
mod exploit_tests;
mod file_hash_tests;
mod findings_tests;
mod fixtures;
mod git_analysis;
mod glob_exclude_tests;
mod global_fp;
mod html_finding_renderer_tests;
mod html_renderer_tests;
mod html_report_assets_tests;
mod html_report_dir_creation_tests;
mod incremental_scan_tests;
mod indexer_tests;
mod inert_config_wiring_tests;
mod llm;
mod llm_analysis;
mod llm_analysis_helpers_tests;
mod llm_cache_tests;
mod llm_client_infra_tests;
mod llm_core_edge_tests;
mod llm_metrics;
mod llm_phase_gating_tests;
mod llm_request_count_tests;
mod llm_structured_output_tests;
mod llm_verification_tests;
mod markdown_report_tests;
mod multi_verifier_phase_tests;
mod orchestrator_integration_tests;
mod org_context_tests;
mod phase;
mod phase_dispatch_tests;
mod phase_graph;
mod phase_scheduling_tests;
mod php_support_tests;
mod pipeline_ordering_tests;
mod pipeline_test_helpers;
mod pipeline_tests;
mod poc_compiler_tests;
mod poc_generation_tests;
mod preset_tests;
mod project_type;
mod prompt_engine_tests;
mod prompt_golden_tests;
mod prompt_hunt_tests;
mod prompt_loader_tests;
mod prompt_prefix_stability_tests;
mod prompt_sanitize_tests;
mod prompt_scope_tests;
mod prompt_templates_tests;
mod prompt_test_fixtures;
mod prompt_tests;
mod rate_limiter_tests;
mod rejected_findings_tests;
mod report_ai_aggregation;
mod report_fixtures;
mod report_html_finding_renderer_tests;
mod report_html_renderer_tests;
mod report_html_tests;
mod report_html_utilities_tests;
mod report_json_tests;
mod report_sarif_tests;
mod report_tests;
mod retrieval_bm25_tests;
mod retrieval_mod_tests;
mod retrieval_tests;
mod root_cause_dedup_phase_tests;
mod router_hunt_wiring_tests;
mod router_tests;
mod rule_validator;
mod rulesynth_deep_tests;
mod rulesynth_emitter_tests;
mod rulesynth_free_fns_tests;
mod rulesynth_mod_tests;
mod rulesynth_pattern_dsl_tests;
mod rulesynth_prompt_tests;
mod rulesynth_proposer_tests;
mod rulesynth_symbolic_validator_tests;
mod rulesynth_tests;
mod rulesynth_validator_tests;
mod run_store_tests;
mod scan_health_tests;
mod scanner;
mod scanner_checkpoint_tests;
mod scanner_core_tests;
mod scanner_env_tests;
mod scanner_helpers_tests;
mod scanner_mod_tests;
mod scanner_orchestrator_inline_tests;
mod scanner_other_phases_tests;
mod scanner_parallel_tests;
mod scanner_sequential_tests;
mod scanner_types_tests;
mod semantic_path;
mod semgrep;
mod semgrep_custom_rules_tests;
mod severity_order_tests;
mod severity_rubric_tests;
mod specifications_config_tests;
mod staging;
mod statement_range;
mod static_analysis_prompt_tests;
mod structural_dedup_tests;
mod threat_generation_tests;
mod threat_model;
mod threat_model_file;
mod threat_model_fs_tests;
mod threat_model_generation_tests;
mod threat_model_tests;
mod ticket_git_cross_tests;
mod tickets;
mod tickets_coverage;
mod tools_tests;
mod triage_rag_tests;
mod truncate_code_tests;
mod validation_success_path_tests;
mod validation_tests;
mod variant_search_edge_tests;
mod variant_search_tests;
mod verification_batch_index_tests;
mod verification_verdict_tests;
mod vuln_spec_tests;
mod wp_primitive_prompt_tests;
