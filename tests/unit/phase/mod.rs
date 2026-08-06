//! Test modules for BACO security scanner phases
//!
//! This module re-exports all test submodules for organized test discovery.

mod ai_aggregation_test;
mod auto_patching_test;
mod confidence_scoring_test;
mod cross_file_analysis_test;
mod cve_bootstrap_test;
mod git_analysis_test;
mod indexing_test;
mod llm_discovery_test;
mod llm_static_test;
mod llm_verification_test;
mod parallel_safety_tests;
mod poc_compiler_test;
mod reporting_test;
mod root_cause_dedup_test;
mod security_agent_verification_test;
mod semgrep_test;
mod threat_modeling_test;
mod ticket_crossref_test;
mod variant_search_test;
