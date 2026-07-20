#![allow(
    clippy::items_after_test_module,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::needless_return,
    clippy::match_single_binding,
    clippy::field_reassign_with_default,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::len_without_is_empty,
    clippy::redundant_clone,
    clippy::doc_markdown,
    clippy::borrow_deref_ref,
    clippy::len_zero,
    clippy::module_inception,
    clippy::vec_init_then_push,
    clippy::cloned_ref_to_slice_refs,
    clippy::needless_borrows_for_generic_args,
    clippy::test_attr_in_doctest
)]

pub mod agent;
pub mod analysis_context; // AnalysisContext persistence (renamed from context.rs)
pub mod checkpoint;
pub mod confidence;
pub mod confidence_refinement;
pub mod config;
pub mod context; // Context extraction module

pub mod crossfile;
pub mod cve_bootstrap;
pub mod cve_client;
pub mod error;
pub mod file_hash;
pub mod findings;
pub mod git_analysis;
pub mod incremental_scan;
pub mod indexer;
pub mod llm;
pub mod llm_analysis;
pub mod llm_cache;
pub mod llm_metrics;
pub mod llm_verification;
pub mod multi_verifier;
pub mod phase;
pub mod poc_compiler;
pub mod poc_generation;
pub mod project_type;
pub mod prompt;
pub mod rate_limiter;
pub mod report;
pub mod retrieval;
pub mod root_cause_dedup;
pub mod router;
pub mod scanner;
pub mod scanner_types;
pub mod semgrep;
pub mod severity_rubric;
pub mod staging;
pub mod threat_model;
pub mod tickets;
pub mod validation;
pub mod variant_search;
