pub mod agent;
pub mod analysis_context; // AnalysisContext persistence (renamed from context.rs)
pub mod chain_analysis;
pub mod checkpoint;
pub mod citation_verification;
pub mod cli;
pub mod confidence_normalization;
pub mod confidence_refinement;
pub mod config;
pub mod context; // Context extraction module
pub mod core_limit;
pub mod crossfile;
pub mod cve_bootstrap;
pub mod cve_client;
pub mod doctor; // Pre-flight health checks
pub mod error;
pub mod eval;
pub mod evidence;
pub mod file_hash;
pub mod findings;
pub mod git_analysis;
pub mod historical_patterns;
pub mod hook_registry;
pub mod incremental_scan;
pub mod indexer;
pub mod init;
pub mod llm;
pub mod llm_analysis;

pub mod llm_verification;
pub mod org_context;
pub mod phase;
pub mod poc_compiler;
pub mod poc_generation;
pub mod preset;
pub mod project_type;
pub mod prompt;
pub mod rate_limiter;
pub mod report;
pub mod retrieval;
pub mod root_cause_dedup;
pub mod router;
pub mod run_store;
pub mod scan_health;
pub mod scanner;
pub mod scanner_types;
pub mod semgrep;
pub mod subprocess;
pub mod tickets;
pub mod tools;
pub mod ui;
pub mod validation;
pub mod vuln_spec; // VulInSpec specification-guided detection
