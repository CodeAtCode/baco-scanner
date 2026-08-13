# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-12

### Added
- 24-phase scanner pipeline with Validate phase
- P1-P5 paper integration tracks (VulTriage, VulnLLM-R, MoCQ, PacVD, AgentFlow) behind `enabled = false` defaults
- `max_reasoning_tokens` field for LLM config
- Agent scaffold modules: `call_graph_paths`, `fn_lookup`
- 63 unit tests for agent_scaffold edge cases
- Example report screenshot in README
- `docs/README.md` index and `docs/roadmap.md`

### Changed
- Split large source files (>1000 lines) into directory modules: `other_phases/`, `llm_phases/`, `config/`
- Extracted shared tree-sitter parser module
- Moved inline tests from source files to `tests/`
- MSRV-compatible clippy fixes (replaced `is_none_or`, `is_multiple_of`)

### Fixed
- C function-name extraction handles `function_declarator` tree-sitter node
- Call-graph builder treats uncalled functions as entry points
- Phase count references updated from 20 to 24 throughout

### Removed
- Duplicate inline test blocks from `ai_aggregation.rs`, `multi_verifier.rs`, `root_cause_dedup.rs`
- Orphaned `scanner_phases_consolidated.rs` artifact