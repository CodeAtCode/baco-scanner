# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- VulnInstruct specification-guided vulnerability detection (`src/vuln_spec` module: schema, extractor, BM25+vector retriever) behind `[vuln_spec] enabled = false` default

### Changed
- Threat-modeling phase disabled by default (`enable_threat_modeling = false`) — it generated a static STRIDE template rather than code-derived analysis

---

## [1.1.0] - 2026-08-12

### Added
- 24-phase scanner pipeline with Validate phase
- P1-P5 paper integration tracks (VulTriage, VulnLLM-R, MoCQ, PacVD, AgentFlow) behind `enabled = false` defaults
- `max_reasoning_tokens` field for LLM config
- Agent scaffold modules: `call_graph_paths`, `fn_lookup`
- `docs/README.md` documentation index

### Changed
- Internal refactoring: split oversized modules into directory modules, extracted shared tree-sitter parser, consolidated tests under `tests/`
- MSRV-compatible clippy fixes (replaced `is_none_or`, `is_multiple_of`)

### Fixed
- C function-name extraction handles `function_declarator` tree-sitter node
- Call-graph builder treats uncalled functions as entry points
- Phase count references updated from 20 to 24 throughout
