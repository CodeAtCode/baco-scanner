# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- VulnInstruct specification-guided vulnerability detection (`src/vuln_spec` module: schema, extractor, BM25+vector retriever) behind `[vuln_spec] enabled = false` default

### Changed
- Threat-modeling phase disabled by default (`enable_threat_modeling = false`) — it generated a static STRIDE template rather than code-derived analysis

## [1.1.0] - 2026-09-15

First public release.

### Added
- `baco doctor` pre-flight checks: config parse, per-phase LLM slot validation (warns on phases without `api_key` that will be skipped), semgrep/python3 presence, output dir writability, disk space
- `baco eval` detection-regression suite: 10 labeled targets with ground-truth oracles, precision/recall/F1, CI gate on pass-rate (`BACO_EVAL_FLOOR`, default 0.70)
- `baco init [PATH]` config scaffolding with language detection and preset suggestions
- Scan-health report (console + JSON section): per-phase run/skipped-with-reason, file counters (indexed/analyzed/dropped/chunked), LLM call outcomes by error class, token and cost totals per phase, blind-scan warning when all LLM phases are skipped
- Pipeline profiles: `[scanner] profile = "core"` (default, 23 phases) or `"all"` (experimental phases included)
- Presets: `django`, `laravel`, `cpp`; inline `custom_rules` Semgrep YAML in presets (self-contained detection packages)
- Per-language default Semgrep rulesets derived from `project.languages`
- Environment-variable bridges for all six LLM phase slots (`LLM_DISCOVERY_KEY`, `LLM_VERIFICATION_KEY`, `LLM_AGGREGATION_KEY`, `LLM_STATIC_ANALYSIS_KEY`, `LLM_SECURITY_AGENT_VERIFICATION_KEY`, `LLM_THREAT_MODELING_KEY`)
- LLM cost transparency: optional `[llm.pricing]` table, token counts per phase and model surfaced in the health report
- Configurable never-submit confidence filter (`never_submit_enabled`, `never_submit_multiplier`)
- `max_reasoning_tokens` field for LLM config
- Agent scaffold modules: `call_graph_paths`, `fn_lookup`
- Chunked analysis of oversized files via tree-sitter (previously dropped or truncated at 8 KB)
- Config-driven per-language hook registry (`[knowledge.hook_registry.<language>]`) and `required_security_primitives` verification prompts

### Changed
- Pipeline defined once in a declarative PhaseSpec table (checkpoint transitions, profile filtering, progress messages and docs all derive from it)
- Semgrep severity read from `extra.severity` first (ERROR/WARNING/INFO mapping); `check_id` keywords can only raise, never lower
- HTML report rendered via embedded minijinja templates
- LLM internals consolidated under `src/llm/` (client, cache, metrics, traits) with canonical import paths
- `max_file_size_kb` defaults to 512; early-termination threshold counts medium+ findings only
- Verification batch parser accepts responses without `index` (positional fallback with warning)
- Multi-model round-robin preserved per phase (`models` list no longer collapsed)
- Internal refactoring: modules split into directory modules, shared tree-sitter parser, tests consolidated under `tests/`

### Fixed
- LLM endpoint URL doubling (`/v1/v1/`) causing silent 404s
- Discovery phase dropping findings that already had LLM evidence
- API key printed in log output during static analysis
- HTML report broken by unclosed `<style>`/`<div>` tags
- Semgrep multi-hit findings attributed to placeholder `multiple_files` path
- Custom-rule IDs prefixed with the materialized temp-file stem
- Discovery enrichment silently overwriting detector severity (enrichment is raise-only)
- LLM findings without a `line` field silently dropped (now salvaged with a warning)
- JSON schema fields serialized as `type_` instead of `type`
- C function-name extraction handles `function_declarator` tree-sitter node
- Call-graph builder treats uncalled functions as entry points

### Removed
- MultiVerifier stub phase (fabricated hash-based verdicts)
- Dead modules: report aggregation, scan diff, worktree staging, severity rubric, phase scaffolding (~2,500 lines)
- Phantom `[llm.phases.*]` config slots and unused configuration keys


