# BACO — Bug Analysis & Cross-reference Orchestrator

A research-backed SAST scanner that augments static analysis with LLM-powered
discovery across a 24-phase pipeline: semgrep → CWE-aware MoE routing (opt-in) →
LLM verification → exploit synthesis (experimental) → ticket cross-referencing → auto-patching (opt-in).
Grounded in 36 surveyed papers (16 integrated) from [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection).

[![CI](https://github.com/CodeAtCode/baco-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeAtCode/baco-scanner/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/CodeAtCode/baco-scanner/branch/master/graph/badge.svg)](https://app.codecov.io/gh/CodeAtCode/baco-scanner)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.74+-orange.svg)](https://www.rust-lang.org)

[![Example Report](docs/example-report-screenshot.png)](example-report.html)

---

## Prerequisites

- **Rust** 1.74+ (`rustup`)
- **An LLM API key** (Mistral, OpenAI, or any OpenAI-compatible endpoint)
- **Semgrep** installed on PATH (`pip install semgrep` or [see install options](https://semgrep.dev/docs/getting-started/))

## Quick Start

Five steps from clone to first scan:

```bash
# 1. Install baco (build from source)
git clone https://github.com/CodeAtCode/baco-scanner.git
cd baco-scanner
cargo build --release

# 2. Install semgrep (required for static analysis)
pip install semgrep

# 3. Set your LLM API key
export MISTRAL_API_KEY="your-key-here"

# 4. Run pre-flight checks
./target/release/baco doctor

# 5. Configure and scan
cp config.toml my-config.toml
# Edit my-config.toml: set [project] path to your target code
./target/release/baco scan --config my-config.toml
```

### Additional subcommands

```bash
# Pre-flight checks (config parse, preset resolve, LLM phases, semgrep, python3, Joern-if-CPG, output dir, disk space)
./target/release/baco doctor --json

# Evaluate precision/recall/F1 vs ground truth
./target/release/baco eval --target /path/to/fixtures --ground-truth eval/oracles/target.json

# Generate report
./target/release/baco report --input findings.json --format html

# Verify findings
./target/release/baco verify --input findings.json

# Scan options
./target/release/baco scan --config my.toml --dry-run   # Print estimate and exit
./target/release/baco scan --config my.toml --target /path  # Override target path
./target/release/baco scan --config my.toml --force     # Force full rescan
```

- **Phases**: 4 parallel (Indexing, Semgrep, CpgSlice, LlmStaticAnalysis) + sequential phases — some disabled by default (see [Configuration](docs/configuration.md))

### What happens next

- **Phases**: 4 parallel (Indexing, Semgrep, CpgSlice, LlmStaticAnalysis) + sequential phases — some disabled by default (see [Configuration](docs/configuration.md))

## Features

- **Pipeline profiles**: `core` (default) runs essential phases; `all` enables experimental phases (still individually flag-gated) — set with `scanner.profile = "core" | "all"`
- **Pipeline phases**: Indexing → Semgrep → CpgSlice (`[cpg]` section, requires Joern) → LlmStaticAnalysis → CweRouting (`router.enabled`) → RuleSynthesis (experimental) → LlmDiscovery → LlmVerification → Validate (opt-in) → SecurityAgentVerification (opt-in) → TicketCrossRef → GitAnalysis → CrossFileAnalysis → ConfidenceScoring → AiAggregation → ThreatModeling (`enable_threat_modeling`) → RootCauseDedup → MultiVerifier (`enable_multi_verifier`, experimental) → AutoPatching (`enable_auto_patching`, opt-in) → CveBootstrap → PocCompiler (`enable_poc_compilation`, opt-in) → ExploitSynth (`[exploit]` section, experimental) → VariantSearch → Reporting
- **Parallel execution**: Indexing, Semgrep, CpgSlice, and LlmStaticAnalysis run concurrently; 20 sequential phases follow
- **CWE-aware MoE (opt-in)**: BM25 RAG retrieval from CWE knowledge base, routes to specialized analysis paths — enable with `router.enabled = true`
- **Research-backed**: 16 academic papers integrated (VulTriage, VulIn, MoCQ, MoEVD, AgentFlow) — see [Research Integration](docs/research-integration.md)
- **Checkpoint/resume**: Crash recovery after each phase
- **Pre-flight checks**: `baco doctor` validates config, presets, LLM phases, semgrep, python3, Joern (if CPG enabled), output dir, and disk space
- **Multiple outputs**: JSON, HTML, SARIF
- **Config-driven**: TOML config with env var overrides
- **Ticket systems**: Configurable via `[[tickets.systems]]` TOML blocks (supports any system type via `system_type` field) — see [Configuration](docs/configuration.md) for setup

### Phase reference table

| Phase | Profile | Enabling flag / condition |
|-------|---------|----------------------------|
| Indexing | Core | Always runs |
| Semgrep | Core | Always runs |
| CpgSlice | Experimental | `scanner.profile = "all"` + `[cpg]` section |
| LlmStaticAnalysis | Core | Always runs |
| CweRouting | Core | `router.enabled = true` |
| RuleSynthesis | Experimental | `scanner.profile = "all"` |
| LlmDiscovery | Core | Always runs |
| LlmVerification | Core | Always runs |
| Validate | Experimental | `scanner.profile = "all"` + `[validate]` section |
| SecurityAgentVerification | Experimental | `scanner.profile = "all"` + `[agent]` section |
| TicketCrossRef | Core | Always runs |
| GitAnalysis | Core | Always runs |
| CrossFileAnalysis | Core | Always runs |
| ConfidenceScoring | Core | Always runs |
| AiAggregation | Core | Always runs |
| ThreatModeling | Experimental | `scanner.profile = "all"` + `enable_threat_modeling = true` |
| RootCauseDedup | Core | Always runs |
| MultiVerifier | Experimental | `scanner.profile = "all"` + `enable_multi_verifier = true` |
| AutoPatching | Experimental | `scanner.profile = "all"` + `enable_auto_patching = true` |
| CveBootstrap | Core | Always runs |
| PocCompiler | Experimental | `scanner.profile = "all"` + `enable_poc_compilation = true` |
| ExploitSynth | Experimental | `scanner.profile = "all"` + `[exploit]` section |
| VariantSearch | Experimental | `scanner.profile = "all"` + `enable_variant_search = true` |
| Reporting | Core | Always runs |

## Evidence & Verification Techniques

- **Citation verification**: Deterministic file existence + line range checks in Reporting phase; failures halve confidence + add note — see [`docs/argus-analysis.md`](docs/argus-analysis.md)
- **Cross-run prior-findings skip lists (opt-in)**: Confirmed/FalsePositive findings from prior scans injected into discovery prompts to reduce redundancy — enable with `[prior runs]` section
- **Domain-routed hunt prompts**: Per-attack-class modules (`prompts/hunt/`) selected by target languages; verification prompt includes skeptical self-refutation gate + untrusted-content framing — see [`docs/cloudflare-security-audit-skill-analysis.md`](docs/cloudflare-security-audit-skill-analysis.md)
- **Rejected-findings persistence**: `include_rejected = true` persists "rejected" array in JSON + "Investigated & Dismissed" appendix in HTML
- **Requires-deployment-testing marker (experimental)**: Exploit synthesis marks unverifiable findings when Docker sandbox unavailable — enable with `[exploit]` section
- **Org-context calibration (opt-in)**: Organizational policy profile (stack, infra, secret_storage, data_sensitivity, severity_rules) injected into prompts to reduce false positives — enable with `[org_context]` section
- **Eval oracles**: Known-answer harness under `eval/` with labeled vulnerable/secure fixtures; precision/recall/F1 scoring via `baco eval --target <path> --ground-truth <oracle.json>` — see [`eval/README.md`](eval/README.md)

## Supported Languages

| Language   | Static analysis          | LLM analysis |
| ---------- | ------------------------ | ------------ |
| C / C++    | tree-sitter + semgrep    | ✅           |
| Rust       | tree-sitter + semgrep    | ✅           |
| Python     | tree-sitter + semgrep    | ✅           |
| JavaScript | tree-sitter + semgrep    | ✅           |

## Outputs

- `findings.json` — complete vulnerability data (all fields, machine-readable)
- `report.html` — interactive report with severity filtering, code highlighting, confidence/CWE badges
- `report.sarif` — SARIF 2.1 for CI/CD integration (GitHub Code Scanning, Azure DevOps)

## Architecture

See [Architecture](docs/architecture.md) for the PhaseGraph pipeline diagram, full phase list, and data flow.

## Research Foundation

BACO integrates 16 academic papers from the [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection) survey. Integrations span agentic workflows, context enhancement, rule synthesis, MoE routing, and confidence calibration.

See [Research Integration](docs/research-integration.md) for per-paper details (techniques, results, config flags) and [Paper Survey](docs/llm-vuln-detection-papers-survey.md) for the full 36-paper survey.

## Documentation

- [Architecture](docs/architecture.md) — PhaseGraph pipeline, all 24 phases, data flow
- [Configuration](docs/configuration.md) — Config options, LLM setup, phase flags, prompt overrides
- [Research Integration](docs/research-integration.md) — 16 integrated papers with techniques and results
- [Paper Survey](docs/llm-vuln-detection-papers-survey.md) — Full 36-paper survey
- [Operator Tuning](docs/operator-tuning.md) — Performance flags and scenario-based tuning
- [Output Interpretation](docs/output-interpretation.md) — Reading findings, confidence, triage verdicts
- [Troubleshooting](docs/troubleshooting.md) — Common errors and fixes
- [Roadmap](todo.md) — Completed and pending work

### Reading Order

Recommended for new users:
1. **README.md** (this page) — overview, quick start
2. **docs/architecture.md** — pipeline architecture
3. **docs/configuration.md** — configuration reference
4. **docs/research-integration.md** — research integrations
5. **docs/llm-vuln-detection-papers-survey.md** — paper survey
6. **docs/operator-tuning.md** — performance tuning
7. **docs/output-interpretation.md** — reading results
8. **docs/troubleshooting.md** — error fixes
9. **todo.md** — roadmap

## Acknowledgements

Sponsored and tested with [Regolo.AI](https://regolo.ai/) — LLM API services.
