# BACO - Bug Analysis & Cross-reference Orchestrator
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

A CLI-based security vulnerability scanner combining static analysis, LLM-powered discovery, and ticket cross-referencing (generated with Regolo.AI).
[Example Report](example-report.html) | [Regolo.AI](https://regolo.ai/)

## Features

- **27+ scanning phases**: Indexing → Semgrep → **CWE MoE Routing** → **CPG-guided slicing** → LLM Static Analysis → **Hunt/Validate/IndependentVerify** → Exploit Synthesis → LLM Discovery → Verification → Rule Synthesis → Ticket Cross-Ref → Git Analysis → Cross-File Analysis → Confidence Scoring → AI Aggregation → Reporting
- **Parallel execution**: Semgrep + LLM discovery concurrent; verification phases run in parallel
- **CWE-aware MoE**: BM25 RAG retrieval from CWE knowledge base, routes to specialized analysis paths
- **CPG-guided slicing**: Precise data-flow extraction via code property graphs
- **Exploit synthesis**: Auto-generates PoC payloads with sandbox validation
- **Rule synthesis**: LLM→semgrep rule generation (MoCQ pattern)
- **Checkpoint/resume**: Crash recovery after each phase
- **Multiple outputs**: JSON, HTML, SARIF
- **Config-driven**: TOML config with env var overrides
- **Ticket integration**: GitHub, GitLab, Bugzilla, Jira

## Installation

```bash
cargo build --release
./target/release/baco --version
```

## Quick Start

```bash
cp config.example.toml myproject.toml
baco scan --config myproject.toml
```

## Documentation

- [Architecture](docs/architecture.md) - PhaseGraph pipeline
- [Configuration](docs/configuration.md) - Settings, LLM config, prompts
- [Research Integration](docs/research-integration.md) - Design decisions

Codecov: [![Codecov](https://codecov.io/gh/CodeAtCode/baco-scanner/branch/master/graph/badge.svg)](https://app.codecov.io/gh/CodeAtCode/baco-scanner/tree/master)