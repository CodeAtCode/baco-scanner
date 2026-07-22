# BACO - Bug Analysis & Cross-reference Orchestrator
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

A CLI-based security vulnerability scanner that combines static analysis, LLM-powered discovery, and ticket system cross-referencing (generated with Regolo.AI).
[Example Report](example-report.html) generated with [Regolo.AI](https://regolo.ai/) models on [ins1gn1a/VulnServer-Linux](https://github.com/ins1gn1a/VulnServer-Linux).

## Features

- **Multi-phase scanning**: 25+ phases including Indexing → Semgrep → LLM Static Analysis → LLM Discovery → LLM Verification → **SecurityAgent Verification** → Ticket Cross-Ref → Git Analysis → Cross-File Analysis → Confidence Scoring → AI Aggregation → Reporting → Advanced V3 features (Threat Modeling, CVE Bootstrap, PoC Compilation, Variant Search)
- **Parallel execution**: Semgrep and LLM discovery run concurrently; verification, ticket cross-ref, and git analysis run in parallel
- **Checkpoint/resume**: Automatically saves state after each phase for crash recovery
- **Multiple output formats**: JSON, HTML, SARIF
- **Config-driven**: TOML configuration with environment variable overrides
- **Prompt customization**: Override default LLM prompts per phase via config
- **Ticket integration**: GitHub, GitLab, Bugzilla, Jira support
- **Cross-file analysis**: Traces data flow between files to identify exploitable chains
- **Composite confidence scoring**: Combines multiple signals into a single reliability score

## Installation

```bash
cargo build --release
./target/release/baco --version
```

## Quick Start

```bash
cp config.example.toml myproject.toml
# Edit myproject.toml to configure project path and LLM API keys
baco scan --config myproject.toml
output/report.html
```

## Documentation

- [Architecture](docs/architecture.md) - PhaseGraph pipeline and data flow
- [Configuration](docs/configuration.md) - Project settings, LLM config, agent mode, prompts
- [Research Integration](docs/research-integration.md) - Research-backed design decisions

Codecov: [![Codecov](https://codecov.io/gh/CodeAtCode/baco-scanner/branch/master/graph/badge.svg)](https://app.codecov.io/gh/CodeAtCode/baco-scanner/tree/master)