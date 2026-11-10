# BACO Documentation

Documentation for baco — a 23-phase LLM-assisted code scanner.

**For setup, usage, and reading order, see the root [README.md](../README.md).**

## Documentation Files

### Getting Started

| File | Description |
|------|-------------|
| [configuration.md](configuration.md) | All config options, LLM setup, phase flags |
| [cli-reference.md](cli-reference.md) | CLI commands and flags |
| [languages.md](languages.md) | Supported languages and analysis coverage |

### Architecture & Design

| File | Description |
|------|-------------|
| [architecture.md](architecture.md) | The 23-phase pipeline, PhaseGraph, data flow |
| [research-integration.md](research-integration.md) | Research-backed design and paper integrations |
| [llm-vuln-detection-papers-survey.md](llm-vuln-detection-papers-survey.md) | Full survey of 36 papers |

### Operator Guide

| File | Description |
|------|-------------|
| [operator-tuning.md](operator-tuning.md) | Tuning knobs: confidence bands, thresholds, profiles |
| [output-interpretation.md](output-interpretation.md) | How to read and act on findings output |
| [findings-field-reference.md](findings-field-reference.md) | JSON output schema for `VulnerabilityFinding` |
| [troubleshooting.md](troubleshooting.md) | Common issues and solutions |

### CI & Testing

| File | Description |
|------|-------------|
| [ci-integration.md](ci-integration.md) | CI/CD setup with SARIF output |
| [mutation-testing.md](mutation-testing.md) | Nightly mutation testing: what it measures and how to read it |

### Reference

| File | Description |
|------|-------------|
| [glossary.md](glossary.md) | Terms used across the docs |
| [example-report-screenshot.png](example-report-screenshot.png) | Sample HTML report preview |

---

**Note:** The detailed reading order and overview now live in the root [README.md](../README.md).
