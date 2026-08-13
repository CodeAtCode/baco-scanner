# BACO Documentation Index

BACO is a research-backed SAST scanner written in Rust. It augments static analysis with LLM-powered vulnerability detection across a 20-phase pipeline, grounded in 18 integrated academic papers.

## Reading Order

Recommended order for new users:

1. **README.md** (root) — project overview, quick start, prerequisites
2. **docs/architecture.md** — the 20-phase pipeline, PhaseGraph, data flow
3. **docs/configuration.md** — all config options, LLM setup, phase flags
4. **docs/research-integration.md** — the 18 papers integrated into baco
5. **docs/llm-vuln-detection-papers-survey.md** — full survey of 36 papers
6. **todo.md** — completed P1–P5 tracks and pending work

## By Topic

| Topic | Document | Section |
|-------|----------|---------|
| Getting started | README.md | Quick Start |
| Pipeline phases | docs/architecture.md | PhaseGraph |
| LLM configuration | docs/configuration.md | LLM Settings |
| Config file format | docs/configuration.md | Project Settings |
| Research basis | docs/research-integration.md | (full document) |
| Paper survey | docs/llm-vuln-detection-papers-survey.md | (full document) |
| Roadmap | todo.md | (full document) |