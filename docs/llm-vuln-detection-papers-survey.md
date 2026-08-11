# LLM Vulnerability Detection Papers — Integration Survey

> Source: [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection)
> Survey date: 2026-08-11
> Purpose: Identify papers worth integrating into baco's scanner phases or documentation.

## 1. Repository Overview

- **Total papers surveyed:** 36 (2025–2026)
- **Categories:**
  - LLM static analysis / vulnerability detection benchmarks
  - LLM + CPG / graph-based approaches
  - LLM reasoning for root cause and specification-driven detection
  - LLM agents & multi-agent frameworks for vulnerability discovery
  - Agent scaffolding & orchestration
  - Neuro-symbolic and reinforcement-learning hybrids
  - Retrieval-augmented / prompt-evolution approaches
  - Multi-modal vulnerability detection
  - MoE- and fine-tuning-based models

## 2. Top 5 Recommended Papers for Integration

### 🥇 1. VulTriage: Triple-Path Context Augmentation (arXiv:2605.09461)
- **Target phase:** `LlmStaticAnalysis`, `ConfidenceScoring`
- **Changes:**
  - Integrate "triple-path" retrieval (type graph, token graph, CPG) as optional pre-filter in `LlmStaticAnalysis`.
  - Add `retrievalMode: triplePath` switch to phase config.
  - Expose retrieval metrics (`typeDepth`, `tokenDensity`, `graphEdgeCount`) to `ConfidenceScoring`.
- **Difficulty:** Low — baco already has configurable retrieval pipelines and CPG integration.
- **Rationale:** Minimal code change; strong empirical false-positive reduction.

### 🥈 2. VulnLLM-R: Specialized Reasoning LLM with Agent Scaffold (arXiv:2512.07533)
- **Target phase:** `LlmStaticAnalysis` (reasoning adapter)
- **Changes:**
  - Register VulnLLM-R as alternate reasoning engine via `reasoningEngine: "vulnllm-r"` config.
  - Add prompt template adapter to wrap LLM outputs through residual adapter FSM.
  - Minimal Rust: one `Engine` trait impl + feature flag in `Cargo.toml`.
- **Difficulty:** Low — ~150 LoC, no new phase overhead.
- **Rationale:** Paper reports 12–15% true-positive recall boost at same token count.

### 🥉 3. Neuro-symbolic Static Analysis with LLM-generated Vulnerability Patterns (arXiv:2504.16057)
- **Target phase:** `RuleSynthesis` → `Semgrep` / `CpgSlice`
- **Changes:**
  - Create `RuleSynthesis2.0` config phase (disabled by default).
  - Generate Semgrep YAML rules from diffs + LLM summaries on nightly runs.
  - `LlmStaticAnalysis` loads generated rules dynamically if enabled.
- **Difficulty:** Medium — new binary + nightly pipeline + rule correctness gates.
- **Rationale:** Bridges symbolic + LLM without replacing existing flows; reduces rule-author fatigue.

### 4. Context-Enhanced Vulnerability Detection Based on LLM (arXiv:2504.16877)
- **Target phase:** `LlmStaticAnalysis` (RAG layer upgrade)
- **Changes:**
  - Add `context-enhancer` sub-crate querying local AST indexes + NVD/MITRE per snippet.
  - Feed retrieved snippets into prompt as optional `retrievalContext: true`.
  - Track relevance score in `ConfidenceScoring` output.
- **Difficulty:** Low — near-zero structural cost.
- **Rationale:** Paper reports +8–12% precision boost; integrates via existing config flags.

### 5. Synthesizing Multi-Agent Harnesses for Vulnerability Discovery (arXiv:2604.20801)
- **Target phase:** `SecurityAgentVerification`, `RootCauseDedup`
- **Changes:**
  - Expose `AgentHarnessConfig` enabling auto-discovery of "triad" agents (analyzer, reviewer, explainer).
  - New `cargo run --bin harness` step synthesizes agent flows matching repo topology.
  - Feed results into `ConfidenceScoring` via agent-specific filter weight.
- **Difficulty:** Medium — new binary, third-party agent networks into async Rust runtime.
- **Rationale:** Leverages existing CPG slice to derive agent topology; uncovers semantic vulns (e.g., TOCTOU) unreachable by symbolic engines alone.

## 3. Papers to Skip (Duplicates or Out-of-Scope)

| Paper | Reason |
|---|---|
| Everything You Wanted to Know About LLM-based Vulnerability Detection… | Duplicate of CORRECT (already integrated as `Validate` phase) |
| A Systematic Literature Review on Detecting Software Vulnerabilities with LLMs | Survey duplicate |
| From Large to Mammoth / Benchmarking LLMs… | Benchmarks only; no algorithmic contribution |
| SecVulEval / CVE-Bench / SV-TrustEval-C / Mono | Benchmark datasets / critiques |
| Generative LLMs in Smart Contract Vuln Detection / MOS / LAMD | Niche (smart contracts, mobile malware) — baco targets general C/C++/Rust |
| Various ICSE 2025 survey/benchmark papers | Not actionable integration targets |

## 4. Long-Term Directions

- **Neuro-symbolic hybrids (R2Vul, QRS, Neuro-symbolic Static Analysis)** suggest longer-term directions tied to `RuleSynthesis`, `AutoPatching`, and `RootCauseDedup`. Worth prototyping in a feature branch before merging.
- **CPG + LLM** continues to dominate context-rich detection; **LLMxCPG** (arXiv:2507.16585) is the closest analogue to ongoing baco work. Safe to integrate CPG-guided prompting into `LlmStaticAnalysis` without adding a new phase.
- **Agentic & MoE themes** appear in VulTriage, VulnLLM-R, MulVul. baco's macro config toggles allow integrating them as pluggable engines, keeping design consistent.

## 5. Full Paper Inventory

| # | Title | Year | ArXiv/Venue | Category | baco-Relevance | Difficulty |
|---|---|---|---|---|---|---|
| 1 | Everything You Wanted to Know About LLM-based Vulnerability Detection | 2025 | arXiv:2504.13474 | Survey | Skip (CORRECT covers it) | Low |
| 2 | VulnGym: Benchmarking Coding Agents for Repo-Level Vuln Detection | 2026 | arXiv:2608.02001 | Multi-agent | New phase: AgentBenchmarkEval | Medium |
| 3 | VulTriage: Triple-Path Context Augmentation | 2026 | arXiv:2605.09461 | LLM static | Enhance LlmStaticAnalysis + ConfidenceScoring | Low |
| 4 | Synthesizing Multi-Agent Harnesses for Vuln Discovery | 2026 | arXiv:2604.20801 | Multi-agent | Enhance SecurityAgentVerification | Medium |
| 5 | QRS: Rule-Synthesizing Neuro-Symbolic Triad | 2026 | arXiv:2602.09774 | Neuro-symbolic | New phase: NeuroSymbolicSync | High |
| 6 | Seclens: Role-specific LLM Eval | 2026 | arXiv:2604.01637 | Benchmark | Enhance CrossFileAnalysis | Low |
| 7 | Do Fine-Tuned LLMs Understand Vulnerabilities? Semantic Trap | 2026 | arXiv:2601.22655 | Fine-tuning | Enhance LlmDiscovery prompts | Medium |
| 8 | Sifting the Noise: LLM Agents in FP Filtering | 2026 | ISSTA 2026 | Agent filtering | Enhance ConfidenceScoring | Low |
| 9 | AgenticSCR: Autonomous Agentic Secure Code Review | 2026 | 2026 | Agentic | Enhance LlmDiscovery/TicketCrossRef | Medium |
| 10 | LLM-based Vuln Detection at Project Scale | 2026 | 2026 | Empirical | Skip (trend-only) | Low |
| 11 | MulVul: Retrieval-augmented Multi-Agent | 2026 | arXiv:2601.18847 | Multi-agent/RAG | Enhance MultiVerifier | Medium |
| 12 | VulnLLM-R: Reasoning LLM + Agent Scaffold | 2025 | arXiv:2512.07533 | Reasoning | Enhance LlmStaticAnalysis | Low |
| 13 | VULPO: Context-Aware On-Policy LLM Optimization | 2025 | arXiv:2511.11896 | On-policy | Enhance ConfidenceScoring; new AdaptiveFinetuneQueue | Medium |
| 14 | VulInstruct: Root-Cause Reasoning via Security Specs | 2025 | arXiv:2511.04014 | Instruction tuning | Enhance LlmDiscovery + ThreatModeling | Low |
| 15 | From Large to Mammoth | 2025 | NDSS 2025 | Benchmark | Skip (parity only) | Low |
| 16 | Benchmarking LLMs and LLM-based Agents | 2025 | ACL 2025 | Benchmark | Skip (benchmark) | Low |
| 17 | Systematic Literature Review on LLMs for Vuln Detection | 2025 | arXiv:2507.22659 | Survey | Skip (summary) | Low |
| 18 | LLMxCPG: CPG-Guided LLMs | 2025 | USENIX 2025 | CPG+LLM | Enhance CpgSlice → LlmStaticAnalysis | Medium |
| 19 | CLeVeR: Multi-modal Contrastive Learning | 2025 | ACL Findings 2025 | Multi-modal | New MultiModalVulnRepr phase | High |
| 20 | Mono: Is Your "Clean" Vuln Dataset Really Solvable? | 2025 | arXiv:2506.03651 | Dataset critique | Skip | N/A |
| 21 | Learning to Focus: Context Extraction for Efficient LLM Vuln Detection | 2025 | arXiv:2505.17460 | Context extraction | Enhance Indexing/CpgSlice | Low |
| 22 | SV-TrustEval-C | 2025 | SP 2025 | Benchmark | Skip | Low |
| 23 | SecVulEval | 2025 | arXiv:2505.19828 | Benchmark | Skip | Low |
| 24 | CVE-Bench | 2025 | NAACL 2025 | Benchmark | Skip | Low |
| 25 | R2Vul: RL + Structured Reasoning Distillation | 2025 | arXiv:2504.04699 | Neuro-symbolic/RL | Enhance AutoPatching + RootCauseDedup | High |
| 26 | Neuro-symbolic Static Analysis with LLM Patterns | 2025 | arXiv:2504.16057 | Neuro-symbolic | Enhance RuleSynthesis → Semgrep/CpgSlice | Medium |
| 27 | Context-Enhanced Vuln Detection Based on LLM | 2025 | arXiv:2504.16877 | Context retrieval | Enhance LlmStaticAnalysis (RAG) | Low |
| 28 | MOS: MoE for Smart Contract Vuln Detection | 2025 | arXiv:2504.12234 | MoE | Low overlap (smart contracts) | Medium |
| 29 | Abundant Modalities: Multi-Modal Function-Level Vuln Detection | 2025 | TOSEM 2025 | Multi-modal | New MultiModalFusion phase | High |
| 30 | Generative LLMs in Smart Contract Vuln Detection | 2025 | arXiv:2504.04685 | Smart contracts | Low overlap | N/A |
| 31 | Closing the Gap: IDE AI Detection User Study | 2025 | ICSE 2025 | Human factors | Skip (UX) | N/A |
| 32 | Vulnerability Detection with Code LM: How Far Are We? | 2025 | ICSE 2025 | Benchmark | Skip | N/A |
| 33 | Fine-Tuning + LLM Agents for Smart Contract Auditing | 2025 | ICSE 2025 | Agentic auditing | Low overlap | N/A |
| 34 | LAMD: Context-driven Android Malware Detection | 2025 | arXiv:2502.13055 | Domain-specific | Skip (mobile malware) | N/A |
| 35 | LLMs in Software Security: Survey of Vuln Detection | 2025 | arXiv:2502.07049 | Survey | Skip | N/A |
| 36 | One-for-All Does Not Work! MoE for Vuln Detection | 2025 | arXiv:2501.16454 | MoE | Skip (method overview) | N/A |
