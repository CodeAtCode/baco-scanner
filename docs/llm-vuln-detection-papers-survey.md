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

All five papers were approved by the project owner on 2026-08-11 for
integration into baco. The full implementation roadmap with sub-tasks,
file paths, and acceptance criteria lives in [`../todo.md`](../todo.md)
(P1-P5). Each integration is gated behind a config flag that defaults to
`enabled = false`, so existing scanner behaviour is unchanged until an
operator opts in.

### P1 — VulTriage: Triple-Path Context Augmentation (arXiv:2605.09461)

- **Source code:** https://github.com/vinsontang1/VulTriage
- **Venue / year:** 2026
- **Claim:** SOTA on PrimeVul pair test set; generalises to Kotlin under
  low-resource and class-imbalanced settings.
- **Core idea:** Before the LLM issues its final vulnerability judgement,
  augment its input with three complementary context paths:

  1. **Control Path** — extract and verbalise AST + CFG + DFG information
     for the target function, exposing control and data dependencies.
  2. **Knowledge Path** — retrieve CWE-derived vulnerability patterns and
     examples via hybrid dense–sparse retrieval.
  3. **Semantic Path** — produce a functional-behaviour summary of the
     code (1–3 sentences) before the final judgement.

  The three contexts are concatenated into one unified instruction passed
  to the LLM. The paper's ablation study confirms each path contributes;
  removing any path degrades precision or recall.

- **baco integration target:** `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`
  (currently passes raw source + CWE prompt). The triple-path context is
  assembled before the LLM call and appended to the existing prompt.
- **Sub-tasks:** P1.1 Control Path extractor, P1.2 Knowledge Path RAG
  over CWE patterns, P1.3 Semantic Path summariser, P1.4 Config + docs,
  P1.5 Wire triple-path into prompt.
- **Risk:** Low–medium. Reuses existing tree-sitter parsers and CPG slice
  from `CpgSlice` phase. Knowledge Path needs an embedding endpoint
  (open question Q1 in `todo.md`).
- **Why integrate:** Strong empirical false-positive reduction; minimal
  structural change to baco.

### P2 — VulnLLM-R: Reasoning LLM + Agent Scaffold (arXiv:2512.07533)

- **Source code:** https://github.com/ucsb-mlsec/VulnLLM-R
- **Venue / year:** 2025
- **Claim:** First specialised reasoning LLM for vulnerability detection.
  7B model distilled from DeepSeek-R1 + QwQ-32B outperforms commercial
  reasoning LLMs and CodeQL/AFL++. 15 zero-days in real projects.

- **Two reusable components (no fine-tuned weights required):**

  **A. Reasoning inference adapter.** Even without their fine-tuned
  weights, the inference-time techniques are portable:
  - **Truncated generation** — stop reasoning at a length cap, force final
    answer.
  - **Policy-based generation** — query the model 4× to get a CWE
    candidate set ("policy"), then re-query with the policy as additional
    context to pick one.
  - **Summary-based reasoning** — query a summariser to compress the
    reasoning chain before the final answer.

  **B. Agent scaffold.** For each target function:
  1. Extract all functions along **three randomly sampled paths** from
     project entry point to the target in the call graph.
  2. Provide these as initial context to the model.
  3. Equip the model with a tool that retrieves function implementations
     by name.
  4. Limit the number of interaction rounds to control inference cost.

- **baco integration target:**
  - Reasoning adapter → `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`
    and `run_llm_verification` (any LLM call site).
  - Agent scaffold → extend `SecurityAgentVerification` phase in
    `src/scanner/phases/other_phases.rs`.
- **Sub-tasks:** P2.1 Truncated generation option, P2.2 Policy-based
  generation, P2.3 Call-graph path sampler, P2.4 Function-by-name
  retrieval tool, P2.5 Wire agent scaffold into SecurityAgentVerification.
- **Risk:** Medium. Agent scaffold depends on call-graph quality and a
  tool-calling interface in `LlmClient` (shared prerequisite PS1 in
  `todo.md`). Policy sampling is 5× LLM calls — must be opt-in.
- **Why integrate:** Inference-time techniques are portable to any
  reasoning-capable model already configured in baco; agent scaffold
  gives the existing `SecurityAgentVerification` phase a concrete
  discovery procedure instead of a fixed multi-verifier pipeline.

### P3 — MoCQ: Neuro-symbolic Static Analysis with LLM Patterns (arXiv:2504.16057)

- **Venue / year:** 2025
- **Claim:** LLM generates vulnerability-detection patterns in a DSL;
  iterative refinement loop with trace-driven symbolic validation gives
  precise feedback. Comparable to expert patterns; 46 new patterns + 25
  zero-days. Hours vs weeks of manual effort.

- **Core algorithm.**
  1. Extract the DSL for expressing vulnerability patterns (paper covers
     12 vuln types across C/C++, Java, PHP, JS).
  2. LLM proposes a candidate pattern in the DSL given a CWE description.
  3. Symbolic validator runs the pattern against a trace corpus and
     produces structured feedback (which traces matched, which missed).
  4. LLM rewrites the pattern using the feedback. Loop until validator
     accepts or budget exhausted.
  5. Accepted patterns are emitted as Semgrep rules (baco's existing
     rule format).

- **baco integration target:** `src/scanner/phases/other_phases.rs::run_rule_synthesis`.
  The current `RuleSynthesis` phase is the natural home — MoCQ is its
  upgrade ("RuleSynthesis 2.0").
- **Sub-tasks:** P3.1 Pattern DSL, P3.2 Symbolic validator against trace
  corpus, P3.3 LLM proposer with feedback loop, P3.4 Emit accepted rules
  to disk, P3.5 Config + tests.
- **Risk:** Medium. Needs a labelled trace corpus (open question Q2 in
  `todo.md`); start small (CWE-78, CWE-89).
- **Why integrate:** Bridges symbolic + LLM without replacing existing
  flows; reduces rule-author fatigue. Emitted Semgrep rules are consumed
  by the existing `Semgrep` phase with no further wiring.

### P4 — PacVD: Context-Enhanced Vulnerability Detection (arXiv:2504.16877)

- **Venue / year:** 2025
- **Claim:** Abstract callee functions via primitive APIs (malloc, free,
  open, close, …) at four granularity levels. Append abstraction to
  target function, feed to LLM. With CoT + DeepSeek-R1: +12.77%
  accuracy, +10.05% precision, +9.25% F1. Different models prefer
  different abstraction levels (GPT-4/DeepSeek = high-level; CodeLLaMA =
  detailed).

- **Core algorithm.**
  1. Default analysis depth: 3 call layers (paper: 75% of inter-procedural
     vulns have call depth ≤ 3).
  2. Build CPGs of the target function and all callees within 3 layers.
  3. For each callee, extract four dimensions of primitive-API usage:
     - **Fuzzy Branches** — API called in all / some / no branches.
     - **Concrete Branches** — specific control conditions under which the
       API fires.
     - **Number of Calls** — count per primitive API.
     - **Key Variables** — identifiers operated on by the API.
  4. Four abstraction levels:
     - Level 1: Fuzzy Branches only (highest abstraction)
     - Level 2: Concrete Branches
     - Level 3: Concrete Branches + Number of Calls
     - Level 4: Concrete Branches + Key Variables
  5. Append the abstraction to the target function; feed to LLM.

- **Primitive API table (from paper).**

  | APIs                                  | Targeted vuln type                     |
  |---------------------------------------|----------------------------------------|
  | open/socket/fopen/fdopen/opendir/close/fclose/closedir | Resource Leak |
  | malloc/realloc/calloc/localtime       | Null Pointer Dereference               |
  | malloc/free                           | Memory Leak, UAF, Double Free          |

- **baco integration target:** `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`.
  The CPG slice from `CpgSlice` phase (when Joern available) or tree-sitter
  CFG fallback provides the call graph. This is a strict superset of P1's
  Control Path — P4 can be a more aggressive mode of the same
  prompt-augmentation hook.
- **Sub-tasks:** P4.1 Primitive API catalogue, P4.2 Call-depth-3 callee
  walker, P4.3 Four-dimension extractor, P4.4 Level selector + prompt
  integration, P4.5 Model-aware level auto-selection.
- **Risk:** Low–medium. Call-graph quality is the main dependency (shared
  prerequisite PS3 in `todo.md`).
- **Why integrate:** Largest reported precision boost among the five
  papers; abstraction is a strict superset of P1's Control Path, so the
  two compose.

### P5 — AgentFlow: Synthesizing Multi-Agent Harnesses (arXiv:2604.20801)

- **Venue / year:** 2026
- **Claim:** Represent the multi-agent harness as a typed graph DSL.
  Search over all 5 dimensions (agent roles A, communication topology G,
  message schemas Σ, tool allocation Φ, coordination protocol Ψ) in one
  optimisation loop. Runtime feedback (coverage, sanitizer, traces)
  diagnoses which part of the harness failed. 84.3% on TerminalBench-2;
  10 zero-days in Chrome including 2 critical sandbox escapes.

- **Five-component harness.** `H = (A, G, Σ, Φ, Ψ)`.
  - A: agent set, each `(role, prompt, model, tools)`
  - G ⊆ A × A: directed communication topology
  - Σ: per-edge message schema (Jinja templates referencing upstream
    outputs + feedback channels)
  - Φ: A → 2^Tools
  - Ψ: coordination protocol (sequential, parallel, fan-out,
    retry-until-success)

- **DSL core (from paper).**
  - Node: `agent(role, prompt, model, tools)` or `fanout(node, k)`
  - Edge: `n1 -> n2` (data) or `n1 ->_g n2` (guarded, `g ∈ {ok, fail}`);
    surface syntax `n.on_fail >> m`
  - Feedback channels: `cov(line coverage)`, `branch`, `san(sanitizer)`,
    `trace(agent)`, `outcome(test)`
  - Templates: Jinja-style `{{ analyst.out }}`, `{{ cov }}`, `{{ san }}`

- **Well-formedness checks (type system).**
  1. Every template variable resolves to an upstream output or feedback
     channel.
  2. Every edge feeds a downstream prompt that actually references the
     upstream output.
  3. The graph is connected (every node reachable from a source).

- **Iterative loop.** propose → execute → observe → score → diagnose.
  The diagnoser reads runtime signals to localise which part of the
  harness failed (e.g. coverage shows the input never reached the
  vulnerable function; sanitizer distinguishes a benign crash from the
  target vuln).

- **baco integration target:** `src/scanner/phases/other_phases.rs::run_security_agent_verification`.
  Today this phase runs a fixed multi-verifier pipeline; AgentFlow would
  make the harness itself searchable. This is the most invasive
  integration — start with a static (non-search) harness encoded in the
  DSL, then add the search loop as a follow-up.
- **Sub-tasks:** P5.1 Harness DSL types, P5.2 Well-formedness checker,
  P5.3 Runtime executor, P5.4 Diagnoser, P5.5 Proposer (search loop).
- **Risk:** High. Coverage/sanitizer feedback requires build
  instrumentation that baco does not have today (shared prerequisite PS2
  in `todo.md`). Recommend shipping P5.1-P5.4 (static harness execution)
  first and deferring P5.5 (search loop) until instrumentation is
  available (open question Q3 in `todo.md`).
- **Why integrate:** Most invasive but highest ceiling. Makes the
  existing `SecurityAgentVerification` phase a concrete, searchable
  harness space instead of a fixed pipeline; the typed DSL gives
  compile-time guarantees on the harness structure.

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
