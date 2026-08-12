<!--
Progress banner
- Tier 1 (T1.1-T1.4): COMPLETE [x]
- Tier 2 (T2.1-T2.5): COMPLETE [x]
- Tier 3 (T3.1 CPG/Joern, T3.2 exploit synthesis, T3.3 TGI reasoning LLM): PARTIAL (T3.2 done via ExploitSynth phase; T3.1 + T3.3 pending external infra)
- Cross-Cutting (X.1-X.5): X.1, X.2, X.3, X.5 done [x]; X.4 done [x]
 - Paper-Integration Roadmap: P1 DONE [x], P2 DONE [x], P3 DONE [x], P4 DONE [x], P5 DONE [x]
- Pipeline: 24 phases (Indexing → Semgrep → CweRouting → LlmStaticAnalysis → Validate → LlmDiscovery → SecurityAgentVerification → RuleSynthesis → CpgSlice → ExploitSynth → Complete)
-->

# Baco — Research-Integration TODO

This file tracks all planned work for integrating published vulnerability-detection
research into the baco scanner. Each task is grep-able by its ID (e.g. `P3.2`)
and lists exact file paths, dependencies, and acceptance criteria.

Project rule reference: `#6381` (tiered structure), `#6452` (progress banner + `[x]`),
`#6453` (exactly five Cross-Cutting tasks), `#6422` (checkpoint transition tests
must be updated when adding phases), `#5811` (coverage ≥ 80%), `#5812` (zero
clippy warnings before merge).

---

## Top-of-file state

| Tier           | Status          |
|----------------|-----------------|
| T1 (T1.1-T1.4) | COMPLETE [x]    |
| T2 (T2.1-T2.5) | COMPLETE [x]    |
| T3 (T3.1-T3.3) | PARTIAL         |
| X  (X.1-X.5)   | COMPLETE [x]    |
| P1 (P1.1-P1.5) | COMPLETE [x]    |
| P2 (P2.1-P2.5) | COMPLETE [x]    |
| P3 (P3.1-P3.5) | COMPLETE [x]    |
| P4 (P4.1-P4.5) | COMPLETE [x]    |
| P5 (P5.1-P5.5) | COMPLETE [x]    |

---

## Tier 3 (pending external infrastructure)

### T3.1 — CPG / Joern integration
- **Status:** blocked
- **Blocker:** Joern binary not installed in environment (constraint `#6515`).
- **Resume condition:** Joern installed; `CpgSlice` phase (`src/cpg/slicer.rs`)
  can produce real CPG output instead of falling back to tree-sitter-only slicing.
- **Tests:** any code path depending on Joern must stay `#[ignore]` until then
  (rule `#6514`).

### T3.3 — TGI reasoning LLM server
- **Status:** blocked
- **Blocker:** TGI server not installed (constraint `#6516`).
- **Resume condition:** TGI endpoint available; `LlmConfig` in `src/config.rs`
  extended with `reasoning_endpoint` field.

---

## Paper-Integration Roadmap (P1-P5)

Five papers approved by the user on 2026-08-11. Each maps to one or more
existing scanner phases. All configs default to `enabled = false` so existing
behaviour is unchanged until the operator opts in.

References:
- P1: VulTriage — arXiv:2605.09461 — https://github.com/vinsontang1/VulTriage
- P2: VulnLLM-R  — arXiv:2512.07533 — https://github.com/ucsb-mlsec/VulnLLM-R
- P3: MoCQ       — arXiv:2504.16057 (Neuro-symbolic Static Analysis)
- P4: PacVD      — arXiv:2504.16877 (Context-Enhanced Vuln Detection)
- P5: AgentFlow  — arXiv:2604.20801

---

### P1 — VulTriage triple-path context augmentation

**Paper claim.** Augment the LLM input with three complementary context paths
before the final judgement. SOTA on PrimeVul pair test set; generalises to
Kotlin under low-resource and class-imbalanced settings.

**Three paths (verbatim from paper).**
1. **Control Path** — extract and verbalise AST + CFG + DFG information to
   expose control and data dependencies for the target function.
2. **Knowledge Path** — retrieve CWE-derived vulnerability patterns and
   examples via hybrid dense–sparse retrieval.
3. **Semantic Path** — produce a functional-behaviour summary of the code
   before the final vulnerability judgement.

The three contexts are concatenated into one unified instruction passed to the
LLM. Ablation study confirms each path contributes; removing any path degrades
precision or recall.

**Integration target.** `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`
(currently passes raw source + CWE prompt). The triple-path context must be
assembled before the LLM call and appended to the existing prompt.

**Sub-tasks.**

#### P1.1 — Control Path extractor [x]
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs` — add `build_control_path(fn_body, cpg)` call site before LLM dispatch
  - `src/llm_analysis.rs` (or new `src/context/control_path.rs`) — implement extractor
- **Inputs.** Function body source + existing CPG slice from `CpgSlice` phase (when Joern available) or tree-sitter AST fallback.
- **Outputs.** Verbalised string of the form:
  ```
  Control dependencies: <list>
  Data dependencies: <list>
  AST summary: <compressed AST>
  ```
- **Reuse.** Tree-sitter parsers already in repo; CPG slice from `src/cpg/slicer.rs`.
- **Acceptance criteria.** Given a sample function, returns a non-empty
  structured string; unit test asserts CFG nodes appear for an `if` statement.
- **Risk:** low.

#### P1.2 — Knowledge Path RAG over CWE patterns [x]
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs` — call `retrieve_cwe_patterns(cwe_id, fn_signature)` before LLM call
  - new `src/context/knowledge_path.rs` — hybrid dense-sparse retriever
  - `src/cwe/` (existing CWE routing module) — expose pattern corpus
- **Inputs.** CWE id (from `CweRouting` phase) + function signature.
- **Outputs.** Top-k CWE-derived vulnerability patterns and examples.
- **External dep.** An embedding model. Reuse existing `LlmConfig` embedding
  endpoint if present; otherwise add a `KnowledgePathConfig { enabled, embedding_endpoint, top_k }`.
- **Acceptance criteria.** For CWE-78 (OS Command Injection), returns ≥ 1
  example pattern; dense + sparse scores are combined.
- **Risk:** medium — needs embedding index; can be stubbed with sparse-only
  retrieval (BM25) as MVP.

#### P1.3 — Semantic Path summariser [x]
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs` — call `summarise_function(fn_body)` before final judgement
  - new `src/context/semantic_path.rs` — LLM summariser
- **Inputs.** Function body.
- **Outputs.** 1-3 sentence functional summary.
- **Reuse.** Same `LlmClient` used by `LlmStaticAnalysis` (smaller model OK).
- **Acceptance criteria.** Output is ≤ 60 tokens; unit test with a sample
  function returns a non-empty English summary.
- **Risk:** low — extra LLM call per function; gate behind `enabled` flag.

#### P1.4 — Config + docs [x]
- **Files to modify:**
  - `src/config.rs` — add `VultriageConfig { enabled: bool, control_path: bool, knowledge_path: bool, semantic_path: bool }` after `ValidateConfig`. Default all `false`.
  - `config/*.toml` example files — add `[vultriage]` section
  - `docs/configuration.md` — document the three flags
- **Acceptance criteria.** `cargo check` clean; existing tests unchanged
  (flag default off).
- **Risk:** low.

#### P1.5 — Wire triple-path into LlmStaticAnalysis prompt [x]
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs::run_llm_static_analysis` — when
    `config.vultriage.enabled`, assemble prompt as
    `[Control Path]\n[Knowledge Path]\n[Semantic Path]\n[Original code + CWE prompt]`
- **Acceptance criteria.** With `vultriage.enabled = true`, the LLM prompt
  includes the three labelled sections; with `false`, prompt is unchanged.
- **Depends on:** P1.1, P1.2, P1.3, P1.4.

---

### P2 — VulnLLM-R reasoning adapter + agent scaffold

**Paper claim.** First specialised reasoning LLM for vulnerability detection.
7B model distilled from DeepSeek-R1 + QwQ-32B outperforms commercial reasoning
LLMs and CodeQL/AFL++. 15 zero-days in real projects.

**Two reusable components.**

**A. Reasoning inference adapter.** Even without their fine-tuned weights, the
inference-time techniques are portable:
- **Truncated generation** — stop reasoning at a length cap, force final answer.
- **Policy-based generation** — query model 4× to get a CWE candidate set
  ("policy"), then re-query with the policy as additional context to pick one.
- **Summary-based reasoning** — query a summariser to compress the reasoning
  chain before the final answer.

**B. Agent scaffold.** For each target function:
1. Extract all functions along **three randomly sampled paths** from project
   entry point to the target in the call graph.
2. Provide these as initial context to the model.
3. Equip the model with a tool that retrieves function implementations by name.
4. Limit the number of interaction rounds to control inference cost.

**Integration target.**
- Reasoning adapter → `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`
  and `run_llm_verification` (any LLM call site).
- Agent scaffold → new option in `LlmStaticAnalysis` config, or extend
  `SecurityAgentVerification` phase in `src/scanner/phases/other_phases.rs`.

**Sub-tasks.**

#### P2.1 — Truncated generation option
- **Files to modify:**
  - `src/llm.rs` — add `max_reasoning_tokens: Option<u32>` to `LlmConfig` and to the request builder
  - `src/config.rs` — expose field in `LlmConfig`
- **Acceptance criteria.** When set, the LLM request includes the cap; when
  `None`, behaviour unchanged.
- **Risk:** low.

#### P2.2 — Policy-based generation
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs` — when `config.policy_sampling.enabled`,
    call the LLM 4 times, parse CWE candidates, then a 5th call with the
    policy in the prompt
  - `src/config.rs` — add `PolicySamplingConfig { enabled: bool, samples: u8 }`
    under `LlmPhasesConfig`
- **Acceptance criteria.** With flag on, produces a final CWE label from the
  policy set; with flag off, single call as today.
- **Risk:** medium — 5× LLM calls; must be opt-in.

#### P2.3 — Call-graph path sampler for agent scaffold
- **Files to modify:**
  - new `src/agent_scaffold/call_graph_paths.rs` — given a target function,
    sample 3 random paths from project entry points to it
  - reuse call graph built by `Indexing` phase (`src/scanner/phases/other_phases.rs::run_indexing`)
- **Inputs.** Call graph + target function id.
- **Outputs.** `Vec<Vec<FunctionId>>` of length 3.
- **Acceptance criteria.** For a call graph with ≥ 3 paths, returns 3 distinct
  paths; for fewer, returns what is available without panicking.
- **Risk:** medium — depends on call graph quality from `Indexing`.

#### P2.4 — Function-by-name retrieval tool
- **Files to modify:**
  - new `src/agent_scaffold/fn_lookup.rs` — index all functions by name; expose
    `lookup(name) -> Option<String>` returning the function body
  - `src/llm.rs` — add a tool-calling interface (or use the existing one if
    present)
- **Acceptance criteria.** Agent can request a function by name and receive its
  body; missing name returns `None`.
- **Risk:** low.

#### P2.5 — Wire agent scaffold into SecurityAgentVerification
- **Files to modify:**
  - `src/scanner/phases/other_phases.rs::run_security_agent_verification` (line 555-592 range per outline)
  - `src/config.rs` — add `AgentScaffoldConfig { enabled, max_rounds: u8, paths_per_target: u8 }`
- **Acceptance criteria.** With `agent_scaffold.enabled = true`, the phase
  builds the 3-path context + lookup tool per target function; with `false`,
  existing behaviour unchanged.
- **Depends on:** P2.3, P2.4.
- **Risk:** medium.

---

### P3 — MoCQ neuro-symbolic rule synthesis (RuleSynthesis 2.0)

**Paper claim.** LLM generates vulnerability-detection patterns in a DSL;
iterative refinement loop with trace-driven symbolic validation gives precise
feedback. Comparable to expert patterns; 46 new patterns + 25 zero-days. Hours
vs weeks of manual effort.

**Core algorithm.**
1. Extract the DSL for expressing vulnerability patterns (paper: 12 vuln types
   across C/C++, Java, PHP, JS).
2. LLM proposes a candidate pattern in the DSL given a CWE description.
3. Symbolic validator runs the pattern against a trace corpus; produces a
   structured feedback signal (which traces matched, which missed).
4. LLM rewrites the pattern using the feedback. Loop until validator accepts or
   budget exhausted.
5. Accepted patterns are emitted as Semgrep rules (baco's existing rule format).

**Integration target.** `src/scanner/phases/other_phases.rs::run_rule_synthesis`
(currently a thin wrapper at lines 940-1031). The current `RuleSynthesis` phase
is the natural home — MoCQ is its upgrade.

**Sub-tasks.**

#### P3.1 — Pattern DSL [x]
- **Files to modify:**
  - new `src/rulesynth/dsl.rs` — define the pattern DSL as Rust types
    (sink, source, sanitizer, path constraints, metavariables)
  - serialise to/from Semgrep YAML for emission
- **Acceptance criteria.** A round-trip `pattern → semgrep_yaml → pattern` is
  lossless for the 12 supported vuln types.
- **Risk:** medium.

#### P3.2 — Symbolal validator against trace corpus [x]
- **Files to modify:**
  - new `src/rulesynth/validator.rs` — given a candidate pattern, run it against
    a labelled trace corpus and return `{matched, missed, false_positives}`
  - trace corpus: reuse `tests/fixtures/` labelled samples
- **Acceptance criteria.** For a known-correct pattern for CWE-78, `matched ≥ 1`
  and `false_positives == 0` on the corpus.
- **Risk:** medium — needs a labelled corpus; start small (CWE-78, CWE-89).

#### P3.3 — LLM proposer with feedback loop [x]
- **Files to modify:**
  - `src/scanner/phases/other_phases.rs::run_rule_synthesis` — replace the
    current body with the propose→validate→rewrite loop
  - reuse `LlmClient` from `create_llm_client_with_metrics`
- **Acceptance criteria.** Within a budget of N iterations, the loop either
  emits an accepted Semgrep rule or reports failure; never loops indefinitely.
- **Depends on:** P3.1, P3.2.
- **Risk:** medium.

#### P3.4 — Emit accepted rules to disk [x]
- **Files to modify:**
  - `src/rulesynth/emitter.rs` — write accepted patterns to
    `output/synthesised_rules/<cwe>_<timestamp>.yml`
  - `Semgrep` phase (`run_semgrep`) — load synthesised rules alongside the
    bundled ones when present
- **Acceptance criteria.** A file is written on acceptance; the next `Semgrep`
  run picks it up.
- **Risk:** low.

#### P3.5 — Config + tests [x]
- **Files to modify:**
  - `src/config.rs` — extend `RulesynthConfig` with `mocq_mode: bool`,
    `max_iterations: u8`, `corpus_path: PathBuf`
  - `tests/unit/rulesynth_tests.rs` — add tests for the loop with a mock LLM
    returning a fixed candidate
- **Acceptance criteria.** `cargo test` passes; with `mocq_mode = false`, the
  old `RuleSynthesis` behaviour is preserved.
- **Risk:** low.

---

### P4 — PacVD primitive-API abstraction context

**Paper claim.** Abstract callee functions via primitive APIs (malloc, free,
open, close, …) at four granularity levels. Append abstraction to target
function, feed to LLM. With CoT + DeepSeek-R1: +12.77% accuracy, +10.05%
precision, +9.25% F1. Different models prefer different abstraction levels
(GPT-4/DeepSeek = high-level; CodeLLaMA = detailed).

**Core algorithm.**
1. Default analysis depth: 3 call layers (paper: 75% of inter-procedural
   vulns have call depth ≤ 3).
2. Build CPGs of the target function and all callees within 3 layers.
3. For each callee, extract four dimensions of primitive-API usage:
   - **Fuzzy Branches** — API called in all / some / no branches.
   - **Concrete Branches** — specific control conditions under which the API fires.
   - **Number of Calls** — count per primitive API.
   - **Key Variables** — identifiers operated on by the API.
4. Four abstraction levels:
   - Level 1: Fuzzy Branches only (highest abstraction)
   - Level 2: Concrete Branches
   - Level 3: Concrete Branches + Number of Calls
   - Level 4: Concrete Branches + Key Variables
5. Append the abstraction to the target function; feed to LLM.

**Primitive API table (from paper).**
| APIs                                  | Targeted vuln type                     |
|---------------------------------------|----------------------------------------|
| open/socket/fopen/fdopen/opendir/close/fclose/closedir | Resource Leak |
| malloc/realloc/calloc/localtime       | Null Pointer Dereference               |
| malloc/free                           | Memory Leak, UAF, Double Free          |

**Integration target.** `src/scanner/phases/llm_phases.rs::run_llm_static_analysis`.
The CPG slice from `CpgSlice` phase (when Joern available) or tree-sitter CFG
fallback provides the call graph. This is a strict superset of P1's Control Path
— P4 can be a more aggressive mode of the same prompt-augmentation hook.

**Sub-tasks.**

#### P4.1 — Primitive API catalogue [x]
- **Files to modify:**
  - new `src/context/primitive_api.rs` — const table of primitive APIs grouped
    by targeted vuln type (from the paper table above)
  - extend to language-specific APIs (Python: `open`, `os.system`; Java: `FileInputStream`, etc.)
- **Acceptance criteria.** `lookup("free")` returns `MemoryLeak | UAF | DoubleFree`.
- **Risk:** low.

#### P4.2 — Call-depth-3 callee walker [x]
- **Files to modify:**
  - new `src/context/callees.rs` — given a target function, return all callees
    within depth 3 via the call graph from `Indexing`/`CpgSlice`
- **Acceptance criteria.** For the CVE-2015-8962 example from the paper,
    returns `blk_end_request_all`, `sg_finish_rem_req`, `blk_finish_request`,
    `blk_put_request`, `mempool_free`, `free` within depth 3.
- **Risk:** medium — depends on call-graph quality.

#### P4.3 — Four-dimension extractor [x]
- **Files to modify:**
  - new `src/context/api_abstraction.rs` — for each callee, extract fuzzy
    branches, concrete branches, call counts, key variables
  - reuse CFG/DFG from tree-sitter or CPG
- **Acceptance criteria.** On the paper's CVE-2015-8962 example, the fuzzy
  branch abstraction matches the paper's stated output:
  `In blk_end_request_all: free called on all branches, malloc on no branch.`
- **Risk:** medium.

#### P4.4 — Level selector + prompt integration [x]
- **Files to modify:**
  - `src/scanner/phases/llm_phases.rs::run_llm_static_analysis` — when
    `config.pacvd.enabled`, assemble the abstraction at the configured level
    and prepend to the LLM prompt
  - `src/config.rs` — add `PacvdConfig { enabled: bool, level: u8 /* 1-4 */ }`
- **Acceptance criteria.** With `level = 1`, the prompt contains only fuzzy
  branch summaries; with `level = 4`, it contains concrete branches + key
  variables. With `enabled = false`, prompt unchanged.
- **Depends on:** P4.1, P4.2, P4.3.
- **Risk:** low.

#### P4.5 — Model-aware level auto-selection [x]
- **Files to modify:**
  - `src/config.rs` — add `auto_level: bool` to `PacvdConfig`
  - `src/scanner/phases/llm_phases.rs` — when `auto_level = true`, pick level
    based on `LlmConfig.model`: large reasoning models (DeepSeek-R1, o3-class)
    → level 1-2; code-tuned small models (CodeLLaMA-class) → level 3-4
- **Acceptance criteria.** A known model string maps to the expected level.
- **Risk:** low.

---

### P5 — AgentFlow typed-graph multi-agent harness synthesiser

**Paper claim.** Represent the multi-agent harness as a typed graph DSL. Search
over all 5 dimensions (agent roles A, communication topology G, message schemas
Σ, tool allocation Φ, coordination protocol Ψ) in one optimisation loop. Runtime
feedback (coverage, sanitizer, traces) diagnoses which part of the harness
failed. 84.3% on TerminalBench-2; 10 zero-days in Chrome including 2 critical
sandbox escapes.

**Five-component harness.** `H = (A, G, Σ, Φ, Ψ)`.
- A: agent set, each `(role, prompt, model, tools)`
- G ⊆ A × A: directed communication topology
- Σ: per-edge message schema (Jinja templates referencing upstream outputs + feedback channels)
- Φ: A → 2^Tools
- Ψ: coordination protocol (sequential, parallel, fan-out, retry-until-success)

**DSL core (from paper).**
- Node: `agent(role, prompt, model, tools)` or `fanout(node, k)`
- Edge: `n1 -> n2` (data) or `n1 ->_g n2` (guarded, g ∈ {ok, fail}); surface
  syntax `n.on_fail >> m`
- Feedback channels: `cov(line coverage)`, `branch`, `san(sanitizer)`,
  `trace(agent)`, `outcome(test)`
- Templates: Jinja-style `{{ analyst.out }}`, `{{ cov }}`, `{{ san }}`

**Well-formedness checks (type system).**
1. Every template variable resolves to an upstream output or feedback channel.
2. Every edge feeds a downstream prompt that actually references the upstream
   output.
3. The graph is connected (every node reachable from a source).

**Iterative loop.** propose → execute → observe → score → diagnose. The
diagnoser reads runtime signals to localise which part of the harness failed
(e.g. coverage shows the input never reached the vulnerable function; sanitizer
distinguishes a benign crash from the target vuln).

**Integration target.** `src/scanner/phases/other_phases.rs::run_security_agent_verification`
(lines 555-592 per outline). Today this phase runs a fixed multi-verifier
pipeline; AgentFlow would make the harness itself searchable. This is the most
invasive integration — start with a static (non-search) harness encoded in the
DSL, then add the search loop as a follow-up.

**Sub-tasks.**

#### P5.1 — Harness DSL types [x]
- **Files to modify:**
  - new `src/agent_flow/dsl.rs` — `Harness`, `Node`, `Edge`, `FeedbackChannel`,
    `Agent { role, prompt, model, tools }`, `Fanout(node, k)`
  - `src/agent_flow/mod.rs` — pub re-exports
- **Acceptance criteria.** The example harness from Figure 3 of the paper
  (analyst → fanout(explorer, 8) → validator, with `validator.on_fail >> analyst`)
  can be constructed in Rust.
- **Risk:** low.

#### P5.2 — Well-formedness checker [x]
- **Files to modify:**
  - `src/agent_flow/typecheck.rs` — implement rules T-Agent, T-Edge, T-Branch,
    T-Conn, T-Pipe from Figure 2 of the paper
- **Acceptance criteria.** Rejects a harness with an unresolved template
  variable; rejects a disconnected node; accepts the Figure 3 example.
- **Risk:** medium.

#### P5.3 — Runtime executor [x]
- **Files to modify:**
  - new `src/agent_flow/runtime.rs` — execute a well-formed harness: schedule
    agents per topology, bind template vars, dispatch tool calls, collect
    feedback channels
  - reuse `LlmClient` for agent dispatch
- **Inputs.** Well-formed harness + target program (source + build with
  coverage/sanitizer instrumentation).
- **Outputs.** Per-agent traces + final verdict + collected feedback bundle.
- **Acceptance criteria.** On a single-agent harness, returns the agent's
  output; on the Figure 3 harness, runs analyst → 8 explorers → validator in
  order, with retry on validator failure.
- **Risk:** high — coverage/sanitizer feedback requires build instrumentation
  that baco does not have today. Gate behind a `requires_instrumented_target`
  flag; fall back to stdout/stderr-only feedback when coverage is unavailable.

#### P5.4 — Diagnoser [x]
- **Files to modify:**
  - new `src/agent_flow/diagnose.rs` — given a failed run + feedback bundle,
    produce a structured diagnosis (e.g. "input never reached vulnerable
    function", "crash was benign", "harness repeats prior trial")
- **Acceptance criteria.** On a run where coverage shows the vulnerable
    function was never executed, the diagnosis names that as the failure mode.
- **Depends on:** P5.3.
- **Risk:** medium.

#### P5.5 — Proposer (search loop) [x]
- **Files to modify:**
  - new `src/agent_flow/propose.rs` — LLM-driven proposer that reads the
    diagnosis + archive of prior trials and emits a rewritten harness
  - `src/scanner/phases/other_phases.rs::run_security_agent_verification` —
    when `config.agent_flow.enabled`, run the propose→execute→diagnose loop
    for a budget of N iterations
  - `src/config.rs` — add `AgentFlowConfig { enabled, max_iterations: u8, requires_instrumented_target: bool }`
- **Acceptance criteria.** Within the budget, the loop either finds a crashing
    input or exhausts the budget; never runs forever.
- **Depends on:** P5.1, P5.2, P5.3, P5.4.
- **Risk:** high — full search loop is a research-grade system. Recommend
    shipping P5.1-P5.4 first (static harness execution), P5.5 last.

---

## Cross-Cutting (X.1-X.5) — already complete [x]

These are the previously-completed Cross-Cutting tasks, kept here for reference
per rule `#6453` (exactly five Cross-Cutting tasks).

- [x] X.1 — RationaleVerdict added to VulnerabilityFinding
- [x] X.2 — `statement_range` field on VulnerabilityFinding
- [x] X.3 — NormalizationConfig with ProjectBaseline
- [x] X.4 — Dataset hygiene rules (tests/fixtures/README.md)
- [x] X.5 — Fine-tuning guidelines (docs/fine-tuning-guidelines.md)

---

## Shared prerequisites for P1-P5

### PS1 — LLMClient tool-calling interface
- Several papers (P2.4, P5.3) need the LLM to call tools (function lookup,
  coverage query). Check whether `src/llm.rs` already supports tool calling;
  if not, add a `tools: Vec<ToolDef>` field to the request builder.
- **Files to inspect:** `src/llm.rs`, `src/llm_analysis.rs`.
- **Blocker for:** P2.4, P5.3.

### PS2 — Feedback channel collection
- AgentFlow needs coverage maps and sanitizer reports. These are not produced
  by any current phase. Add a `FeedbackCollector` trait with a no-op default
  and a real implementation gated behind `requires_instrumented_target`.
- **Blocker for:** P5.3, P5.4.

### PS3 — Call graph quality
- P1.1 (Control Path), P2.3 (call-graph path sampler), P4.2 (callee walker) all
  depend on a call graph. The `Indexing` phase produces one; verify its
  language coverage and edge cases (indirect calls, dynamic dispatch).
- **Blocker for:** P1.1, P2.3, P4.2.

### PS4 — Checkpoint transition test updates
- Per rule `#6422`, if any paper integration adds a new `ScanPhase`, all
  checkpoint transition tests in `tests/unit/checkpoint_resume_tests.rs` and
  `tests/unit/pipeline_ordering_tests.rs` must be updated to reflect the new
  `resume_from` sequence before CI can pass.
- Current phase count: 24. Any new phase requires renumbering and test updates.

### PS5 — CI gate (applies to every sub-task)
- Per rules `#5773`, `#5812`, `#5815`, `#5846`, `#5968`: every sub-task must
  end green on `cargo fmt --check && cargo clippy --all-targets -- -D warnings
  && cargo test`. No commit until the combined gate passes.

---

## Recommended execution order

1. **P1.4, P2.1, P3.5 (config scaffolding), P4.1, P5.1** — can run in
   parallel; all are low-risk and unblock the rest of their tracks.
2. **P1.1, P1.3, P4.1-P4.3** — context extractors; depend only on existing
   tree-sitter/CPG infra.
3. **P3.1, P3.2** — pattern DSL + validator; unblock P3.3.
4. **P2.3, P2.4** — call-graph sampler + function lookup; unblock P2.5.
5. **P5.2** — well-formedness checker; unblocks P5.3.
6. **P1.2, P1.5** — knowledge-path RAG (needs embedding endpoint); wire
   triple-path.
7. **P2.2, P2.5** — policy sampling + agent scaffold wiring.
8. **P3.3, P3.4** — proposer loop + emitter.
9. **P4.4, P4.5** — prompt integration + auto-level.
10. **P5.3, P5.4, P5.5** — runtime, diagnoser, proposer (highest risk; last).

---

## Open questions for the user

- Q1. **Embedding endpoint for P1.2 (Knowledge Path RAG).** Reuse the existing
  LLM provider's embedding API, or add a dedicated `embedding_endpoint` field?
- Q2. **P3 trace corpus.** Use the existing `tests/fixtures/` labelled samples
  as the initial corpus, or curate a separate `corpus/` directory?
- Q3. **P5 build instrumentation.** AgentFlow's full value needs coverage +
  sanitizer feedback, which requires building the target with instrumentation.
  Ship P5.1-P5.4 (static harness) first and defer P5.5 (search loop) until
  instrumentation is available, or invest in the instrumentation pipeline now?
- Q4. **P2 model weights.** VulnLLM-R's reasoning adapter techniques are
  portable, but the full value comes from their fine-tuned 7B model. Host the
  released weights locally, or apply only the inference-time techniques
  (truncated generation, policy sampling, summary-based reasoning) to the
  existing configured LLM?
