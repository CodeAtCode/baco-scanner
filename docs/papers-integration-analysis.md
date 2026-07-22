# LLM-Based Vulnerability Detection — Paper Survey & Integration Analysis for baco

> **Purpose**: Catalog of techniques from 30 papers and 7 projects surveyed from
> [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection),
> assessed for concrete integration into baco's Rust scanner.
>
> **Status**: Research synthesis — no implementation commitments. Each item ends with an
> adopt/defer/skip verdict with rationale.
>
> **Date**: July 2026

---

## 1. baco Today — Current Architecture (Baseline for Integration)

This is what baco already has. New techniques must fit this surface or explicitly extend it.

### 1.1 Phase dispatch
- Centralized in `src/scanner/phases.rs::run_phase` matching the `ScanPhase` enum (declared in `src/checkpoint.rs`).
- Adding a technique = extend the enum + add a match arm.

### 1.2 Existing phases

| Phase                    | File:lines                              | Technique        | Output                          |
| ------------------------ | --------------------------------------- | ---------------- | ------------------------------- |
| Indexing                 | `src/scanner/phases.rs:60-`             | static (hashing) | `FileIndex`, `FileHashStore`    |
| Semgrep                  | `src/scanner/phases.rs` + `src/semgrep/`| semgrep (CLI)    | `Vec<VulnerabilityFinding>`     |
| LlmStaticAnalysis        | `src/llm_analysis.rs:188-535`           | LLM (zero-shot)  | findings (JSON array)           |
| LlmDiscovery             | `src/scanner/phases.rs`                 | LLM              | findings                        |
| LlmVerification          | `src/llm_verification.rs:44-413`         | LLM + heuristic  | `VerificationResult`            |
| ConfidenceScoring        | `src/confidence.rs` + `confidence_refinement.rs` | static  | refined scores                  |
| TicketCrossRef           | `src/scanner/phases.rs:835-840` + `src/tickets/` | cross-ref | findings + `ticket_reference` |
| GitAnalysis              | `src/git_analysis.rs`                   | git2             | `commit_reference` per finding  |
| CrossFileAnalysis        | `src/prompt/templates.rs:328-352`       | LLM              | `cross_file_references`         |
| ThreatModeling           | `src/threat_model/`                     | static + LLM     | threat model                    |
| VariantSearch            | `src/variant_search.rs`                 | static           | variants                        |
| AgentVerification        | `src/agent/session.rs` + `src/phase/security_agent_verification.rs` | LLM agentic (tool-calling) | `AgentFinding` + PoC evidence |
| AiAggregation            | `src/report/ai_aggregation.rs`          | LLM              | aggregated groups               |
| ReportAggregation        | `src/report/aggregation.rs:81-`         | static           | `AggregationResult`             |
| Reporting                | `src/report/html.rs`, `src/report/json.rs` | rendering      | HTML/JSON                       |

### 1.3 LLM integration points

| File:lines             | Function                          | Provider/Model                                | Response parsing                       |
| ---------------------- | --------------------------------- | --------------------------------------------- | -------------------------------------- |
| `src/llm.rs:188-329`   | `try_chat_request`                | OpenAI-compatible `/v1/chat/completions`; round-robin `ModelSelector` | `choices[0].message.content` as string |
| `src/llm.rs:331-`      | `try_chat_with_tools_request`     | same client                                   | `choices[0].message` + `tool_calls`    |
| `src/llm_analysis.rs:197-330` | `LlmAnalyzer::analyze_file` | `LlmClient`                                   | JSON array with `before`/`after` snippets |
| `src/llm_verification.rs:44-413` | `ExtendedVerificationPhase::execute` | optional LLM                            | `VerificationResult` struct            |
| `src/agent/session.rs:49-437` | `AgentSession::analyze_file`, `verify_finding` | `AgentLlmClient` (tool-calling)        | JSON `{title,description,severity,cwe_id,...}` |
| `src/report/ai_aggregation.rs` | `AiAggregationPhase`        | LLM client                                    | structured aggregation output          |
| `src/multi_verifier.rs:40-208` | `MultiVerifier::verify`     | N independent verifiers                       | `VerifierVerdict` → `MajorityVerdict`  |

### 1.4 Confidence scoring

**Base** (`src/confidence.rs:6-46`) — 0-100 scale, additive boosts:
- Severity base: 80/60/40/20/10 (Critical/High/Medium/Low/Info)
- +10 has-source, +10 commit-ref, +10 ticket-ref, +15 multi-source, +5 high-severity, +20 verified

**Refinement** (`src/confidence_refinement.rs:230-369`) — 0-1 scale:
- Boosts: +0.15 verified by LLM, +0.10 multi-source, +0.08 cross-file, +0.10 historical pattern, +0.05 supports-vuln, +0.05 high-severity
- Penalties: -0.30 FP detected, -0.10 failed verify, -0.20 FP historical pattern, -0.15 contradicts, -0.10 test code, -0.15 third-party, -0.05 low-confidence source
- Historical patterns seeded for CWE-79, CWE-89, CWE-22

### 1.5 Finding model (`src/findings.rs:122-169`)

`VulnerabilityFinding` fields: `id`, `title`, `description`, `severity`, `confidence_score`,
`cwe_id`, `file_path`, `line_number`, `code_snippet`, `diff_hunk`, `recommendation`,
`code_location`, `already_reported`, `sources`, `commit_reference`, `ticket_reference`,
`priority_score`, `cross_file_references`, `verification_status`, `verification_notes`,
`verification_error`, `agent_evidence_path`, `security_issue`, `poc_code`, `mitigation_code`,
`poc_format`, `llm_model`, `agent_mode`.

Supporting: `Severity`, `VerificationStatus` (Confirmed/FalsePositive/NeedsReview/Failed),
`IssueCategory` (15 variants), `SecurityIssue` (category, cwe_id, owasp_category, mitre_attack, custom_tags).

### 1.6 Aggregation layers
1. `FindingsMerger` (`src/findings.rs:184-206`) — dedup by `id` (SHA256 of file+line+cwe)
2. `ReportAggregationPhase::deduplicate_findings` (`src/report/aggregation.rs:124-152`) — HashSet on `file:line:cwe`
3. `RootCauseDeduplicator` (`src/root_cause_dedup.rs:17-108`) — group by SHA256(title|path|normalized_snippet)
4. CVE dedup (`src/cve_client.rs:153-171`) — KEV priority over NVD by `cve_id`

### 1.7 Semgrep integration
- Files: `src/semgrep/{mod,runner,parser,rules}.rs`
- Severity: substring match on `check_id` (critical/high/medium/low) → baco severity
- No bundled rule files; relies on external semgrep + optional `config_path`
- `RawFinding` intermediate struct; multi-location aggregation per check_id

### 1.8 Advanced techniques — presence check

| Technique                         | Present? |
| --------------------------------- | -------- |
| Chain-of-thought prompting        | NO       |
| RAG / retrieval / vector store    | NO       |
| Few-shot examples in prompts      | NO       |
| AST usage (tree-sitter/syn)      | NO       |
| CFG construction                  | NO       |
| Call-graph analysis               | NO       |
| Code Property Graph (CPG)         | NO       |
| Fine-tuning                       | NO       |
| LLM tool calling / function calls| YES (`src/llm.rs:78-104`, `src/agent/session.rs:128-149`) |
| Multi-agent orchestration          | PARTIAL (`MultiVerifier` majority vote; single `AgentSession` loop) |
| Adversarial verification           | PARTIAL (cross-check + PoC test, no attacker/defender setup) |
| Data-flow / taint analysis         | **NOT PRESENT** (only LLM-prompted `cross_file_analysis_template`; no symbolic engine) |

### 1.9 Prompt inventory
All current prompts are zero-shot structured-output. Templates in two places:
- `src/prompts/phases/*.md` (markdown, `include_str!`)
- `src/prompt/templates.rs:98-499` (`DefaultPrompts`)

Override mechanism: `PromptEngine` (`src/prompt/engine.rs:20-213`) — per-phase config or file overrides. Common variables injected by `get_common_variables`.

**Key gap**: every LLM call is zero-shot, no context extraction, no retrieval, no program-analysis grounding.

---

## 2. Integration Opportunities — Cross-Paper Synthesis

The 30 papers + 7 projects converge on five themes baco can adopt. Ranked by impact × feasibility.

### 2.1 TOP 5 cross-paper recommendations

1. **Context-rich inputs + rationale validation** — Every LLM phase should receive data/control-flow context, cross-file references, and patch context; down-rank findings whose rationales fail an LLM-as-judge check.
   - Sources: [CORRECT (2504.13474)](https://arxiv.org/abs/2504.13474), [PrimeVul (2403.18624)](https://arxiv.org/abs/2403.18624)
   - baco gap: zero-shot prompts with no context extraction. High impact, low infra cost.

2. **MoE-style per-CWE / per-language routing** — Route by CWE family or language to specialized prompts/models. Maintain a registry of per-CWE experts.
   - Source: [MoEVD (2501.16454)](https://arxiv.org/abs/2501.16454) — +12.8% F1, +9-77.8% recall on long-tailed CWEs.
   - baco gap: single monolithic LLM phase. Fits phase-dispatch architecture cleanly.

3. **Specification/KB RAG (BM25, no vectors)** — Retrieve relevant security specs and prior patched examples, inject into LLM prompt.
   - Source: [VulInstruct (2511.04014)](https://arxiv.org/abs/2511.04014) — 45.0% F1, +32.7%, discovered CVE-2025-56538.
   - baco gap: no retrieval layer. BM25 fits "no-vector-store" constraint; CWE KB is JSON-serializable.

4. **Agentic FP filtering** — LLM triage step that filters static-analysis false positives; backbone strength dictates gains.
   - Source: [Sifting the Noise ISSTA 2026 (2601.22952)](https://arxiv.org/abs/2601.22952) — 92% FP → 6.3% with SOTA models.
   - baco gap: existing `ExtendedVerificationPhase` is the natural host; only needs a calibration layer.

5. **Statement/block-level confidence + multi-agent recon→find→verify→triage→patch** — Localize to statement level; loop agents to recover orthogonal signal.
   - Sources: [SecVulEval (2505.19828)](https://arxiv.org/abs/2505.19828), [Anthropic defending-code-harness](https://github.com/anthropics/defending-code-reference-harness)
   - baco gap: line-level findings only; `AgentSession` is single-agent. Architectural.

### 2.2 TOP 5 pitfalls to avoid

- **Semantic Trap** — Models that exploit surface text gaps fail on V2P (paired vulnerable/patched). Always evaluate on V2P, not just unpaired labels. [2601.22655](https://arxiv.org/abs/2601.22655)
- **Context-deprived evaluation** — Function-level-only evaluations are misleading. Include multi-file, patch, and execution context. [2504.13474](https://arxiv.org/abs/2504.13474), [2403.18624](https://arxiv.org/abs/2403.18624)
- **Misleading legacy benchmarks** — BigVul et al. inflate F1 by 22× vs PrimeVul. Distrust labels without provenance. [2403.18624](https://arxiv.org/abs/2403.18624)
- **Overconfident false positives** — User study: high FP rate + non-applicable fixes destroyed adoption. Calibrate confidence penalties; surface only high-consensus findings. [2412.14306](https://arxiv.org/abs/2412.14306)
- **"One-for-all" models** — Monolithic models collapse on long-tailed CWEs. Per-CWE/per-language specialization is non-optional. [2501.16454](https://arxiv.org/abs/2501.16454)

### 2.3 Cross-paper consensus on what works
- **Context windows matter most** — Performance improves with richer context regardless of model family.
- **Specialization > generality** — Code-aware or per-CWE experts beat general-purpose LLMs.
- **Rationale validation reduces hallucinations** — LLM-as-judge on rationales lowers FP from reasoning errors.
- **Agentic multi-agent loops recover orthogonal signal** — recon→find→verify→triage→patch improves localization.
- **Fine-tuning must avoid Semantic Trap** — V2P paired data + explicit control/data-flow reasoning required.

---

## 3. Paper-by-Paper Analysis

### Batch A — Agentic / Multi-Agent / Neuro-Symbolic (10 papers)

#### A1. QRS: Rule-Synthesizing Neuro-Symbolic Triad
- **Source**: [arxiv:2602.09774](https://arxiv.org/abs/2602.09774) · 2026
- **Technique**: Three agents (Query/Review/Sanitize) generate CodeQL queries from a schema + few-shot, validate semantically, confirm via exploit synthesis.
- **Insight**: LLM-generated queries + on-the-fly exploit synthesis escape manual-rule limits and suppress FPs without retraining.
- **Integrability**: **HIGH** — LLM→semgrep rule compiler as a new phase; exploit results feed confidence boosts.

- **Verdict**: **ADOPT** — leverages existing semgrep layer with agentic upgrade path.

#### A2. AgentFlow (Multi-Agent Harnesses)
- **Source**: [arxiv:2604.20801](https://arxiv.org/abs/2604.20801) · [code](https://github.com/berabuddies/agentflow) · 2026
- **Technique**: Typed graph DSL over agent roles/prompts/tools/communication; runtime feedback rewrites the harness.
- **Integrability**: MEDIUM — could replace fixed phase topology; needs Python interop.
- **Verdict**: **DEFER** — Python-only; revisit once Rust interop stabilizes.

#### A3. Sifting the Noise (ISSTA 2026)
- **Source**: [arxiv:2601.22952](https://arxiv.org/abs/2601.22952)
- **Technique**: Comparative study of Aider/OpenHands/SWE-agent filtering CodeQL FPs in Java; 92% FP → 6.3% with SOTA backbones.
- **Insight**: Backbone strength dictates agent utility; weaker models need guided prompting.
- **Integrability**: **HIGH** — embed triage prompt template; statistical trust layer demotes FP triples in `confidence_refinement.rs`.
- **Verdict**: **ADOPT** — tiny high-impact integration.

#### A4. AgenticSCR
- **Source**: [arxiv:2601.19138](https://arxiv.org/abs/2601.19138)
- **Technique**: Security-focused semantic memory + agentic loops for "immature" pre-commit vulnerabilities.
- **Integrability**: MEDIUM — new phase with persistent KV/vector store.
- **Verdict**: **DEFER** — niche; wait for phase loop stabilization.

#### A5. MulVul
- **Source**: [arxiv:2601.18847](https://arxiv.org/abs/2601.18847)
- **Technique**: Router agent picks CWE classes, specialized detectors use RAG; cross-model prompt evolution (generator vs executor).
- **Insight**: Decoupled prompt optimization avoids self-correction bias — +51.6% prompt quality.
- **Integrability**: MEDIUM — semgrep rule generation via prompt evolution; validate via `semgrep --validate`.
- **Verdict**: **ADOPT** — big jump in rule coverage.

#### A6. VulnLLM-R
- **Source**: [arxiv:2512.07533](https://arxiv.org/abs/2512.07533) · [code](https://github.com/ucsb-mlsec/VulnLLM-R)
- **Technique**: Fine-tuned 7B reasoning LLM + agent scaffold; 0-day discoveries surpassing CodeQL/AFL++.
- **Integrability**: LOW — would need GPU cluster + vLLM serve; Rust GPU inference not native.
- **Verdict**: **SKIP** for baco; consume as external service if ever needed.

#### A7. MoCQ (Neuro-symbolic Static Analysis)
- **Source**: [arxiv:2504.16057](https://arxiv.org/abs/2504.16057)
- **Technique**: LLM generates vulnerability patterns, symbolic engine validates, iterative refinement eliminates hallucinations. 46 new rules + 25 unknown CVEs.
- **Integrability**: **HIGH** — run MoCQ as cargo task emitting `.sgql`/semgrep rule files; fits baco's cargo-based build.

- **Verdict**: **ADOPT** — rapid F-score uplift, minimal deps.

#### A8. OpenAnt (Knostic)
- **Source**: [code](https://github.com/knostic/OpenAnt)
- **Technique**: Five-stage detect→attack→verify→report→audit pipeline; multi-provider; "what survives is real".
- **Integrability**: MEDIUM — UniFFI bindings, heavy interop.
- **Verdict**: **DEFER** — architectural impact too large for now.

#### A9. AutoCVE
- **Source**: [code](https://github.com/larlarua/AutoCVE) · AGPL-3.0
- **Technique**: Four agents (Recon/Scan/Triage/Finding) with ReAct loop; runs are additive and merge-safe.
- **Integrability**: **HIGH** — adopt dedup/FP-filter layer as first-class merge stage; aligns with `FindingsMerger`/`RootCauseDeduplicator`.

- **Verdict**: **ADOPT** — aligns with baco's aggregation goals.

#### A10. Cloudflare security-audit-skill
- **Source**: [code](https://github.com/cloudflare/security-audit-skill) · MIT
- **Technique**: Six-phase parallel pipeline (Recon/Hunt/Validate/Report/Structured/Independent-verify). "Only report what you can exploit." ~2x discovery from fresh independent verification.
- **Integrability**: **HIGH** — restructure `PhaseOrchestrator` to 6-step graph; cherry-pick attack-class prompts into `LlmStaticAnalysisPhase`; add validation schema.

- **Verdict**: **ADOPT** — high-impact refactor of orchestration.

### Batch B — Context / CPG / RAG / Reasoning (10 papers)

#### B1. VulTriage (Triple-Path Context Augmentation)
- **Source**: [arxiv:2605.09461](https://arxiv.org/abs/2605.09461) · [code](https://github.com/vinsontang1/VulTriage)
- **Technique**: Control Path (AST/CFG/DFG verbalized), Knowledge Path (CWE KB hybrid dense-sparse retrieval), Semantic Path (functional summary) — three contexts injected into prompt with strict Yes/No output.
- **Integrability**: **HIGH** — new context-builder module before the LLM phase; BM25 for Knowledge Path fits no-vector-store constraint.

- **Verdict**: **ADOPT** — Control Path directly addresses baco's missing data-flow grounding.

#### B2. LLMxCPG (Usenix 2025)
- **Source**: [arxiv:2507.16585](https://arxiv.org/abs/2507.16585) · [code](https://github.com/qcri/llmxcpg)
- **Technique**: LLMxCPG-Q generates CPGQL queries → CPG slice extraction (67-91% code reduction) → LLMxCPG-D classifies the slice.
- **Integrability**: **HIGH** — CPG context builder feeding existing LLM phase; needs Joern CPG engine in subprocess.

- **Verdict**: **ADOPT** — complements data-flow + multi-file correlation; highest quality gain in the batch.

#### B3. Learning to Focus (FocusVul)
- **Source**: [arxiv:2505.17460](https://arxiv.org/abs/2505.17460) · **WITHDRAWN**
- **Technique**: Learn region selection from commit annotations; extract dependency/execution-flow context.
- **Verdict**: **SKIP** — paper withdrawn; code inaccessible; approach depends on commit annotations unavailable at inference.

#### B4. Context-Enhanced Vulnerability Detection
- **Source**: [arxiv:2504.16877](https://arxiv.org/abs/2504.16877)
- **Technique**: Program analysis extracts context at variable/function/module/project levels; inject with code into LLM. Sweeps GPT-4/DeepSeek/CodeLLaMA across zero-shot/ICL/few-shot.
- **Insight**: Filtered abstracted context beats raw-code prompts; best level varies by model.
- **Integrability**: **MEDIUM** — Rust module emitting hierarchical AST/function/module summaries into prompts.

- **Verdict**: **ADOPT** — low-friction modular add-on, incremental.

#### B5. SV-TrustEval-C (SP 2025)
- **Source**: [arxiv:2505.20630](https://arxiv.org/abs/2505.20630) · [code](https://github.com/Jackline97/SV-TrustEval-C)
- **Technique**: Benchmark with Structure-Oriented Variants Generator perturbing DFG/CFG; 9,401 Q&A pairs across 82 CWEs. Shows LLMs rely on pattern-matching, struggle with structural/semantic reasoning.
- **Integrability**: MEDIUM — evaluation suite for baco's regression tests, not runtime.
- **Verdict**: **ADOPT as evaluation suite** — alerts when models regress to pattern-matching.

#### B6. LLM-based Vulnerability Detection at Project Scale
- **Source**: [arxiv:2601.19239](https://arxiv.org/abs/2601.19239)
- **Technique**: Empirical study of 5 detectors + 2 traditional tools on 222 real-world vulns; manual inspection of 385 warnings.
- **Key finding**: LLM detectors have low recall but higher unique discoveries; huge FP rates; shallow inter-procedural reasoning and source/sink misidentification are top failure causes.
- **Verdict**: **DEFER as cautionary study** — confirms baco's multi-source/cross-file boosts and FP penalties are correct mitigations.

#### B7. VULPO
- **Source**: [arxiv:2511.11896](https://arxiv.org/abs/2511.11896)
- **Technique**: ContextVul dataset + cold-start SFT + on-policy RL with multi-dimensional rewards (identification/localization/reasoning). VULPO-4B beats 150%-larger baseline.
- **Integrability**: MEDIUM — long-term training pipeline, not runtime.
- **Verdict**: **DEFER** — interesting future fine-tuning, not current runtime.

#### B8. R2Vul
- **Source**: [arxiv:2504.04699](https://arxiv.org/abs/2504.04699) · [code](https://github.com/martin-wey/R2Vul) · MIT
- **Technique**: Structured reasoning distillation via paired vulnerable/patched functions; SFT/ORPO fine-tune Qwen2.5-Coder.
- **Integrability**: MEDIUM — optional specialized LLM via TGI serving for explainability.
- **Verdict**: **DEFER** — needs GPU infra; defer to future explainability work.

#### B9. VulInstruct (FSE 2026)
- **Source**: [arxiv:2511.04014](https://arxiv.org/abs/2511.04014)
- **Technique**: Specification KB (general cross-project + domain-specific intra-repo) retrieved and injected; root-cause reasoning over security specs. 45.0% F1 (+32.7%), discovered CVE-2025-56538.
- **Integrability**: **MEDIUM-HIGH** — Rust module with CWE KB (JSON) + BM25 retrieval; inject top specs into LLM prompt.

- **Verdict**: **ADOPT** — fits baco's no-vector-store default; high FP reduction.

#### B10. DeepAudit
- **Source**: [code](https://github.com/lintsinghua/DeepAudit) · AGPL-3.0
- **Technique**: Multi-agent red-team platform (Orchestrator/Recon/Analysis/Verification) with RAG + Docker PoC sandbox. 49 CVEs + 6 GHSA in 17 projects.
- **Integrability**: LOW — full platform, diverges from baco's monolithic Rust design.
- **Verdict**: **SKIP** — too large and divergent.

### Batch C — Surveys / Benchmarks / Insights (10 papers)

#### C1. CORRECT (Everything You Wanted to Know)
- **Source**: [arxiv:2504.13474](https://arxiv.org/abs/2504.13474)
- **Type**: empirical study
- **Finding**: Prior evaluations understate LLMs by using isolated functions; with context (CORRECT framework, 99 CWEs, 13 LLMs) SOTA reaches 0.7 F1 / 0.8 precision. FPs stem from reasoning errors. Overthinking bias exists.
- **Takeaway**: Use context-rich inputs; boost confidence only when rationales pass LLM-as-judge; avoid scale-only improvements.
- **Verdict**: **ADOPT-INSIGHT** — core "context + validation" lesson.

#### C2. LLMs in Software Security (Survey)
- **Source**: [arxiv:2502.07049](https://arxiv.org/abs/2502.07049) · [code](https://github.com/OwenSanzas/LLM-For-Software-Security)
- **Type**: survey
- **Finding**: Catalogs architectures/methods/languages/fine-tuning/datasets. Gaps: cross-language, multimodal, repo-level.
- **Takeaway**: Prefer code-aware/frontier models; build multi-language support early with per-language adapters.
- **Verdict**: **ADOPT-INSIGHT**.

#### C3. Systematic Literature Review
- **Source**: [arxiv:2507.22659](https://arxiv.org/abs/2507.22659) · [code](https://github.com/hs-esslingen-it-security/Awesome-LLM4SVD)
- **Type**: SLR (263 studies, 2020-2025)
- **Finding**: Dataset mislabeling/leakage, weak generalization, scarce reproducibility.
- **Takeaway**: Strict data hygiene (chronological splits, dedup), standardized cross-context evaluation.
- **Verdict**: **ADOPT-INSIGHT** — informs any future dataset/eval pipeline.

#### C4. From Large to Mammoth (NDSS 2025)
- **Source**: [NDSS](https://www.ndss-symposium.org/ndss-paper/from-large-to-mammoth-a-comparative-evaluation-of-large-language-models-in-vulnerability-detection/)
- **Type**: benchmark
- **Finding**: LLaMA-2/3, CodeLLaMA, Mistral, Mixtral, Gemma, CodeGemma, Phi-2/3, GPT-4 vary wildly; some no better than random. Context window size matters most; model size/quantization limited benefit. Few-shot is task/language-dependent.
- **Takeaway**: Prioritize large context windows; per-language prompt specialization.
- **Verdict**: **DEFER as one data point** — don't adopt wholesale without local validation.

#### C5. MoEVD (One-for-All Does Not Work)
- **Source**: [arxiv:2501.16454](https://arxiv.org/abs/2501.16454) · FSE 2025
- **Type**: system
- **Finding**: Two-stage CWE-type routing then CWE-specific experts: +12.8% F1, +9-77.8% recall, especially on long-tailed CWEs.
- **Takeaway**: MoE routing by CWE family/language; per-CWE expert registry.
- **Verdict**: **ADOPT-INSIGHT** — aligns with baco's phase architecture.

#### C6. Semantic Trap Investigation
- **Source**: [arxiv:2601.22655](https://arxiv.org/abs/2601.22655)
- **Type**: empirical
- **Finding**: Vanilla SFT shows V2N/V2P gap; CoT reduces symptoms but can drop recall to floor; models still misread control flow + hallucinate APIs.
- **Takeaway**: If fine-tuning, emphasize root-cause reasoning (control/data flow + patch alignment); always evaluate on V2P.
- **Verdict**: **ADOPT-INSIGHT** — critical warning for any future fine-tuning.

#### C7. PrimeVul (How Far Are We?)
- **Source**: [arxiv:2403.18624](https://arxiv.org/abs/2403.18624) · ICSE 2025 · [code](https://github.com/DLVulDet/PrimeVul)
- **Type**: benchmark/system
- **Finding**: SOTA models score 3.09% F1 on PrimeVul vs 68.26% on BigVul — legacy benchmarks overestimate by 22×. Even GPT-4 near random.
- **Takeaway**: Distrust legacy labels; chronological splits, dedup, cross-context labels; default to cautious reporting.
- **Verdict**: **ADOPT-INSIGHT** — dataset hygiene methodology.

#### C8. SecVulEval
- **Source**: [arxiv:2505.19828](https://arxiv.org/abs/2505.19828)
- **Type**: benchmark
- **Finding**: 25,440 functions / 5,867 CVEs at statement level; best LLM (Claude-3.7-Sonnet) only 23.83% F1 with correct reasoning.
- **Takeaway**: Statement/block-level confidence; multi-agent recon→localize→verify→triage loop.
- **Verdict**: **ADOPT-INSIGHT** — aligns with baco's granular aggregation.

#### C9. Closing the Gap (User Study, ICSE 2025)
- **Source**: [arxiv:2412.14306](https://arxiv.org/abs/2412.14306)
- **Type**: user study
- **Finding**: DeepVulGuard scanned 24 projects → 170 alerts, 50 fixes, but high FP + non-applicable fixes made it impractical. Confidence scores mismatched reality.
- **Takeaway**: Calibrate confidence with post-hoc normalization (dedup, threat-model alignment); surface only high-consensus findings; per-project normalization tiers; include data/control flow + patch alignment in alerts.
- **Verdict**: **ADOPT-INSIGHT** — UX and confidence calibration guidance.

#### C10. Anthropic defending-code-reference-harness
- **Source**: [code](https://github.com/anthropics/defending-code-reference-harness)
- **Type**: reference implementation
- **Finding**: Autonomous recon→find→verify→report→patch loop with Dockerized sandbox; `/triage` skill dedup; patch validation via sandboxed execution.
- **Takeaway**: Isolate each phase; sandbox execution; mirror agent/phase registry on baco's phases.
- **Verdict**: **ADOPT-INSIGHT** — validated orchestration/sandbox pattern.

---

## 4. Recommended Integration Roadmap

Sequenced by dependency and ROI. Each item is bounded to a phase-style change.

### Tier 1

| # | Technique                          | Source paper          | baco target                                        |
|---|------------------------------------|-----------------------|----------------------------------------------------|
| 1 | Agentic FP filter prompt + trust   | Sifting the Noise     | `src/llm_verification.rs` + `confidence_refinement.rs` |
| 2 | Hierarchical context extraction    | Context-Enhanced Vuln | new `src/context/` module feeding LLM phase prompts |
| 3 | CWE KB RAG (BM25, JSON)            | VulInstruct           | new retrieval module + prompt injection            |
| 4 | SV-TrustEval-C regression suite    | SV-TrustEval-C        | `tests/integration/` benchmark import              |

### Tier 2

| # | Technique                          | Source paper          | baco target                                        |
|---|------------------------------------|-----------------------|----------------------------------------------------|
| 5 | MoE per-CWE/language routing       | MoEVD                 | new router before `LlmStaticAnalysisPhase`         |
| 6 | Triple-path context (AST/CFG/DFG)  | VulTriage              | new context-builder phase + tree-sitter dep        |
| 7 | LLM→semgrep rule synthesis (MoCQ)  | MoCQ                  | new phase emitting `.yml` rules                    |
| 8 | AutoCVE-style merge + FP suppression | AutoCVE             | `FindingsMerger` + `RootCauseDeduplicator`          |
| 9 | Six-phase parallel orchestration   | Cloudflare skill      | `PhaseOrchestrator` restructure                    |

### Tier 3

| #  | Technique                          | Source paper          | baco target                                        |
|----|------------------------------------|-----------------------|----------------------------------------------------|
| 10 | CPG-guided slicing (LLMxCPG)       | LLMxCPG (Usenix 2025) | CPG engine subprocess + slice-based LLM phase      |
| 11 | Adversarial exploit synthesis      | QRS                   | new phase + exploit harness bindings               |
| 12 | Specialized reasoning LLM (R2Vul/VULPO) | R2Vul / VULPO    | external TGI-served model as new provider          |

### Explicitly deferred / skipped

- **AgentFlow** — Python-only, defer until Rust interop stabilizes.
- **AgenticSCR** — niche pre-commit case, defer.
- **VulnLLM-R** — GPU cluster required, skip (consume as external service).
- **OpenAnt** — heavy UniFFI build, defer.
- **DeepAudit** — too large/divergent, skip.
- **FocusVul** — paper withdrawn, skip.

---

## 5. Open Source References

| Project        | License   | URL                                                                              |
| -------------- | --------- | -------------------------------------------------------------------------------- |
| VulTriage      | -         | https://github.com/vinsontang1/VulTriage                                         |
| LLMxCPG        | -         | https://github.com/qcri/llmxcpg                                                   |
| R2Vul          | MIT       | https://github.com/martin-wey/R2Vul                                               |
| VulnLLM-R      | Apache-2.0| https://github.com/ucsb-mlsec/VulnLLM-R                                          |
| PrimeVul       | -         | https://github.com/DLVulDet/PrimeVul                                              |
| AutoCVE         | AGPL-3.0  | https://github.com/larlarua/AutoCVE                                               |
| OpenAnt        | -         | https://github.com/knostic/OpenAnt                                                |
| DeepAudit      | AGPL-3.0  | https://github.com/lintsinghua/DeepAudit                                           |
| Cloudflare skill | MIT     | https://github.com/cloudflare/security-audit-skill                                |
| Anthropic harness | -      | https://github.com/anthropics/defending-code-reference-harness                    |
| AgentFlow      | MIT       | https://github.com/berabuddies/agentflow                                          |
| SV-TrustEval-C | -        | https://github.com/Jackline97/SV-TrustEval-C                                      |
| SecVulEval     | -         | https://github.com/basimbd/secvuleval                                             |
| LLM-For-Software-Security | - | https://github.com/OwenSanzas/LLM-For-Software-Security                          |
| Awesome-LLM4SVD | -        | https://github.com/hs-esslingen-it-security/Awesome-LLM4SVD                       |

---

## 6. Methodology

- 4 parallel subagents: 1 explorer (baco architecture map) + 3 librarians (10 papers each).
- Papers sourced from [huhusmang/Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection).
- Each paper fetched from arxiv abstract page; PDF fetched when deeper detail was needed.
- GitHub projects fetched via README.
- INACCESSIBLE marked where paywall/404/withdrawn — no content invented.
- All file paths in §1 verified against the baco repository at `/media/mte90/Doh-cker/projects/baco`.

## 7. Gaps in baco This Survey Highlights

1. **No data-flow/taint engine** — only LLM-prompted cross-file analysis. Every paper on context/CPG (B1, B2, B4, B9) says this is the single biggest accuracy lever.
2. **All prompts zero-shot** — no few-shot, no CoT, no rationale validation. CORRECT (C1) shows this is the cheapest win.
3. **No retrieval/KB layer** — VulInstruct (B9) and VulTriage (B1) show specification RAG cuts FP sharply without vector stores.
4. **No per-CWE specialization** — MoEVD (C5) shows monolithic models collapse on long-tailed CWEs.
5. **No structured agentic loop** — `AgentSession` is single-agent; Cloudflare/Anthropic/OpenAnt show multi-agent parallel + adversarial loops give ~2x discovery.
6. **No statement-level localization** — SecVulEval (C8) shows function-level findings miss real patterns.
7. **No benchmark/regression suite for LLM phase quality** — SV-TrustEval-C (B5) and PrimeVul (C7) provide ready-made rigor.
