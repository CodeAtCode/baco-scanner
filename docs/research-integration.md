# Research-Backed Design

BACO's LLM integration is informed by a survey of 30 papers and 7 projects from
[Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection).
This document describes which techniques were integrated and why.

---

## Integrated Papers

### Tier 1 — Quick Wins

These papers provide high-impact integrations with minimal infrastructure cost.

#### Sifting the Noise (ISSTA 2026)
- **arxiv:** [2601.22952](https://arxiv.org/abs/2601.22952)
- **Technique:** Agentic false-positive filtering using LLM triage to filter static analysis findings.
- **Why integrated:** Reduces FP rates from 92% to 6.3% with SOTA models. Provides a lightweight calibration layer that fits naturally into existing verification flows.
- **What it enables:** An agentic FP filter that routes findings through a triage step before final reporting, dramatically improving signal-to-noise ratio.

#### Context-Enhanced Vulnerability Detection
- **arxiv:** [2504.16877](https://arxiv.org/abs/2504.16877)
- **Technique:** Program analysis extracts context at variable, function, module, and project levels; injects filtered abstracted context with code into LLM prompts.
- **Why integrated:** Filtered abstracted context beats raw-code prompts; best context level varies by model. Addresses baco's gap of zero-shot prompts with no context extraction.
- **What it enables:** Hierarchical context extraction that provides richer inputs to LLM phases, improving detection accuracy across model families.

#### VulInstruct (FSE 2026)
- **arxiv:** [2511.04014](https://arxiv.org/abs/2511.04014)
- **Technique:** Specification knowledge base (general cross-project + domain-specific intra-repo) retrieved via BM25 and injected into LLM prompts with root-cause reasoning over security specs. Achieved 45.0% F1 (+32.7%) and discovered CVE-2025-56538.
- **Why integrated:** Shows specification RAG cuts FP sharply without vector stores. Fits baco's no-vector-store constraint; CWE KB is JSON-serializable.
- **What it enables:** CWE KB RAG using BM25 retrieval that injects relevant security specs and prior patched examples into LLM prompts.

#### SV-TrustEval-C (SP 2025)
- **arxiv:** [2505.20630](https://arxiv.org/abs/2505.20630)
- **Technique:** Benchmark with Structure-Oriented Variants Generator perturbing DFG/CFG; 9,401 Q&A pairs across 82 CWEs. Shows LLMs rely on pattern-matching and struggle with structural/semantic reasoning.
- **Why integrated:** Provides evaluation suite for regression testing; alerts when models regress to pattern-matching.
- **What it enables:** A regression suite that validates LLM phase quality and ensures structural reasoning capabilities are maintained.

---

### Tier 2 — Structural Improvements

These papers require architectural changes but deliver significant quality gains.

#### MoEVD (FSE 2025)
- **arxiv:** [2501.16454](https://arxiv.org/abs/2501.16454)
- **Technique:** Two-stage mixture-of-experts approach: CWE-type routing followed by CWE-specific experts. Achieved +12.8% F1 and +9-77.8% recall, especially on long-tailed CWEs.
- **Why integrated:** Shows monolithic models collapse on long-tailed CWEs; per-CWE specialization is non-optional. Fits baco's phase-dispatch architecture cleanly.
- **What it enables:** MoE-style per-CWE and per-language routing that maintains a registry of specialized prompts/models, improving detection for rare vulnerability classes.

#### VulTriage
- **arxiv:** [2605.09461](https://arxiv.org/abs/2605.09461)
- **Technique:** Triple-path context augmentation: Control Path (AST/CFG/DFG verbalized), Knowledge Path (CWE KB hybrid dense-sparse retrieval), Semantic Path (functional summary) — three contexts injected into prompt with strict Yes/No output.
- **Why integrated:** Control Path directly addresses baco's missing data-flow grounding. High integrability with new context-builder module.
- **What it enables:** Triple-path context extraction (AST/CFG/DFG) that provides program analysis grounding for LLM verification.

#### MoCQ
- **arxiv:** [2504.16057](https://arxiv.org/abs/2504.16057)
- **Technique:** LLM generates vulnerability patterns, symbolic engine validates, iterative refinement eliminates hallucinations. Produced 46 new rules and discovered 25 unknown CVEs.
- **Why integrated:** LLM-to-semgrep rule synthesis fits baco's cargo-based build; rapid F-score uplift with minimal dependencies.
- **What it enables:** LLM-driven semgrep rule synthesis that automatically generates and validates vulnerability patterns.

#### AutoCVE
- **code:** [larlarua/AutoCVE](https://github.com/larlarua/AutoCVE)
- **Technique:** Four agents (Recon/Scan/Triage/Finding) with ReAct loop; runs are additive and merge-safe.
- **Why integrated:** Aligns with baco's aggregation goals; provides dedup/FP-filter layer as first-class merge stage.
- **What it enables:** Global false-positive suppression through multi-agent deduplication and merge-safe finding aggregation.

#### Cloudflare security-audit-skill
- **code:** [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
- **Technique:** Six-phase parallel pipeline (Recon/Hunt/Validate/Report/Structured/Independent-verify) with principle "only report what you can exploit." Achieved ~2x discovery from fresh independent verification.
- **Why integrated:** High-impact orchestration pattern; restructures pipeline to 6-step graph with independent verification.
- **What it enables:** Six-phase parallel orchestration with independent verification that doubles discovery rates.

---

### Tier 3 — Infrastructure

These papers require significant infrastructure investment but provide foundational capabilities.

#### LLMxCPG (Usenix 2025)
- **arxiv:** [2507.16585](https://arxiv.org/abs/2507.16585)
- **Technique:** LLMxCPG-Q generates CPGQL queries for Code Property Graph slice extraction (67-91% code reduction) → LLMxCPG-D classifies the slice.
- **Why integrated:** Complements data-flow and multi-file correlation; highest quality gain in the batch. Requires Joern CPG engine as subprocess.
- **What it enables:** CPG-guided slicing that dramatically reduces code volume for LLM analysis while preserving vulnerability-relevant context.

#### QRS
- **arxiv:** [2602.09774](https://arxiv.org/abs/2602.09774)
- **Technique:** Three agents (Query/Review/Sanitize) generate CodeQL queries from schema + few-shot, validate semantically, confirm via exploit synthesis.
- **Why integrated:** LLM-to-rule compiler with on-the-fly exploit synthesis escapes manual-rule limits and suppresses FPs without retraining.
- **What it enables:** Adversarial exploit synthesis that validates generated rules and provides proof-of-concept evidence.

#### R2Vul + VULPO
- **arxiv:** [2504.04699](https://arxiv.org/abs/2504.04699) + [2511.11896](https://arxiv.org/abs/2511.11896)
- **Technique:** R2Vul uses structured reasoning distillation via paired vulnerable/patched functions; VULPO adds context-aware RL with multi-dimensional rewards for identification/localization/reasoning.
- **Why integrated:** Provides specialized reasoning LLM for explainability; optional TGI-served model as new provider.
- **What it enables:** Specialized reasoning models that improve explainability and root-cause analysis for detected vulnerabilities.

---

### Cross-Cutting Insights

These papers provide methodological guidance applied across multiple components.

| Insight | Paper | Application |
|---------|-------|-------------|
| Rationale validation via LLM-as-judge | CORRECT — [2504.13474](https://arxiv.org/abs/2504.13474) | Down-rank findings whose rationales fail an LLM-as-judge check; reduces hallucinations from reasoning errors. |
| Statement-level localization | SecVulEval — [2505.19828](https://arxiv.org/abs/2505.19828) | Move from line-level to statement/block-level confidence; best LLM achieved only 23.83% F1 with correct reasoning at this granularity. |
| Dataset hygiene (chronological splits) | PrimeVul (ICSE 2025) — [2403.18624](https://arxiv.org/abs/2403.18624) | Legacy benchmarks overestimate by 22×; enforce chronological splits, dedup, and cross-context labels. |
| Confidence calibration per user study | Closing the Gap (ICSE 2025) — [2412.14306](https://arxiv.org/abs/2412.14306) | High FP rates + non-applicable fixes destroyed adoption; calibrate confidence with post-hoc normalization and surface only high-consensus findings. |
| Semantic Trap guard for fine-tuning | Semantic Trap — [2601.22655](https://arxiv.org/abs/2601.22655) | Vanilla SFT shows V2N/V2P gap; if fine-tuning, emphasize root-cause reasoning (control/data flow + patch alignment) and always evaluate on V2P paired data. |

---

## Surveyed but Not Integrated

Papers assessed but deferred or skipped, with rationale.

| Paper | Verdict | Rationale |
|-------|---------|-----------|
| AgentFlow (2604.20801) | Defer | Python-only; revisit once Rust interop stabilizes. |
| AgenticSCR (2601.19138) | Defer | Niche pre-commit case; wait for phase loop stabilization. |
| VulnLLM-R (2512.07533) | Skip | GPU cluster required; consume as external service if needed. |
| OpenAnt | Defer | Heavy UniFFI build; architectural impact too large. |
| DeepAudit | Skip | Full platform, diverges from baco's monolithic Rust design. |
| FocusVul (2505.17460) | Skip | Paper withdrawn; code inaccessible. |
| LLM-based Vulnerability Detection at Project Scale (2601.19239) | Cautionary study | Confirms multi-source/cross-file boosts and FP penalties are correct mitigations. |
| VULPO (2511.11896) | Defer | Interesting future fine-tuning, not current runtime. |
| R2Vul (2504.04699) | Defer | Needs GPU infra; defer to future explainability work. |
| From Large to Mammoth (NDSS 2025) | Defer | One data point; don't adopt wholesale without local validation. |

---

## Sources

All papers and projects surveyed from:
- [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection)

### Open Source References

| Project | License | URL |
|---------|---------|-----|
| VulTriage | - | https://github.com/vinsontang1/VulTriage |
| LLMxCPG | - | https://github.com/qcri/llmxcpg |
| R2Vul | MIT | https://github.com/martin-wey/R2Vul |
| VulnLLM-R | Apache-2.0 | https://github.com/ucsb-mlsec/VulnLLM-R |
| PrimeVul | - | https://github.com/DLVulDet/PrimeVul |
| AutoCVE | AGPL-3.0 | https://github.com/larlarua/AutoCVE |
| OpenAnt | - | https://github.com/knostic/OpenAnt |
| DeepAudit | AGPL-3.0 | https://github.com/lintsinghua/DeepAudit |
| Cloudflare skill | MIT | https://github.com/cloudflare/security-audit-skill |
| Anthropic harness | - | https://github.com/anthropics/defending-code-reference-harness |
| AgentFlow | MIT | https://github.com/berabuddies/agentflow |
| SV-TrustEval-C | - | https://github.com/Jackline97/SV-TrustEval-C |
| SecVulEval | - | https://github.com/basimbd/secvuleval |
| LLM-For-Software-Security | - | https://github.com/OwenSanzas/LLM-For-Software-Security |
| Awesome-LLM4SVD | - | https://github.com/hs-esslingen-it-security/Awesome-LLM4SVD |

---

## Key Gaps Identified

This survey highlighted seven critical gaps in baco's original design:

1. **No data-flow/taint engine** — Only LLM-prompted cross-file analysis. Every paper on context/CPG says this is the single biggest accuracy lever.

2. **All prompts zero-shot** — No few-shot, no CoT, no rationale validation. CORRECT shows this is the cheapest win.

3. **No retrieval/KB layer** — VulInstruct and VulTriage show specification RAG cuts FP sharply without vector stores.

4. **No per-CWE specialization** — MoEVD shows monolithic models collapse on long-tailed CWEs.

5. **No structured agentic loop** — Single-agent design; Cloudflare/Anthropic/OpenAnt show multi-agent parallel + adversarial loops give ~2x discovery.

6. **No statement-level localization** — SecVulEval shows function-level findings miss real patterns.

7. **No benchmark/regression suite for LLM phase quality** — SV-TrustEval-C and PrimeVul provide ready-made rigor.