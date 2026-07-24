# Research-Backed Design

Baco's LLM integration is informed by a survey of 30 papers from [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection). This document details the 18 papers integrated into baco's architecture and what each contributes.

## Agentic & Multi-Agent Approaches

### Sifting the Noise (ISSTA 2026) — [arxiv](https://arxiv.org/abs/2601.22952)

**Problem:** LLM-based vulnerability detectors produce excessive false positives, with initial detection rates showing up to 92% false positive rates that overwhelm developers.

**Technique:** A lightweight agentic triage system filters findings before final reporting. The approach uses a minimal LLM call to validate each potential vulnerability, applying learned heuristics to distinguish true positives from noise without expensive re-analysis.

**Key Result:** False positive rate dropped from 92% to 6.3% with the triage filter, representing a dramatic improvement in signal quality while maintaining high recall.

**Baco Integration:** Baco implements a triage filter phase before final vulnerability reporting, applying the same lightweight validation pattern to reduce noise in the output.

### AutoCVE — [code](https://github.com/larlarua/AutoCVE)

**Problem:** Vulnerability detection pipelines generate redundant findings across multiple scans, requiring manual deduplication and causing alert fatigue.

**Technique:** A four-agent pipeline handles reconnaissance, scanning, triage, and finding consolidation. Each agent has a specialized role, with the triage agent performing cross-scan deduplication and the finding agent producing consolidated reports.

**Key Result:** The multi-agent approach achieves significant deduplication rates while preserving true positive coverage, with each agent operating independently to avoid cascading failures.

**Baco Integration:** Baco adopts the multi-agent deduplication pattern as a global false positive suppression stage, consolidating findings across aggregation boundaries.

### Cloudflare Security-Audit-Skill — [code](https://github.com/cloudflare/security-audit-skill)

**Problem:** Security audit workflows suffer from sequential bottlenecks and lack independent verification at each stage.

**Technique:** A six-phase parallel pipeline with independent verification at each step. The architecture restructures the audit process into a graph of independent phases that can run in parallel, with each phase having its own verification mechanism.

**Key Result:** The parallel orchestration pattern doubled discovery rates compared to sequential approaches while maintaining accuracy through independent verification.

**Baco Integration:** Baco restructured its pipeline to a six-step graph with independent verification, implementing the Cloudflare pattern for higher discovery rates.

## Context & Program Analysis

### Context-Enhanced Vulnerability Detection — [arxiv](https://arxiv.org/abs/2504.16877)

**Problem:** LLMs analyzing code lack sufficient context to understand vulnerability patterns, leading to poor performance on zero-shot tasks.

**Technique:** Hierarchical context extraction builds multi-level representations of code, from function-level summaries to cross-file dependencies. Filtered abstracted context consistently outperforms raw code prompts by focusing the LLM on relevant vulnerability patterns.

**Key Result:** Filtered context injection improved detection accuracy by addressing the zero-shot performance gap, with abstracted representations showing consistent gains across vulnerability types.

**Baco Integration:** Baco implements multi-level context injection into LLM prompts, using hierarchical extraction to provide relevant context without overwhelming the model.

### VulIn (BM25 RAG) — [arxiv](https://arxiv.org/abs/2511.04014)

**Problem:** Retrieval-augmented generation for vulnerability detection typically requires expensive vector stores and complex infrastructure.

**Technique:** Specification RAG with BM25 retrieval uses a JSON-serializable CWE knowledge base. The approach shows that keyword-based retrieval can sharply reduce false positives without the overhead of embedding models or vector databases.

**Key Result:** Spec RAG with BM25 achieved significant false positive reduction while maintaining a lightweight, serializable knowledge base that integrates cleanly into existing pipelines.

**Baco Integration:** Baco uses CWE knowledge base RAG with BM25 retrieval for security specifications, avoiding vector stores while maintaining high-quality context.

### VulTriage — [arxiv](https://arxiv.org/abs/2605.09461)

**Problem:** Vulnerability analysis lacks proper data-flow grounding, causing LLMs to miss critical execution paths and control dependencies.

**Technique:** Triple-path context augmentation extracts control flow (AST/CFG/DFG), knowledge flow, and semantic flow information. The control path specifically addresses missing data-flow grounding by providing structural program analysis alongside semantic context.

**Key Result:** Triple-path context extraction significantly improved analysis accuracy by grounding LLM reasoning in actual program structure rather than surface-level patterns.

**Baco Integration:** Baco implements triple-path context extraction with program analysis grounding, using the control path to address data-flow grounding gaps.

### LLMxCPG (Usenix 2025) — [arxiv](https://arxiv.org/abs/2507.16585)

**Problem:** LLMs analyzing full codebases face context window limits and performance degradation from excessive code volume.

**Technique:** CPG-guided slicing uses the Code Property Graph to reduce code volume by 67-91% while preserving vulnerability-relevant paths. The approach complements data-flow analysis and multi-file correlation by providing precise slicing based on program structure.

**Key Result:** CPG-guided slicing achieved the highest quality gain among context techniques, reducing code volume dramatically while maintaining analysis accuracy.

**Baco Integration:** Baco integrates CPG-guided slicing using Joern CPG to reduce code volume for LLM analysis while preserving critical vulnerability paths.

## Rule Synthesis & Exploit Generation

### MoCQ — [arxiv](https://arxiv.org/abs/2504.16057)

**Problem:** Manual rule creation for static analysis is slow and cannot keep pace with emerging vulnerability patterns.

**Technique:** LLM-generated patterns with symbolic validation synthesize semgrep rules from vulnerability descriptions. The approach uses rapid iteration with build validation to achieve immediate F-score uplift, fitting naturally into cargo-based build systems.

**Key Result:** LLM-driven rule synthesis achieved rapid F-score improvement through automated pattern generation and validation, demonstrating the viability of synthetic rule creation.

**Baco Integration:** Baco implements LLM-driven semgrep rule synthesis with validation, using the cargo-based build system for rapid rule iteration.

### QRS — [arxiv](https://arxiv.org/abs/2602.09774)

**Problem:** Static analysis rules are limited by manual creation and cannot adapt quickly to new vulnerability patterns.

**Technique:** LLM-to-CodeQL query generation with adversarial validation creates detection queries automatically. The approach includes on-the-fly exploit synthesis to validate generated rules, escaping the limits of manual rule creation.

**Key Result:** The LLM-to-rule compiler with adversarial validation produced high-quality CodeQL queries that matched or exceeded manually created rules.

**Baco Integration:** Baco implements adversarial exploit synthesis to validate generated rules, using the QRS pattern for dynamic rule verification.

## Model Specialization & Routing

### MoEVD (FSE 2025) — [arxiv](https://arxiv.org/abs/2501.16454)

**Problem:** Monolithic LLMs collapse on long-tailed CWEs, failing to detect less common vulnerability patterns.

**Technique:** Mixture-of-experts architecture routes queries to specialized models per-CWE. The approach fits naturally with phase-dispatch architectures, allowing different models and prompts for different vulnerability types.

**Key Result:** Per-CWE routing significantly improved detection on long-tailed vulnerabilities while maintaining performance on common patterns.

**Baco Integration:** Baco implements per-CWE and per-language routing with specialized prompts and models, using the MoEVD pattern for phase-based dispatch.

### R2Vul + VULPO — [arxiv](https://arxiv.org/abs/2504.04699) + [arxiv](https://arxiv.org/abs/2511.11896)

**Problem:** Vulnerability explanations lack clarity and root-cause analysis, reducing developer trust in findings.

**Technique:** Structured reasoning distillation combined with context-aware reinforcement learning produces specialized reasoning models. The approach trains models specifically for vulnerability explanation and root-cause analysis.

**Key Result:** Specialized reasoning models significantly improved explainability and root-cause analysis quality compared to general-purpose LLMs.

**Baco Integration:** Baco supports optional specialized reasoning models served via TGI for improved explainability and root-cause analysis.

## Quality & Evaluation

### SV-TrustEval-C (SP 2025) — [arxiv](https://arxiv.org/abs/2505.20630)

**Problem:** LLM-based vulnerability detectors can regress to pattern-matching behavior without proper evaluation metrics.

**Technique:** Structure-oriented benchmark with 9,401 Q&A pairs covering 82 CWEs provides comprehensive evaluation coverage. The benchmark alerts when models regress to pattern-matching rather than genuine vulnerability reasoning.

**Key Result:** The evaluation suite successfully detected regression to pattern-matching in tested models, validating its effectiveness as a quality gate.

**Baco Integration:** Baco uses SV-TrustEval-C as a regression suite to validate LLM phase quality and detect performance degradation.

### CORRECT — [arxiv](https://arxiv.org/abs/2504.13474)

**Problem:** LLM-generated vulnerability rationales often contain hallucinations that undermine trust in findings.

**Technique:** Rationale validation via LLM-as-judge down-ranks findings whose explanations fail consistency checks. The approach uses a secondary LLM to validate the reasoning behind each vulnerability finding.

**Key Result:** Rationale validation significantly reduced hallucination rates while maintaining true positive coverage.

**Baco Integration:** Baco implements rationale validation to reduce reasoning errors and hallucinations in vulnerability explanations.

### SecVulEval — [arxiv](https://arxiv.org/abs/2505.19828)

**Problem:** Vulnerability localization at statement-level granularity is extremely difficult, with best LLMs achieving only 23.83% F1.

**Technique:** Statement-level localization benchmark provides rigorous evaluation for fine-grained vulnerability detection. The benchmark pushes beyond line-level to statement/block-level precision.

**Key Result:** The benchmark established that even best LLMs struggle with statement-level localization, highlighting the need for confidence-aware detection.

**Baco Integration:** Baco implements statement/block-level confidence scoring instead of simple line-level detection, addressing the granularity challenge.

### PrimeVul (ICSE 2025) — [arxiv](https://arxiv.org/abs/2403.18624)

**Problem:** Legacy vulnerability benchmarks overestimate model performance by 22× due to data contamination and poor hygiene.

**Technique:** Chronological dataset hygiene enforces time-based splits, deduplication, and cross-context labeling. The approach prevents data leakage by ensuring training data predates vulnerability disclosures.

**Key Result:** Legacy benchmarks were shown to overestimate performance by 22×, validating the need for chronological hygiene in evaluation.

**Baco Integration:** Baco implements dataset hygiene with chronological splits and deduplication to ensure accurate performance measurement.

## Confidence & Calibration

### Closing the Gap (ICSE 2025) — [arxiv](https://arxiv.org/abs/2412.14306)

**Problem:** High false positive rates and non-applicable fixes destroyed developer adoption of LLM vulnerability detectors.

**Technique:** Confidence calibration via post-hoc normalization adjusts model outputs to match real-world accuracy. The approach calibrates confidence scores to reflect actual false positive rates.

**Key Result:** Post-hoc normalization significantly improved calibration, making confidence scores trustworthy for triage decisions.

**Baco Integration:** Baco implements confidence calibration with post-hoc normalization to produce trustworthy confidence scores.

## Surveyed but Not Integrated

Papers assessed but deferred or skipped:

| Paper | Verdict | Rationale |
|-------|---------|-----------|
| AgentFlow (2604.20801) | Defer | Python-only; revisit once Rust interop stabilizes |
| AgenticSCR (2601.19138) | Defer | Niche pre-commit case; wait for phase loop stabilization |
| VulnLLM-R (2512.07533) | Skip | GPU cluster required; consume as external service if needed |
| OpenAnt | Defer | Heavy UniFFI build; architectural impact too large |
| DeepAudit | Skip | Full platform, diverges from baco's monolithic Rust design |
| FocusVul (2505.17460) | Skip | Paper withdrawn; code inaccessible |
| VULPO (2511.11896) | Defer | Interesting future fine-tuning, not current runtime |
| R2Vul (2504.04699) | Defer | Needs GPU infra; defer to future explainability work |
| Semantic Trap (2601.22655) | Guidance-only | Fine-tuning guidance not applicable; baco uses API models, not fine-tuned models |

## Sources

All papers and projects surveyed from:
- [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection)