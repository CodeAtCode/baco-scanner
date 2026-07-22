# Research-Backed Design

BACO's LLM integration is informed by a survey of 30 papers and 7 projects from
[Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection).
The full analysis and integration roadmap live in [`docs/papers-integration-analysis.md`](papers-integration-analysis.md).

## Integrated Papers

### Tier 1

| Task | Paper | arxiv | baco target |
|------|-------|-------|------------|
| Agentic FP filter | Sifting the Noise (ISSTA 2026) | [2601.22952](https://arxiv.org/abs/2601.22952) | `src/llm_verification.rs` + `src/confidence_refinement.rs` |
| Hierarchical context extraction | Context-Enhanced Vuln Detection | [2504.16877](https://arxiv.org/abs/2504.16877) | new `src/context/` module |
| CWE KB RAG (BM25, no vectors) | VulInstruct (FSE 2026) | [2511.04014](https://arxiv.org/abs/2511.04014) | new `src/retrieval/` module |
| Regression suite | SV-TrustEval-C (SP 2025) | [2505.20630](https://arxiv.org/abs/2505.20630) | `tests/integration/` |

### Tier 2

| Task | Paper | arxiv/code | baco target |
|------|-------|-------------|------------|
| MoE per-CWE/language routing | MoEVD (FSE 2025) | [2501.16454](https://arxiv.org/abs/2501.16454) | new `src/router/` module |
| Triple-path context (AST/CFG/DFG) | VulTriage | [2605.09461](https://arxiv.org/abs/2605.09461) | `src/context/` extension |
| LLM→semgrep rule synthesis | MoCQ | [2504.16057](https://arxiv.org/abs/2504.16057) | new `src/rulesynth/` phase |
| Global FP suppression | AutoCVE | [code](https://github.com/larlarua/AutoCVE) | `src/findings.rs` + `src/root_cause_dedup.rs` |
| Six-phase parallel orchestration | Cloudflare security-audit-skill | [code](https://github.com/cloudflare/security-audit-skill) | `src/scanner/pipeline/orchestrator.rs` |

### Tier 3

| Task | Paper | arxiv/code | baco target |
|------|-------|-------------|------------|
| CPG-guided slicing | LLMxCPG (Usenix 2025) | [2507.16585](https://arxiv.org/abs/2507.16585) | new `src/cpg/` + Joern |
| Adversarial exploit synthesis | QRS | [2602.09774](https://arxiv.org/abs/2602.09774) | new `src/exploit/` + sandbox |
| Specialized reasoning LLM | R2Vul + VULPO | [2504.04699](https://arxiv.org/abs/2504.04699) + [2511.11896](https://arxiv.org/abs/2511.11896) | new `LlmProvider::TgiServed` |

### Cross-cutting insights

| Insight | Paper | baco application |
|---------|-------|-----------------|
| Rationale validation via LLM-as-judge | CORRECT — [2504.13474](https://arxiv.org/abs/2504.13474) | `src/llm_verification.rs` |
| Statement-level localization | SecVulEval — [2505.19828](https://arxiv.org/abs/2505.19828) | `src/findings.rs` |
| Dataset hygiene (chronological splits) | PrimeVul (ICSE 2025) — [2403.18624](https://arxiv.org/abs/2403.18624) | `tests/fixtures/` |
| Confidence calibration per user study | Closing the Gap (ICSE 2025) — [2412.14306](https://arxiv.org/abs/2412.14306) | `src/confidence_refinement.rs` |
| Semantic Trap guard for fine-tuning | Semantic Trap — [2601.22655](https://arxiv.org/abs/2601.22655) | `docs/fine-tuning-guidelines.md` |

## Surveyed but deferred/skipped

- **AgentFlow** (2604.20801) — Python-only, defer until Rust interop stabilizes
- **AgenticSCR** (2601.19138) — niche pre-commit case
- **VulnLLM-R** (2512.07533) — GPU cluster required
- **OpenAnt** — heavy UniFFI build
- **DeepAudit** — too large/divergent
- **FocusVul** (2505.17460) — paper withdrawn

For the full list of surveyed papers and their verdicts, see
[`docs/papers-integration-analysis.md`](papers-integration-analysis.md).