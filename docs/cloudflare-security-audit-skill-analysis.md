# Research: cloudflare/security-audit-skill → baco adoption analysis

Source: https://github.com/cloudflare/security-audit-skill (MIT-licensed, 12 files).
Analyzed against baco's 24-phase pipeline, evidence gating, vuln_spec RAG, and LLM
verification machinery. Date: 2026-09-01. Status: all 5 selected items implemented
(commit 61e2c80) — see "Implementation status" at the bottom.

## Summary

The repo is **not a scanner engine — it is a prompt-only "coding-agent skill"**:
9 Markdown methodology files, one JSON schema (`report-schema.json`), and one
zero-dependency Node validator (`validate-findings.cjs`). It instructs a
general-purpose coding agent through a six-phase audit:

Recon (3 parallel research agents → `architecture.md` with trust boundaries +
input-surface inventory) → Hunt (parallel per-attack-class agents, domain-routed
to 4 companion prompt files) → Validate (separate agents with an explicit
*disprove* mandate) → Report → Structured output (`findings.json` against
schema, mechanically validated) → Independent verification (fresh agents
re-check every factual claim in the JSON against source).

It is the seed of Cloudflare's production vulnerability-discovery harness
(blog: 20,799 raw candidates → 12,057 surviving independent validation →
7,245 actionable findings across 145 repos; initial validation rejection rate
improved 40%→11% after recon-context improvements). Small as a repo, dense as
methodology, backed by fleet-scale operational data. Everything adoptable is
prompt/schema/state-design, not code.

## Adoptable techniques (all 5 implemented)

### 1. Final independent claim-verification pass (their Phase 6)
- **Evidence:** `VALIDATION-AND-REPORTING.md`, Phase 6: one fresh `research`
  agent per confirmed finding verifies *every factual claim* in
  `findings.json` — file exists, line number matches described code, function
  scope correct, payloads survive validation/auth on the real path, remediation
  wouldn't break normal function, `confidence` matches evidence strength.
- **baco gap:** no phase verified report citations — hallucinated `file:line`
  references are the signature failure of LLM-generated reports.
- **Implementation:** `src/citation_verification.rs` — deterministic gate in
  the Reporting phase: file-existence + line-range checks; failing findings
  get halved confidence + a note. Config `[citation_verification] enabled`
  (default false).

### 2. Additive multi-run: cross-run findings store + gap targeting
- **Evidence:** `SKILL.md`, "Coverage and prior runs": every run writes
  `findings.json` to a stable per-repo dir; the next run reads all prior runs
  and (1) skips known findings, (2) targets gaps, (3) resolves disagreements.
- **baco gap:** root-cause dedup was intra-run; each scan restarted from
  scratch, re-spending verification budget on the same bugs.
- **Implementation:** `src/run_store.rs` — stable finding keys
  `sha256(file_path + normalized snippet)[:12]`; prior Confirmed/FalsePositive
  findings injected into discovery prompts as a skip list (capped at 50);
  each completed run saved under `{output_dir}/runs/run-<ts>/`. Config
  `[prior_runs] enabled` (default false).

### 3. Domain-routed hunting modules with domain-specific validation rules
- **Evidence:** `ATTACK-CLASSES.md` routing block → 4 companion files, each
  with a core discipline block + named bug-pattern classes + domain-specific
  validation rules (the FP-killers).
- **baco gap:** `prompts/hunt/*.md` existed but the loader ignored them and
  discovery used inline prompts.
- **Implementation:** `src/prompt/loader.rs` loads `prompts/hunt/`;
  `PromptEngine::select_hunt_domains(languages)` exact-match table routes by
  target languages; domain modules appended to discovery prompts. Config
  `scanner.performance.enable_hunt_prompts` (default false).

### 4. First-class rejected findings (`oneOf` confirmed/rejected)
- **Evidence:** `report-schema.json`: finding schema is a `oneOf` —
  `confirmed` **or** `rejected` with `reason`. Killed FPs are persisted
  artifacts, not discarded.
- **Implementation:** verification returns rejected findings with reasons
  instead of dropping them; JSON report gains a `"rejected"` array; HTML
  gains an "Investigated & Dismissed" appendix. Config
  `output.include_rejected` (default false).

### 5. Dynamic confirmation: minimal-harness extraction + sandboxed execution
- **Evidence:** `SKILL.md` "Confirm dynamically when you can"; harness blog:
  every confirmed finding ships a PoC run against the untouched codebase —
  "if there is no working PoC, we treat the finding as fake."
- **baco state (verified):** exploit synthesis ALREADY executes exploits in a
  Docker sandbox (`src/exploit/harness.rs`: `--network none --read-only`,
  no-new-privileges) and stamps `IndependentVerifier("exploit_synth")`
  evidence on confirmation. The remaining delta implemented: the
  "requires deployment testing" marker — when the harness cannot execute
  (Docker unavailable), the finding is labeled `requires_deployment_testing`
  in verification notes, distinct from "executed but not confirmed". Plus a
  new `prompts/hunt/memory_safety.md` module (length-subtraction underflow,
  operator-precedence length errors, sizeof(*p) confusion, double-fetch
  TOCTOU, offset off-by-one, audit-the-incomplete-fix).

## Also adopted cheaply (from the same report)

- Semantic trace-shape validation ideas folded into the citation gate.
- Two-axis severity with reasons and the boundary-defeat rule noted for
  future confidence-scoring work.

## Not worth adopting

| Item | Reason |
| --- | --- |
| Parallel sub-agent orchestration | baco already runs parallel multi-phase LLM agents |
| Recon architecture.md as such | baco's indexing + threat modeling cover it |
| "Obvious things" checklist agent | Semgrep already covers secrets/CORS/cookies/redirects |
| CI integration | repo has none |
| "Positive patterns" report section | cosmetic; tier-filtered reports suffice |
| Skills-CLI packaging | coding-agent packaging; irrelevant to a standalone binary |
| Wishlist mechanism | harness-only, fleet-scale |
| Cross-repo dependency tracing | requires multi-repo fleet |
| Per-repo cost budgets, worker pools | fleet cost management |
| Fixer (auto-patch + merge gate) | baco is a scanner, not a fixer |
| Different models for discovery vs validation | procurement decision, not code |
| Git-history mining | mostly covered by vuln_spec RAG + CVE bootstrap |

## Implementation status

All five items landed in commit `61e2c80` (36 files, +2337/−273), CI green
(fmt, clippy `-D warnings`, 4429 tests). Every feature is default-off and
documented in `config.example.toml`. Bonus fix shipped in the same commit:
`config.example.toml` previously set `enable_multi_verifier = true`, which
would enable the hash-based stub that fabricates `IndependentVerifier`
evidence — corrected to `false`.
