# Research: argusappsec/argus → baco adoption analysis

Source: https://github.com/argusappsec/argus (Go daemon, Apache-2.0, pre-1.0,
24 ADRs + design docs). Analyzed 2026-09-01. Companion analysis:
docs/cloudflare-security-audit-skill-analysis.md (5 items from that report
already implemented in commit 61e2c80 — not repeated here).

## Summary

**Different category from the Cloudflare skill: argus is an interactive
application-security *agent platform*, not a scanner pipeline.** A Go daemon
(`argusd`) wrapping semgrep/gitleaks/osv-scanner as structured tools, driving
an open-ended LLM review loop humans converse with over TUI, GitHub PR
webhooks, and MCP. Differentiating ideas: (a) validated skill content — a
6-pass BOLA/IDOR/BFLA hunting methodology benchmarked against a labeled target
(VAmPI, 100% recall / 100% precision on that corpus) before shipping, with the
ground-truth oracle shipped as a regression check; (b) content-derived stable
finding IDs; (c) org-context (SOUL) prompt calibration; (d) strict lane
discipline ("pattern → tool, semantic → skill"); (e) prompt-injection
hardening of the untrusted-code review path. The daemon/channel/RBAC machinery
is product architecture baco ignores.

## Adoptable techniques (all 6 selected for implementation)

### 1. Known-answer benchmark oracles as regression gates for LLM phases
- **Evidence:** `pkg/skill/builtin/authz-audit/self-test-vampi.md` — expected
  findings table (recall set, exact sink + rule_id + severity), expected-NOT
  findings (precision set, deliberately labeled near-misses), pass/fail
  criteria; loaded only for validation, never during real audits.
- **baco gap:** nothing measures the LLM discovery/verification phases —
  every prompt change lands unmeasured.
- **Mapping:** `eval/` harness: labeled fixture targets with vulnerable/secure
  aligned pairs + oracle JSON; scoring module reports recall (on vulnerable
  set) and precision (zero flags on secure twins); e2e run gated behind an
  env flag (needs real LLM), oracle/fixture validation always in CI.

### 2. Ground-model-first + skeptical-gate methodology for absence-based bugs
- **Evidence:** `pkg/skill/builtin/authz-audit/SKILL.md` — PASS 0 builds the
  ground model before judging (router style, canonical principal accessor,
  ownership/tenancy model, actual guard vocabulary); "'I can't find a guard
  in this file' is not a finding — it is an instruction to go read the call
  chain"; PASS 6 skeptical self-refutation gate before every emit
  ("the correctly-scoped sibling branch is SAFE — flagging it is the canonical
  false positive"; "default to NOT reporting if any guard chain is
  unresolved"). Naive LLM IDOR passes measure 78–88% FP.
- **Mapping:** new ground-model authz hunt module + self-refutation gate
  section in the verification prompt.

### 3. Content-derived stable finding IDs (closed rule taxonomy + normalized snippet)
- **Evidence:** `pkg/report/report.go` `ComputeFindingID` =
  `sha256(rule_id + "\x00" + normalizeSnippet(snippet))[:12]`; rule_id from a
  closed taxonomy; IDs survive refactors; a fix changes the snippet and
  auto-resolves the finding.
- **baco state:** the key mechanism landed with the prior-runs store
  (`src/run_store.rs::stable_finding_key`, snippet-based). Remaining delta:
  a closed rule taxonomy (domain/CWE-sourced rule_id) stamped on findings.

### 4. Lane discipline: closed ownership per module
- **Evidence:** "if a deterministic tool catches it reliably, the skill's only
  job is to triage/confirm the tool's output"; adjacent classes emitted as
  `info` under a deterministic handoff rule_id for a future sibling module —
  "If you see an f-string SQL query while tracing a sink, that is not your
  finding."
- **Mapping:** every hunt module declares a "Scope — stay in your lane"
  section: closed class ownership + out-of-scope list + info-severity handoff
  rule for adjacent observations.

### 5. Org-context profile with meaning-attached severity calibration
- **Evidence:** `pkg/soul/soul.go` — narrow structured profile (stack, infra,
  data sensitivity, where secrets live in production, risk tolerance) where
  every label renders as an instruction with meaning attached ("without this
  the model reads 'high' as 'only flag criticals'"); `secret_storage` is a
  massive FP reducer; per-repo exception store curated via explicit writes.
- **Mapping:** `[org_context]` config section → rendered prompt block with
  meaning-attached text injected into discovery/verification.

### 6. Prompt-injection hardening of the target-code path
- **Evidence:** ADR-0018 — untrusted reviews run read-only on the knowledge
  base and in ephemeral sessions ("an injection in reviewed code could poison
  MEMORY.md; a public-repo attacker could silently steer reviews of private
  code"); ADR-0019 — symlink resolution for path containment.
- **Mapping:** code-as-data framing in the phase prompts (instructions inside
  analyzed code are injection attempts, never obeyed); cross-run store already
  ingests only verified/gated outcomes; symlink containment in the indexer.

## Not worth adopting

| Item | Reason |
| --- | --- |
| Daemon/platform architecture (TUI/MCP/Slack, webhooks, RBAC, audit log) | conversational product; baco is a batch pipeline |
| `pr-quick-check` diff-scoped review | PR-comment product mode |
| Webhook dedup + repo gating | GitHub App plumbing |
| Persona/identity layer | chat cosmetics |
| Memory-curator subagent | overlaps the cross-run store |
| `secret-rotation-plan` skill | analyst work-product, not a finding |
| Agent-loop safety nets | baco phases emit structured verdicts |
| Markdown+YAML report format | SARIF/JSON/HTML already cover it |

## Caveats

- "100%/100% on VAmPI" is a single tiny purpose-built target — the
  transferable asset is the oracle+blind-validation method, not the number.
- argus's LLM loop is open-ended tool-use; mappings target baco's structured
  phases, not a re-architecture.
- Repo is pre-1.0, schema-unstable; ADRs/design docs are the stable knowledge.
