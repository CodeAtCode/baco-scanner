# Output Interpretation Guide

How to read and act on baco's scan findings.

## Reading a Finding Entry

Each finding in `findings.json` is a `VulnerabilityFinding` struct. Example:

```json
{
  "id": "a1b2c3d4e5f6...",
  "title": "SQL Injection in user_query()",
  "description": "User input concatenated directly into SQL query",
  "severity": "high",
  "confidence_score": 0.87,
  "cwe_id": "CWE-89",
  "file_path": "src/db.rs",
  "line_number": 42,
  "code_snippet": "query = \"SELECT * FROM users WHERE id=\" + user_input",
  "diff_hunk": "@@ -40,4 +40,4 @@\n- query = \"SELECT...\" + user_input\n+ query = prepare(\"SELECT...\", user_input)",
  "recommendation": "Use parameterized queries",
  "sources": ["phase3_pattern", "phase7_llm"],
  "verification_status": "needs_review",
  "triage_verdict": "pass"
}
```

**Key fields:**

| Field | Meaning |
|-------|---------|
| `id` | SHA256 hash of file+line+CWE (unique identifier) |
| `severity` | Critical, High, Medium, Low, or Info |
| `confidence_score` | 0.0–1.0 likelihood this is a real vulnerability |
| `cwe_id` | Common Weakness Enumeration identifier |
| `line_number` | Exact line where vulnerability occurs |
| `diff_hunk` | Unified diff showing vulnerable code → suggested fix |
| `verification_status` | Human/LLM triage state (see below) |
| `triage_verdict` | Prioritization signal (see below) |
| `sources` | Which detection phases found this |

When a finding spans multiple files, `code_snippet` may include "Found in X file(s)".

## Confidence Score (0.0–1.0)

The `confidence_score` reflects how likely the finding is a true positive.

| Range | Interpretation | Action |
|-------|----------------|--------|
| 0.8+ | High confidence — likely real | Prioritize for fix |
| 0.4–0.6 | Moderate confidence — needs review | Investigate manually |
| <0.4 | Low confidence — likely false positive | Review but deprioritize |

### How Confidence Gets Adjusted

The confidence refinement phase applies boosts and penalties:

| Factor | Adjustment |
|--------|------------|
| High/Critical severity + base >0.7 | +0.15 |
| LLM verification confirmed | +0.05 |
| Multi-source confirmation (>1 detector) | +0.1 |
| Cross-file reachability confirmed | +0.08 |
| CVE pattern match | +0.1 |
| False-positive pattern detected | -0.1 |
| Never-submit/risky pattern | -0.15 |
| Test/vendor code | -0.1 to -0.15 |
| Verification failed | -0.1 |

All adjustments are clamped to 0.0–1.0.

## Verification Status

The `verification_status` field shows human/LLM triage state:

| Status | Meaning | What to Do |
|--------|---------|------------|
| `confirmed` | Verified as a real vulnerability | **Fix immediately** |
| `needs_review` | Not yet verified — LLM flagged it | **Investigate** — determine if true positive |
| `false_positive` | Verified as not a vulnerability | **Dismiss** — no action needed |
| `failed` | Verification process encountered an error | **Retry verification** or manual review |

Set `verification_status` manually in `findings.json` or via baco's triage interface.

## Triage Verdicts

The `triage_verdict` field indicates how the finding should be prioritized:

| Verdict | Meaning | Action Priority |
|---------|---------|-----------------|
| `pass` | True positive — should be fixed | **Act on this** |
| `kill` | False positive or noise | Ignore / suppress |
| `downgrade` | Theoretical impact, not demonstrated | Review and possibly downgrade severity |
| `chain_required` | Needs a partner finding to be exploitable | Find the chain partner first |

When `triage_verdict` is `downgrade`, the finding includes `adjusted_severity` showing the reduced level.

When `triage_verdict` is `chain_required`, the finding includes `chain_partner_ids` listing related finding IDs that must be present for exploitation.

## Verification Tiers

The `verification_tier` field classifies how strongly a finding is supported by independent evidence:

| Tier | Rule | Meaning |
|------|------|---------|
| `verified` | Evidence from ≥2 different source kinds, including at least one verifier | Independently reproduced — highest trust |
| `supported` | ≥2 evidence items of any kind, or a single source with confidence > 0.8 | Plausible but not independently reproduced |
| `unverified` | Everything else | Single-source or no evidence |

Evidence sources are grouped into kinds: static analysis (`semgrep`, `cpg_slice`), LLM analysis (`llm_analysis`, `rule_synthesis`), verifiers (`independent_verifier`, `security_agent_verification`), and specifications (`cwe_spec`). Two entries from the same kind do not count as independent reproduction.

### Evidence Gating

Enable with `[output] evidence_gate = true` in your config or `--evidence-gate` on the scan command:

| Output | Behavior when gate is on |
|--------|--------------------------|
| `findings.json` | All findings kept; each gets `verification_tier` attached |
| `report.html` | Main body shows verified + supported only; unverified findings listed in an appendix section |
| `report.sarif` | Only verified + supported findings emitted |
| CLI | Summary line: `Evidence gate: N verified, M supported, K unverified (excluded from reports)` |

With the gate off (default), all outputs contain all findings unchanged.

## Severity vs. Confidence: Prioritization Matrix

Combine severity and confidence to decide what to fix first:

| | **High Confidence (0.8+)** | **Medium (0.4–0.6)** | **Low (<0.4)** |
|---|---|---|---|
| **Critical** | 🔴 Fix now | 🟠 Verify, then fix | 🟡 Verify first |
| **High** | 🔴 Fix now | 🟠 Investigate | 🟡 Review later |
| **Medium** | 🟠 Fix soon | 🟡 Investigate | ⚪ Defer |
| **Low** | 🟡 Fix when convenient | ⚪ Defer | ⚪ Ignore |
| **Info** | ⚪ Informational | ⚪ Informational | ⚪ Informational |

**Rule of thumb:**
- High severity + high confidence → **act immediately**
- High severity + low confidence → **verify before fixing**
- Low severity + high confidence → **fix when convenient**

## Report Artifacts

baco generates three output files:

| File | Purpose |
|------|---------|
| `findings.json` | Full JSON array of all `VulnerabilityFinding` objects. Use for programmatic processing or custom reports. With evidence gating on, each entry includes its `verification_tier`. |
| `report.html` | Human-readable HTML report with severity breakdown, charts, and clickable finding details. With evidence gating on, shows verified + supported findings and an appendix of unverified ones. |
| `report.sarif` | SARIF output for CI/CD integration. With evidence gating on, contains only verified + supported findings. |
| `checkpoint.json` | Internal state for resuming interrupted scans. Do not edit manually. |

All files are written to the output directory specified in your config or CLI flags.

---

**See also:** [CI/CD Integration](ci-integration.md) for SARIF output, [Configuration](configuration.md) for output options.