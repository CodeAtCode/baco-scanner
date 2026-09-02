# BACO Scanner — Deep Codebase Analysis & Improvement Plan

**Repo:** `CodeAtCode/baco-scanner` (master @ `776028e`, 2026-08-26)
**Scope:** UI/UX, code quality, tests, AI-efficiency, intelligence upgrades, and project-type presets (TOML) for large OSS targets (WordPress, WordPress plugins, LiteLLM).
**Method:** Full read of the source tree (~37k LOC across `src/`, `tests/`, `prompts/`, `docs/`, `config.example.toml`), traced from CLI entry points through the 24-phase pipeline, the LLM client, the agent subsystem, and the report renderers.

---

## 1. Executive Summary

BACO is a genuinely ambitious Rust SAST tool: a 24-phase pipeline (Semgrep → CWE routing → LLM discovery → LLM verification → agent verification → ticket/git cross-referencing → aggregation → patching/PoC), checkpoint/resume, three output formats, and research integrations (VulTriage triple-path, PacVD abstraction, VulnLLM-R policy sampling, MoCQ rule synthesis, CORRECT LLM-as-judge). The test suite is large (~3,000 test functions) and CI is well-configured.

However, the current architecture is **maximally AI-intensive and minimally AI-smart** in its default path:

| Area | Verdict |
|---|---|
| LLM request volume | **Unbounded per-file + per-finding loops, zero batching, zero caching** |
| LLM request quality | Verification prompts omit the code; JSON parsed by `contains()`; self-contradictory prompts |
| Cost controls | **Phantom config options** — `enable_llm_cache`, `max_parallel_tasks`, `enable_file_filtering` are documented but do not exist in code |
| Multi-Verifier (default ON) | **A stub** — verdicts are `hash(finding_id) % 3`, not real verification |
| Language coverage | PHP is indexed but **silently skipped** by LLM analysis — WordPress core/plugins can't be properly scanned today |
| Noise injection | The static-analysis prompt *forbids* empty results, forcing fake `CWE-1000` "analysis complete" findings into every downstream LLM phase |

The single biggest win is architectural: **invert the pipeline from "LLM analyzes everything, then more LLM re-describes and re-verifies everything" to "cheap signals triage, LLM analyzes a prioritized subset once, with full context, in batches."** Combined with a real LLM cache, prompt-prefix caching, and file prioritization, a typical scan can drop 60–85% of requests while *increasing* accuracy, because the requests that remain carry the code context they currently lack.

Everything below is organized as concrete tasks. No timelines — only priority tiers:

- **P0 = correctness/cost bugs that actively waste money or produce wrong results**
- **P1 = structural changes that reduce request count and increase intelligence**
- **P2 = polish, UX, and ecosystem work (presets, docs, packaging)**

---

## 2. How BACO Works Today (Ground Truth From the Code)

### 2.1 Pipeline shape

`src/scanner/pipeline/orchestrator.rs` defines a `PhaseGraph` with 24 phases. Execution (`src/scanner/orchestrator.rs`):

1. **Parallel block** (`tokio::join!` over 4 optional handles — Indexing, Semgrep, CpgSlice, LlmStaticAnalysis).
2. **Sequential block** of 20 phases: CweRouting → RuleSynthesis → LlmDiscovery → LlmVerification → Validate → SecurityAgentVerification → TicketCrossRef → GitAnalysis → CrossFileAnalysis → ConfidenceScoring → AiAggregation → ThreatModeling → RootCauseDedup → MultiVerifier → AutoPatching → CveBootstrap → PocCompiler → ExploitSynth → VariantSearch → Reporting.

Each phase is checkpointed (`checkpoint.json`), enabling resume. `early_termination_threshold` (default 1000 findings) can stop the run.

### 2.2 The actual LLM cost map (who calls what, how many times)

Traced every `client.chat(...)` / `chat_with_tools(...)` call site:

| Phase | Call pattern | Requests for F files / N findings |
|---|---|---|
| LlmStaticAnalysis (4) | 1 call per indexed file, whole file truncated at **8,000 chars**, no chunking | **F** |
| — semantic path (VulTriage, opt-in) | 1 extra call per file to "summarize" it | +F |
| — policy sampling (VulnLLM-R, opt-in) | 4 extra calls per file | +4F |
| LlmDiscovery (7) | 1 call per finding (re-describes it, *without* the code) | **N** |
| LlmVerification (8) | 1 call per finding (verdict, *without* the code) | **N** |
| TicketCrossRef / GitAnalysis / CrossFile (11–13) | loops over findings (mixed LLM/API usage) | ~N |
| AiAggregation enrichment (15) | 1 call per finding + **automatic retry** call if JSON parse yields empty fields | **N…2N** |
| ThreatModeling (16) | batched (good) | ~1–few |
| MultiVerifier (18, **default ON**) | 3 "verifiers" per finding — but it's a **hash-based stub**, no real calls | 0 (fake results) |
| Rulesynth (6, opt-in) | iterative propose→validate loop | k×corpus |
| AgentFlow / AgentScaffold / ExploitSynth (opt-in) | multi-turn tool loops per target | varies |

**Default-path total ≈ F + 2N + (N…2N) ≈ F + 3N..4N requests**, all executed **sequentially** in `for` loops with `.await` per iteration, with a **fresh `reqwest::Client` built per request** (no connection reuse), **no concurrency cap in the client** (the `RateLimiter` exists in `src/rate_limiter.rs`, fully tested, and is wired to nothing), and **no cache**.

### 2.3 Concrete examples of the anti-patterns

**Per-finding enrichment without code context** (`src/report/ai_aggregation/enrichment.rs:40-95`) — asks the LLM to "describe this security finding" passing only title/severity/location/description/recommendation. The LLM cannot see the code; it hallucinates plausible text. On parse failure it sends a *second* retry prompt.

**String-match verdict parsing** (`src/scanner/phases/llm_phases/verification.rs:158-167`):
```rust
if response_with_model.content.contains("confirmed") {
    finding.verification_status = Some(VerificationStatus::Confirmed);
```
A response "this is NOT confirmed, it's a false positive" classifies as **Confirmed** because "confirmed" appears as a substring. Also, no `false_positive` → `Confirmed` ordering hazard: "false_positive" responses are checked second, but any mention of the word "confirmed" earlier in the text wins.

**Phantom config** — `config.example.toml` and `docs/operator-tuning.md` advertise:
```toml
[scanner.performance]
enable_llm_cache = true      # ← does not exist anywhere in src/
enable_file_filtering = true # ← does not exist anywhere in src/
max_parallel_tasks = 4       # ← does not exist anywhere in src/
[scanner]
commit_lookback_days = 90    # ← does not exist anywhere in src/
```
`grep` across `src/` finds zero references. The `LlmConfig.max_concurrent` field *does* exist in config parsing but is **never read** by `LlmClient` (a hardcoded `max_concurrent: 4` appears only in a test fixture). The operator tuning guide's "LLM-Cost-Sensitive Runs" profile is tuning knobs that do nothing.

**The noise-injection prompt** (`prompts/phases/llm_static_analysis.md`): the prompt first commands *"NEVER return empty arrays `[]`. ALWAYS provide detailed analysis"* with a template emitting a fake `CWE-1000 (Analysis Complete)` "finding" for clean files, and then **60 lines later** contradicts itself: *"IF NO VULNERABILITIES FOUND: Return an empty array `[]`"*. Depending on which instruction the model follows, you either get noise findings that flow through discovery/verification/aggregation (cost) or you get empty results; behavior is model-dependent and non-deterministic. There is also a stray Russian word ("конкретные") in the English prompt, indicating copy-paste from an LLM session.

**Multi-Verifier is fake** (`src/multi_verifier.rs:91-117`): `run_single_verifier` is explicitly commented `// Simulate different verifier behavior. In production, these would call actual verification APIs` and returns verdicts from `simple_hash(finding_id) % 3` plus keyword matches on "TODO"/"unsafe". It is **enabled by default** (`enable_multi_verifier = true`) and stamps `MajorityVerdict`s onto findings that look like real evidence in reports.

**PHP gap**: `src/indexer.rs` maps `php` → `.php` extensions (files are indexed), but `LlmAnalyzer::get_extensions()` (`src/llm_analysis.rs`) supports only c/cpp/python/js/ts/rust/go/java. PHP files are indexed and then **silently skipped** by LLM static analysis; tree-sitter grammars are loaded only for C/Rust/Python/JS. WordPress (≈90% PHP) is effectively unscannable beyond Semgrep.

---

## 3. Findings — UI/UX

### 3.1 CLI (`src/main.rs`)

**Good:** clap subcommands (`scan`, `resume`, `report`, `verify`), `--quiet`/`-v` levels mapped to tracing filters, Ctrl+C handler that points at the checkpoint, auto-resume from existing checkpoint, evidence-gate summary line.

**Problems found:**

1. **Duplicated result-writing logic** — `run_scan()` has two nearly identical ~35-line branches (`if !quiet` / `else`) that both serialize findings, count severities, and compute evidence tiers. Divergence risk (they already differ: quiet branch drops severity breakdown).
2. **`format_phase()` hand-maintains 26 phase variants** with hardcoded indices — the PhaseGraph was built to be the single source of truth, then main.rs re-implements a parallel table that already disagrees with it (e.g., `Complete` numbered 15, `ExploitSynth` 25).
3. **No `--version` flag**, no `--dry-run`, no `--max-requests`/budget flag, no `--preset` flag (needed for §7).
4. **Emoji-heavy logs** (`📁`, `🎉`, `⚠️`) via `tracing::info!` — inconsistent rendering across terminals/CI logs; some go to stderr via progress bar, some to stdout.
5. **No estimated cost preview.** A user pointing BACO at a 5,000-file repo has no way to know it's about to fire ~5,000+ sequential LLM calls before it's too late.
6. `verify` subcommand requires `LLM_CONFIG_PATH` env var rather than a `--config` flag — inconsistent with `scan`.
7. Exit code semantics are implicit (1 on scan failure, 2 on validation, 130 on Ctrl+C) but undocumented in `--help`.

### 3.2 HTML report (`src/report/html/`)

**Good:** severity filtering, confidence/CWE badges, evidence tiers, per-language Prism.js loading, SARIF + JSON + HTML outputs, evidence-gate appendix separating verified/supported/unverified.

**Problems found:**

1. **CDN dependency**: Prism.js core, theme, and language grammars load from `cdn.jsdelivr.net` at view time. In air-gapped/CI contexts the report renders unhighlighted. Should be embedded (the binary already embeds prompts via `include_str!`).
2. **No Markdown report** — `Commands::Report { format: "markdown" }` returns `"Markdown report not yet implemented"` (main.rs:501) despite PRs/comments/GitHub being Markdown-first. For an OSS-auditing tool this is the #1 missing artifact.
3. **No scan-to-scan diffing.** For CI and repeated OSS audits (the preset use-case), the report can't answer "what's new since last scan?". `checkpoint.json` already holds prior findings — the data needed for a diff view exists but is unused.
4. **Report timestamp is generation time, not scan time** (`chrono::Utc::now()` in the renderer); re-rendering an old findings.json falsifies the date.
5. **No token/cost section.** `LlmMetricsTracker` collects requests/tokens/latency per model and per operation, and even has `cached_requests` — but metrics are only partially surfaced. Also, since every call records `phase: "unknown"`, per-phase attribution is broken (see §5.3).
6. **No grouping by file/component** in the HTML — findings list flat; on WordPress-scale targets this becomes thousands of rows with no navigation (no file tree, no "group by root cause" toggle, although RootCauseDedup data exists).
7. **No deep-linking/filter state in URL** — filters reset on reload; can't share "show me confirmed high-severity PHP findings" links.

### 3.3 Progress UX

Single `indicatif` bar whose position is manually managed (`base + progress_pct` with magic constants like `pb.set_position(300)` for "parallel done"). Phases emit overlapping messages; per-phase sub-bars exist in `MultiProgress` but only one bar is used. On a 24-phase run with per-finding loops, the user sees "Enriching findings [127/?]" with no ETA, no request counter, no cost ticker.

---

## 4. Findings — Code Quality

### 4.1 What's good

- `thiserror` used in the newer modules (`multi_verifier`, `staging`, `error.rs`).
- `PhaseGraph` data-driven design is genuinely nice — phases + metadata in one place.
- Prompt system (`prompt/loader.rs`) with file-based templates, `include_str!` fallbacks, and config overrides is well thought out.
- Evidence model (`evidence.rs`) with tiers (Verified/Supported/Unverified) and the evidence gate is a strong, differentiating design.
- Sandbox with per-tool timeouts for the agent; mock LLM for integration tests.

### 4.2 Problems (concrete)

1. **Stringly-typed errors dominate**: most of the pipeline returns `Result<_, String>` (all phase functions, `LlmClient`, agent session). Error causes, kinds, and retryability are uninspectable; `phase functions return String` forces `.map_err(|e| e.into())` everywhere.
2. **The 16-arm tuple match** in `run_parallel_phases` (orchestrator.rs:120-187) to satisfy `tokio::join!` over optional futures — should be `Vec<JoinHandle>` + `futures::future::join_all`; the current code adds a new combinatorial arm for every future phase added.
3. **Two different `LlmConfig` types**: `config::LlmConfig` (global `[llm]` settings) and `llm::LlmConfig` (client settings), manually re-assembled at every phase (`verification.rs:541-557`, `static_analysis.rs:140-150`, …). Field drift already happened (temperature is sometimes hardcoded 0.5 instead of `config.llm.temperature` — `main.rs:555`).
4. **Misleading API**: `Scanner::findings_mut(&self) -> Vec<VulnerabilityFinding>` returns a **clone** despite the `_mut` name.
5. **Dead/duplicated code**: `check_early_termination` marked `#[allow(dead_code)]` while its body is copy-pasted inline twice in `orchestrator.rs`; `PhaseResult` type alias dead; `format_phase` duplicates PhaseGraph metadata; `retrieve_cwe_specs` is a one-line wrapper around `retrieve_cwe_specs_inner` that exists only to be re-exported.
6. **CI config typo**: `.github/workflows/ci.yml` triggers on `branches: ain, master]` — missing opening `[`; the intent (`main` vs `ain`) is ambiguous and `ain` is almost certainly wrong.
7. **Config surface drift** (the phantom options of §2.3) is the worst instance of a general pattern: docs, `config.example.toml`, and code are three different languages for the same settings.
8. **`worktree_staging`/`staging` module overlap**: two staging subsystems (`src/staging/` and `src/worktree_staging.rs`) with overlapping responsibilities.
9. **Unbounded `exclude_paths` matching is substring-based** (`should_exclude` does `path_str.contains(exclude)`) — the documented glob patterns like `"docs/*"` never match globs; they match by substring, so `"src"` would exclude `src/` AND `assets/src/` AND any file containing "src".
10. **Retry loop retries non-retryable errors**: `try_chat_request` retries on *any* non-2xx including 400/401/403 (bad request/auth will never succeed) while honoring no `Retry-After` header on 429.
11. **`truncate_code` slices by bytes** (`&code[..8000]`) — panics on multi-byte UTF-8 boundaries for non-ASCII source files (a real risk with i18n-heavy PHP/JS).
12. **Phase-gate inconsistency**: the architecture doc says phases gate on specific config (e.g., ThreatModeling on `aggregation.tier_2_features`), but code gates on `scanner.performance.enable_threat_modeling`; new phase flags live in yet another section. Four different config sections gate the pipeline.

---

## 5. Findings — Tests

### 5.1 What's good

- **~3,000 unit test functions** across ~120 test files; integration tests with a mock LLM (`agent/mock_llm.rs`), determinism tests, e2e agent tests, SARIF/HTML report tests, checkpoint-resume tests, CLI integration tests. `cargo tarpaulin` coverage runs in CI with codecov badge. This is far above average for a hobby/research tool.

### 5.2 Problems

1. **Tests validate the stubs, not reality.** `multi_verifier` has extensive tests asserting the hash-modulo behavior — the suite locks in fake semantics and gives false confidence ("Multi-Verifier tested ✔"). Same for parts of `poc_generation` (template strings asserted verbatim) and `generate_recommendation`'s keyword-matching.
2. **No golden-file tests for prompts**: prompt markdown files can (and did) drift into self-contradiction without any test noticing. A test asserting "empty-array instruction appears exactly once" would have caught §2.3's contradiction.
3. **No cost/behavioral regression tests for the LLM loops**: nothing asserts "verifying K findings issues ≤ ceil(K/batch) requests". Request-count assertions are the single most valuable test class for this project's goal, and there are none.
4. **No mock-server HTTP tests for `LlmClient`** retry/backoff/429 handling — retry logic is untested against realistic status codes (there are `cve_client_network_tests.rs` for CVE fetching but nothing exercising the LLM retry ladder, e.g., via `wiremock`/`httpmock`).
5. **Fixture coverage gap**: `tests/fixtures/vulnerable-project/` is 2 tiny Python files; there are no PHP/JS/Rust fixtures despite the supported-language matrix, and no WordPress-like fixture at all.
6. **Flaky-by-design risks**: `cve_client_network_tests.rs` and anything hitting real NVD/KEV endpoints in CI without recorded fixtures.

---

## 6. Findings — AI Efficiency & Intelligence (the core)

### 6.1 Efficiency: where the money burns

1. **No batching anywhere in the default path.** Discovery, verification, enrichment all send one request per finding with tiny prompts (<300 tokens). Batching 8–10 findings per verification request is mechanically easy (the response schema is an array) and cuts those phases by ~90%.
2. **No LLM cache.** `enable_llm_cache` is advertised, `LlmMetrics` even has a `cached_requests` counter — but no cache implementation exists. Re-running a scan on a slightly changed branch re-pays 100% of the cost for 99% unchanged files.
3. **No prompt-prefix caching discipline.** The CWE-specs RAG block (fetched via BM25) is embedded mid-prompt *after* file-specific content; providers' automatic prompt caching (OpenAI/Anthropic/KGKV-style) rewards stable prefixes. System prompt + hunt-domain knowledge should be byte-stable across requests to harvest 50–90% discounts on the static prefix.
4. **Sequential loops with per-request client construction.** Each `chat()` builds a new `reqwest::Client` (new connection pool, new TLS handshake). With F sequential calls this dominates wall-clock. One shared client + `buffer_unordered(concurrency)` turns the same request count into a fraction of the latency.
5. **Discovery phase is redundant by construction.** LlmStaticAnalysis already produced a full description + `fix_code` for every finding *with the code in context*. LlmDiscovery then re-describes each finding *without the code*. For semgrep-sourced findings (no description), enrichment makes sense; for LLM-sourced findings it's paying twice for a worse result.
6. **`analyze_file` truncation wastes the tail of every large file.** Files >8,000 chars are silently cut — the "interesting" sinks are often past line 300 in real codebases. No chunking, no windowing around tree-sitter-identified functions, no "analyze the tail next" follow-up. This simultaneously *wastes* requests (huge prefix, truncated payload) and *misses* vulnerabilities.
7. **No file triage/prioritization.** Tests, vendored code, generated code, minified JS, docs, fixtures — all get the same full LLM pass. A WordPress core checkout spends most of its budget on `wp-content/themes/*/assets/*.js` before touching `wp-includes/`.
8. **Retry-on-parse-failure double-pays** (enrichment): when JSON parsing yields empty fields, it re-sends a different, simpler prompt rather than enforcing structured output in the first place.
9. **Fake token accounting** blocks any budget feature: prompt tokens are approximated as `content.len()/4` and completion as `messages.len()`-ish counts (llm.rs `record_metrics`); the API's `usage` field is discarded. Every cost feature the user wants (budgets, dry-run estimates, cost report) needs real usage data.

### 6.2 Intelligence: where it's dumb (and how to make it smarter)

1. **Verification without code is not verification.** The verification prompt (§2.3) contains title/description/location only. A model asked "is this real?" without the code will mostly echo the finding's confidence. **Fixing this is the highest intelligence-per-line change in the codebase**: attach `code_snippet` (already on the finding) + ±5 lines of context (the file is on disk) + the CWE knowledge block for the finding's CWE.
2. **Self-contradictory prompt → nondeterministic noise** (§2.3). Pick one behavior (recommend: empty array for clean files; drop the `CWE-1000` fake-finding template entirely) and add a golden test.
3. **The MoE router exists but is orphaned.** `router/registry.toml` maps CWE-79 → `xss_specialized`, CWE-89 → `sqli_specialized`, etc., but **no such prompt files exist** in `prompts/` — the specialized routing targets nothing. Meanwhile excellent, already-written domain prompts (`prompts/hunt/xss.md`, `injection.md`, `path_traversal.md`, `deserialization.md`, `crypto.md`, `auth.md`, `resource.md`) are loaded by `load_hunt_prompts()` but only referenced as a placeholder string in verification (`[Hunt context: {} vulnerability - analyze with domain-specific patterns]` — verification.rs:143, with a comment admitting it's a placeholder). Wiring hunt prompts into the CWE router for *both* static analysis and verification is nearly free intelligence.
4. **CWE RAG query is weak**: BM25 query = file path + first 20 lines (`retrieve_cwe_specs_inner`). First 20 lines are usually imports/licenses. Query should be built from sink calls, taint-relevant tokens, and semgrep CWE hints — the code has tree-sitter and semgrep output available but uses neither for retrieval.
5. **Finding-centric analysis would beat file-centric.** For findings that come from semgrep, the right unit of LLM work is *the finding with its data-flow window*, not the whole file. The `context/` module family (callee walker, triple-path, control path) already builds rich function-level context — but only behind opt-in research flags. Promote the callee/call-site extraction into the default verification path.
6. **Dedup happens too late.** Semgrep + LlmStaticAnalysis regularly produce the same issue twice (same file/line/CWE). RootCauseDedup runs at phase 17 — *after* discovery, verification, and enrichment have already paid for both duplicates. A cheap structural dedup (file, line±2, CWE) immediately after the parallel block would remove a large fraction of downstream N.
7. **Confidence signals exist but don't gate spend.** Findings with high semgrep confidence + matching CWE-spec evidence + LLM static analysis don't need another verification call; findings with conflicting signals need *more* context, not another vote. The pipeline spends uniformly.
8. **Multi-Verifier should either be real or removed.** Today it decorates findings with hash-based verdicts — actively misleading. If kept: batch-vote with real calls (one request, N findings × K voters in a single structured response is enough — voters see the same context; disagreement is the signal). If not: delete it and stop advertising 24 phases.
9. **No call for structured outputs / function calling in the main path.** `chat_with_tools` exists (used by the agent), but discovery/verification/enrichment use freeform JSON with fence-stripping. `response_format: {type: "json_schema"}` (or tools-as-schema on providers without it) would eliminate the parse/retry tax.
10. **Git history is underused.** GitAnalysis cross-references tickets/commits, but churn/authorship is also the cheapest *pre-LLM* prioritization signal (hot files deserve analysis; untouched-for-5-years files deserve less). `git_analysis` already computes patterns — feed them into file ranking.
11. **No feedback loop.** `ConfidenceRefinement` ships `HistoricalData`/`record_verification` APIs (false-positive patterns per CWE) that are never persisted across scans. Persisting "CWE-79 in this repo pattern X was FP 12 times" would compound intelligence run over run — exactly what a preset-based OSS workflow needs.

---

## 7. Task List (prioritized, no timelines)

### P0 — Stop the bleeding (correctness + cost)

- [ ] **T1. Fix the static-analysis prompt contradiction.** Remove the "NEVER return empty arrays / CWE-1000 fake finding" block; keep the empty-array contract. Add a golden-file test that fails if both instructions coexist.
- [ ] **T2. Include code in verification prompts.** In `run_llm_verification` (non-agent path), append `finding.code_snippet` + ±5 context lines read from disk + the hunt-domain prompt for the finding's CWE (`cwe_to_hunt_domain` already maps it). This is ~20 lines of code.
- [ ] **T3. Replace `contains()` verdict parsing** with strict JSON parsing (serde into a `VerificationVerdict` struct); treat unparseable output as `NeedsReview` with the raw text stored in notes.
- [ ] **T4. Make Multi-Verifier honest.** Either (a) wire it to real batched LLM voting, or (b) default `enable_multi_verifier = false` and label the phase "experimental stub" in docs/report until it's real. Do not ship hash-based verdicts as evidence.
- [ ] **T5. Implement the LLM cache or remove the flag.** Content-addressed cache: key = SHA256(model, normalized messages, temperature, max_tokens); value = response; persisted under `output_dir/llm-cache/` (or `~/.cache/baco/`); TTL + invalidation on file hash change. Honor `enable_llm_cache` everywhere `chat()` is called (centralize in `LlmClient`), and record real `cached_requests` metrics.
- [ ] **T6. Reuse one `reqwest::Client`** (static/lazy `OnceLock<reqwest::Client>` in `LlmClient`) — eliminate per-request pool construction.
- [ ] **T7. Wire the existing `RateLimiter`** into `LlmClient::chat` with permits from `llm.max_concurrent` (currently unread). Cap *all* call sites, not just one phase.
- [ ] **T8. Don't retry 4xx.** In `try_chat_request`, classify statuses: retry 408/429/5xx only; honor `Retry-After`; fail fast on 400/401/403 with actionable messages.
- [ ] **T9. Use real token usage.** Parse `usage.prompt_tokens`/`completion_tokens` from the API response into `record_metrics`; delete the `len()/4` heuristics. Thread the phase name into metrics (fix `phase: "unknown"`).
- [ ] **T10. Fix `truncate_code` UTF-8 panic** (slice on `char_indices` boundaries / use `floor_char_boundary`).
- [ ] **T11. Remove or implement phantom config**: `enable_llm_cache` (T5), `enable_file_filtering`, `max_parallel_tasks`, `commit_lookback_days`. Implement the cheap two (`file_filtering` = skip minified/generated/vendor patterns; `max_parallel_tasks` = semaphore permits for the parallel phase block + LLM concurrency default), and delete `commit_lookback_days` or thread it into `git_analysis`.
- [ ] **T12. Fix CI branch typo** (`ain, master]` → `[main, master]`) and the duplicate README "What happens next"/"First scan sequence" blocks.
- [ ] **T13. Structural dedup before LLM phases**: after the parallel block, collapse findings sharing (normalized file, line±2, CWE, similar title) — before CweRouting/LlmDiscovery/LlmVerification pay for duplicates.

### P1 — Structural efficiency & intelligence (the big multipliers)

- [ ] **T14. Batch verification + enrichment.** New `verify_batch(findings[≤10]) -> Vec<Verdict>` with a single structured request (array in, array out). Same for enrichment. Expected request reduction on those phases: ~10×.
- [ ] **T15. Merge discovery into the producers.** (a) LLM-sourced findings already have descriptions + fix_code from static analysis — skip LlmDiscovery for them (gate on `finding.sources`). (b) Semgrep-sourced findings get enriched *with code context attached* (currently description-only). Net: discovery cost ≈ only-for-semgrep-findings.
- [ ] **T16. Enforce structured outputs.** Add `response_format` JSON-schema support in `LlmClient` (OpenAI-compatible), fall back to a tool-schema forced call on providers lacking it. Use in discovery/verification/enrichment/rulesynth. Eliminates the enrichment retry path.
- [ ] **T17. Two-tier model cascade ("triage cheap, analyze deep").** Per-phase model config gains a `triage` entry: cheap/fast model does a first pass (file summary + suspicion score, batched, small output); strong model only analyzes files that clear a suspicion threshold. Config: `[llm.phases.triage]`. Research flags (VulTriage/PacVD) then apply only to the deep tier.
- [ ] **T18. File prioritization & budget.** Pre-LLM ranking of files by: semgrep hit density, git churn (reuse `git_analysis`), entry-point patterns (per preset), size, path entropy (skip vendored/test/docs/minified via real glob semantics — fix `should_exclude` substring matching too, see T24). New `[budget]` config: `max_llm_requests`, `max_tokens`, `stop_when_reached` → the scanner processes in priority order and stops cleanly at budget, recording what was skipped.
- [ ] **T19. Fix chunking for large files.** Replace 8,000-char truncation with tree-sitter function-level windows: analyze per function (or per ~120-line window at function boundaries), carry a one-line "module summary" header from previous chunks. No silent tail-dropping.
- [ ] **T20. Prompt-prefix caching layout.** Reorder prompts to a stable prefix: system prompt → hunt-domain/CWE knowledge (stable per domain) → project context → volatile code last. Keep prefixes byte-identical across calls to harvest provider prompt caching.
- [ ] **T21. Wire the MoE router to real prompts.** Create `prompts/hunt/`-backed specialized templates for the registry's existing keys (xss/sqli/buffer-overflow/c/rust), or generate registry entries *from* `cwe_to_hunt_domain`. Route both static analysis and verification.
- [ ] **T22. Better CWE-RAG queries.** Build the BM25 query from sink tokens + tree-sitter call extraction + semgrep CWEs instead of "path + first 20 lines".
- [ ] **T23. Persist the feedback loop.** Serialize `ConfidenceRefinement::HistoricalData` (per-CWE FP patterns + stats) into `output_dir/` and reload on next scan; presets (§8) can seed it with project-specific FP patterns (huge for WordPress).
- [ ] **T24. Real glob exclusion.** Implement `globset`-based `exclude_paths` matching the documented syntax; add preset-driven default excludes (see presets).
- [ ] **T25. Refactor phase concurrency.** Replace the 16-arm `tokio::join!` match with a `Vec<JoinHandle>` + `join_all`; make the parallel set data-driven from PhaseGraph (phases declare `parallelizable: true`).
- [ ] **T26. Unify the two `LlmConfig`s** into one client-construction helper (`LlmClient::for_phase(&config, Phase::Discovery)`) to kill per-phase drift (temperature hardcoding etc.).
- [ ] **T27. `thiserror` for pipeline errors** (phase results, LlmClient, agent) with a `ScanError` taxonomy: retryable/non-retryable, phase, context. Enables smarter retry + better UX.

### P2 — UX, presets, ecosystem

- [ ] **T28. Implement the Markdown report** (`baco report --format markdown`): findings grouped by severity/file, code fences, CWE links, triage verdicts, cost table. This is the artifact GitHub issues/PRs consume.
- [ ] **T29. Scan-to-scan diffing.** `baco scan --baseline previous-findings.json` → report gains "New / Fixed / Regressed / Unchanged" sections; SARIF diff for CI gating. Data already in checkpoints.
- [ ] **T30. `--dry-run` + cost estimate.** Print: files indexed, files by priority tier, estimated LLM requests/tokens per phase, estimated cost (with per-model price table in config). No LLM calls issued.
- [ ] **T31. Embed Prism.js** (+ theme) via `include_str!`/`rust-embed`; zero CDN dependency.
- [ ] **T32. Report UX for scale**: file/component grouping, group-by-root-cause toggle, URL-encoded filter state, per-phase request/token/cost table (from fixed metrics, T9), scan-timestamp instead of render-timestamp.
- [ ] **T33. CLI consistency**: `--config` for `verify`; `--version`; `--preset <name>` (loads `presets/<name>.toml` shipped with the binary or from `~/.config/baco/presets/`); document exit codes.
- [ ] **T34. Kill duplicated main.rs branches** (quiet/non-quiet) — one writer function, quiet controls only printing.
- [ ] **T35. De-duplicate `format_phase`** — drive from PhaseGraph metadata.
- [ ] **T36. Test upgrades**: request-count regression tests (mock LLM counts calls per phase; assert batching bounds); prompt golden tests; LlmClient retry tests with `wiremock`; add PHP/JS/Rust + WordPress-like fixtures.
- [ ] **T37. Docs pass**: regenerate `config.example.toml` from the actual struct (write a `baco config-docs` subcommand or a doc test that fails when the TOML references unknown keys — kill config drift permanently); fix operator-tuning.md profiles to reference only real flags; document the cost model per phase.
- [ ] **T38. PHP language support** (prerequisite for WordPress presets): add `php` to `LlmAnalyzer::get_extensions`, add `tree-sitter-php`, add PHP hunt-prompt section (hooks, `$wpdb->query`, `$_GET/$_POST/$_REQUEST`, `esc_html*` vs `echo`, `unserialize`, `eval`, nonce checks, capability checks), and verify semgrep `p/php` + `p/wordpress` rulesets flow through findings.
- [ ] **T39. Presets v1** — see §8: ship `presets/wordpress-core.toml`, `presets/wordpress-plugin.toml`, `presets/litellm.toml`, `presets/oss-python.toml`, `presets/oss-monorepo.toml`.
- [ ] **T40. Sandbox-by-default for agent/auto-patch on untrusted OSS code**: auto-patch runs git commands and writes files; presets for third-party code should force `agent_flow.trusted_paths` to a staging copy only (worktree staging already exists — make presets use it).

*(All tasks are independent of timelines; T1–T13 are small, T14–T27 are structural, T28+ are additive.)*

---

## 8. Preset System for Large OSS Targets

### 8.1 Why presets matter here

BACO's config is already TOML-driven, which is the right substrate. What's missing is a **project-type-aware layer**: today, pointing BACO at WordPress vs LiteLLM vs a Rust CLI differs only by `languages` + `exclude_paths`, while the *interesting* dimensions (entry points, sink patterns, semgrep rulesets, FP-prone patterns, file priorities, model tiers, budgets) are hardcoded or absent. A preset should encode **everything the scanner needs to know about a class of project**.

Proposed loading order (implemented in T33/T39):

```
built-in defaults  →  preset file (bundled or ~/.config/baco/presets/<name>.toml)
                   →  user config.toml  →  CLI flags
```

New TOML sections a preset may set (each maps to an existing or task-listed feature):

| Section | Purpose | Status |
|---|---|---|
| `[project]` / `[scanner]` / `[llm.phases.*]` | already exist | ✅ |
| `[scanner.semgrep] config` | ruleset selection (`p/wordpress`, `p/php`, `p/python`, `p/bandit`...) | partial (runner supports `--config`) |
| `[priority]` | entry-point/sink patterns → file ranking (T18) | new |
| `[budget]` | max requests/tokens, stop behavior (T18) | new |
| `[triage]` | cheap-model first pass + thresholds (T17) | new |
| `[knowledge.fp_patterns]` | seed `ConfidenceRefinement` historical FP data per CWE (T23) | new |
| `[languages.php]` | language pack flag (T38) | new |

### 8.2 Preset: WordPress core (`presets/wordpress-core.toml`)

Design notes: WordPress core is ~500k LOC, ≈90% PHP + bundled JS libs. The naive full-file LLM pass would cost thousands of requests for near-zero yield on `wp-content/themes`. The preset (1) excludes everything not security-relevant, (2) prioritizes request-handling entry points (admin-post, ajax handlers, REST controllers, xmlrpc, upload handling), (3) leans on semgrep `p/wordpress` + `p/php` first (cheap), (4) uses the LLM only where semgrep flags or entry-point logic concentrates, (5) hard-codes WordPress-specific FP patterns (nonce-verified, capability-checked code is the #1 FP source).

```toml
# BACO preset — WordPress core (requires T38 PHP support)
# Usage: baco scan --config my.toml --preset wordpress-core

[project]
name = "wordpress-core"
path = "./wordpress"
languages = ["php", "javascript"]

[scanner]
max_file_size_kb = 256
exclude_paths = [
  "wp-content/*",        # themes/plugins shipped for testing — not core attack surface
  "wp-includes/js/*",    # vendored JS libs (tinymce, jquery, ...)
  "wp-includes/ID3/*",
  "wp-includes/Requests/*",
  "wp-includes/SimplePie/*",
  "wp-includes/Text/*",
  "tests/*", "tools/*", "docs/*", "src/wp-includes/js/*",
  "*.min.js",            # minified assets (needs T24 glob support)
]

[scanner.semgrep]
# Cheap first pass: everything semgrep+wordpress can find without LLM
config = ["p/wordpress", "p/php", "p/security"]

[scanner.performance]
enable_incremental_scan = true   # WP moves slowly between minor versions
enable_llm_cache = true          # T5 — re-audits on point releases become cheap
enable_root_cause_dedup = true
enable_multi_verifier = false    # stub today (T4); don't decorate WP findings with hash votes
enable_variant_search = true     # WP is variant heaven (same bug copy-pasted in 20 files)
enable_cve_bootstrap = true      # WP has rich CVE history — feed it early
enable_threat_modeling = false

[llm]
timeout_secs = 90
max_concurrent = 6               # T7: actually enforced
temperature = 0.2

[llm.phases.discovery]
# cheap triage tier over entry-point files (T17)
models = ["mistral-small"]

[llm.phases.verification]
# strong tier only for findings that survived triage
model = "mistral-medium"

[llm.phases.aggregation]
model = "mistral-medium"

# --- new sections (T17/T18/T23) ---
[triage]
enabled = true
model = "mistral-small"
batch_size = 8                  # files per triage request
suspicion_threshold = 0.35      # deep analysis if >= threshold
include_code_in_summary = false # signatures + sink lines only

[priority]
# ranked: higher first. Entry points that receive untrusted request data.
entry_point_patterns = [
  "wp-admin/admin-post.php", "wp-admin/admin-ajax.php",
  "wp-admin/includes/*", "wp-admin/options.php",
  "wp-includes/rest-api/*",
  "wp-includes/class-wp-xmlrpc-server.php",
  "xmlrpc.php",
  "wp-admin/includes/file.php", "wp-admin/includes/image.php",
  "wp-includes/pluggable.php", "wp-includes/user.php",
  "wp-includes/formatting.php", "wp-includes/kses.php",
]
sink_patterns = [               # boost files containing these
  "$wpdb->query", "$wpdb->get_results", "$wpdb->prepare",
  "unserialize(", "maybe_unserialize(",
  "eval(", "create_function(", "preg_replace(.*e'",
  "$_GET", "$_POST", "$_REQUEST", "$_FILES", "$_COOKIE",
  "wp_handle_upload", "move_uploaded_file",
  "system(", "exec(", "shell_exec(", "passthru(", "proc_open(",
  "include(", "require(", "include_once", "require_once",
  "wp_redirect", "wp_kses(",
]
churn_weight = 0.3              # recent commits add priority (git_analysis reuse)

[budget]
max_llm_requests = 600          # core audit ceiling; ~10k+ files → ranked subset
max_tokens = 6_000_000
on_budget_exhausted = "stop_and_report"   # report what was skipped

[knowledge.fp_patterns]
# Seed the confidence-refinement feedback loop (T23): WordPress FP classics
"CWE-79" = [
  "esc_html(", "esc_attr(", "esc_url(", "wp_kses_post(",
  "esc_textarea(", "esc_js(",   # already escaped → XSS finding is FP
]
"CWE-89" = [
  "$wpdb->prepare(",             # parameterized → SQLi finding is FP
]
"CWE-352" = [
  "check_admin_referer(", "wp_verify_nonce(", "check_ajax_referer(",
]
"CWE-862" = [                    # missing-authorization FPs
  "current_user_can(", "user_can(", "is_admin()",
]
```

### 8.3 Preset: WordPress plugin (`presets/wordpress-plugin.toml`)

Plugins are smaller (100–5,000 files) but *nastier*: they're the actual attack surface in most real-world WP compromises, quality varies wildly, and the same anti-patterns repeat (unprefixed globals, direct `$_REQUEST` use, no nonce). Compared to core: no huge exclusions needed, tighter entry-point logic (hooks registered by the plugin itself), and a lower budget.

```toml
# BACO preset — WordPress plugin
[project]
languages = ["php", "javascript"]

[scanner]
max_file_size_kb = 512
exclude_paths = [
  "node_modules/*", "vendor/*", "dist/*", "build/*",
  "assets/*", "*.min.js", "*.min.css",
  "tests/*", "test/*", "spec/*", "cypress/*", "playwright/*",
  "*.map",
]

[scanner.semgrep]
config = ["p/wordpress", "p/php", "p/security"]

[scanner.performance]
enable_incremental_scan = true
enable_llm_cache = true
enable_multi_verifier = false
enable_variant_search = true
enable_cve_bootstrap = true

[llm]
temperature = 0.2
max_concurrent = 4

[llm.phases.discovery]
models = ["mistral-small"]

[llm.phases.verification]
model = "mistral-medium"

[triage]
enabled = true
model = "mistral-small"
batch_size = 8
suspicion_threshold = 0.30

[priority]
# plugins live or die by their hooks — find the hook registrations, then
# trace the callbacks
entry_point_patterns = [
  "add_action(", "add_filter(", "register_rest_route(",
  "register_activation_hook(", "register_admin_menu_page(",
  "admin_post_", "wp_ajax_", "init.php", "admin.php",
  "uninstall.php", "xmlrpc",
]
sink_patterns = [
  "$wpdb->query", "$wpdb->get_results", "$wpdb->prepare",
  "unserialize(", "maybe_unserialize(",
  "eval(", "assert(", "preg_replace(",
  "$_GET", "$_POST", "$_REQUEST", "$_FILES",
  "move_uploaded_file(", "file_get_contents(", "fopen(",
  "include", "require",
  "wp_enqueue_script", "wp_localize_script", "wp_add_inline_script",  # XSS sinks
  "header('Location:", "wp_redirect(", "wp_safe_redirect(",
  "curl_init(", "wp_remote_get(", "wp_remote_post(",   # SSRF sinks
  "base64_decode(", "str_rot13(", "gzinflate(",        # obfuscation smell
  "shell_exec", "system(", "exec(", "passthru(",
]

[budget]
max_llm_requests = 250
max_tokens = 2_500_000
on_budget_exhausted = "stop_and_report"

[knowledge.fp_patterns]
"CWE-79"  = ["esc_html(", "esc_attr(", "esc_url(", "wp_kses", "sanitize_text_field("]
"CWE-89"  = ["$wpdb->prepare(", "$wpdb->insert(", "$wpdb->update(", "$wpdb->delete("]
"CWE-352" = ["wp_verify_nonce(", "check_admin_referer(", "check_ajax_referer("]
"CWE-862" = ["current_user_can(", "is_admin()", "manage_options"]
```

### 8.4 Preset: LiteLLM (`presets/litellm.toml`)

LiteLLM is a large, high-quality Python (FastAPI) proxy — the security profile is completely different: **auth bypass on admin routes, SSRF via user-supplied base URLs, API-key/secret leakage in logs, YAML/JSON deserialization, path traversal in file-backed config, and dependency confusion via dynamic imports.** Python is fully supported by BACO today, so this preset works with the current codebase except for the new `[triage]`/`[budget]`/`[priority]` sections (T17/T18).

```toml
# BACO preset — LiteLLM (Python/FastAPI gateway)
[project]
name = "litellm"
languages = ["python"]

[scanner]
max_file_size_kb = 512
exclude_paths = [
  "tests/*", "test/*", "tests_local/*",
  "docs/*", "examples/*", "cookbook/*",
  "ui/*",                       # Next.js frontend — separate preset if needed
  ".github/*", "benchmarks/*", "scripts/*",
  "litellm/_vendor/*",          # vendored deps
  "*.lock",
]

[scanner.semgrep]
config = ["p/python", "p/bandit", "p/flask", "p/security"]

[scanner.performance]
enable_incremental_scan = true
enable_llm_cache = true
enable_root_cause_dedup = true
enable_multi_verifier = false
enable_variant_search = true
enable_cve_bootstrap = true

[llm]
temperature = 0.2
max_concurrent = 6

[llm.phases.discovery]
models = ["mistral-small"]

[llm.phases.verification]
model = "mistral-medium"

[triage]
enabled = true
model = "mistral-small"
batch_size = 10
suspicion_threshold = 0.30

[priority]
# LiteLLM attack surface, ranked
entry_point_patterns = [
  "litellm/proxy/",             # the FastAPI gateway itself
  "litellm/proxy/proxy_server.py",
  "litellm/proxy/auth/",        # auth backends (JWT, LDAP, SSO) — bypass heaven
  "litellm/proxy/management_endpoints/",
  "litellm/proxy/openai_files_endpoints/",
  "litellm/proxy/spend_management/",
  "litellm/integrations/",
  "litellm/router.py", "litellm/constants.py",
]
sink_patterns = [
  "requests.", "httpx.", "aiohttp.",          # SSRF surface
  "base_url", "api_base",                     # user-controlled endpoints
  "yaml.load", "yaml.safe_load",              # deserialization
  "pickle.", "marshal.",
  "os.system", "subprocess.", "os.popen",
  "eval(", "exec(",
  "open(", "os.path.join",                    # path traversal
  "api_key", "master_key", "sk-", "Bearer ",  # secret handling / leakage
  "logging.", "print(",                       # secret leakage into logs
  "tempfile.", "shutil.",
  "Dockerfile", "docker-compose",
]

[budget]
max_llm_requests = 800          # litellm is big; triage keeps effective coverage
max_tokens = 8_000_000
on_budget_exhausted = "stop_and_report"

[knowledge.fp_patterns]
# FastAPI idioms that trip generic scanners
"CWE-78"  = ["shell=False", "shlex.quote(", "subprocess.run([", "subprocess.Popen(["]
"CWE-79"  = ["JSONResponse", "orjson.dumps", "HTTPException"]  # API JSON ≠ HTML XSS
"CWE-611" = ["defusedxml", "xml.etree.ElementTree.fromstring"] # guarded parse
```

### 8.5 Preset: generic large OSS / monorepo (`presets/oss-monorepo.toml`)

The "other big things" case — when the target is too big to reason about (Linux-style C/C++ projects, big Python frameworks, mixed-language monorepos):

```toml
[project]
languages = ["c", "cpp", "python", "javascript", "rust"]  # subset as needed

[scanner]
max_file_size_kb = 512
exclude_paths = [
  "node_modules/*", "vendor/*", "third_party/*", "thirdparty/*",
  "external/*", "deps/*", "submodules/*",
  "tests/*", "test/*", "testing/*", "spec/*", "e2e/*", "fixtures/*",
  "docs/*", "examples/*", "samples/*", "demo/*", "benchmarks/*",
  "dist/*", "build/*", "out/*", "target/*", ".venv/*", "site-packages/*",
  "*.min.js", "*.bundle.js", "*.map", "*_pb2.py", "*.pb.cc", "*.pb.h",
]

[scanner.performance]
enable_incremental_scan = true
enable_llm_cache = true
enable_multi_verifier = false

[llm.phases.discovery]
models = ["mistral-small"]      # triage tier

[llm.phases.verification]
model = "mistral-medium"        # strong tier

[triage]
enabled = true
batch_size = 10
suspicion_threshold = 0.40      # higher bar on unknown codebases

[priority]
entry_point_patterns = [        # language-agnostic entry points
  "main.c", "main.rs", "main.py", "index.js", "app.py", "server.py",
  "cli/", "api/", "routes/", "controllers/", "handlers/",
  "endpoints/", "servlet", "cmd/",
]
sink_patterns = [
  "strcpy", "strcat", "sprintf", "memcpy", "gets(",
  "system(", "exec", "popen", "shell=True", "eval(", "unserialize",
  "SELECT", "query(", "execute(",
  "innerHTML", "dangerouslySetInnerHTML", "document.write",
  "os.system", "subprocess", "open(",
]
churn_weight = 0.4              # hot files first

[budget]
max_llm_requests = 1000
max_tokens = 10_000_000
on_budget_exhausted = "stop_and_report"
```

### 8.6 Preset mechanics worth adding while at it

- [ ] **T41. `baco preset list` / `baco preset show <name>`** — discoverability of the shipped presets.
- [ ] **T42. Preset validation tests**: every shipped preset must parse into `ScannerConfig` + new sections and pass a "dry-run on a fixture tree" test (T30 makes this cheap).
- [ ] **T43. Semgrep ruleset wiring**: the runner supports `--config`; presets should support an array of rulesets, and findings should carry which ruleset found them (report grouping + FP-feedback per ruleset).
- [ ] **T44. CPE hint per preset**: for WordPress/LiteLLM, `cve_bootstrap` can target the known CPE (e.g. `cpe:2.3:a:wordpress:wordpress`) instead of NVD dependency guessing — sharper CVE enrichment, fewer wasted NVD calls.

---

## 9. Request-Reduction Playbook (the math)

For a concrete feel, take a target with **F = 1,000 indexed files** and **N = 250 findings** (typical for a WordPress-plugin-scale audit; multiply linearly for bigger targets):

| Strategy | Task | Requests before | Requests after | Notes |
|---|---|---|---|---|
| Baseline (defaults, all opt-ins off) | — | 1,000 (static) + 250 (discovery) + 250 (verification) + ~375 (enrichment+retries) ≈ **1,875** | — | sequential, uncached |
| Structural dedup pre-LLM (say 30% dupes) | T13 | 1,875 | ~1,600 | removes duplicate downstream N |
| Discovery only for semgrep findings | T15 | ~1,600 | ~1,350 | LLM findings already described |
| Batch verification+enrichment (×8) | T14 | ~1,350 | ~1,050 | 500 per-finding calls → ~65 |
| Triage tier (60% of files cleared as low-risk) | T17 | ~1,050 | ~700 | 1,000 file calls → 400 triage + ~250 deep |
| Prioritization + vendor/test exclusion (typ. −40% files) | T18/T24 | ~700 | ~450 | budget-capped by construction |
| LLM cache on re-scan after small change (~5% files touched) | T5 | ~450 | **~50–80** | cache hits for unchanged files+prompts |
| Prompt-prefix caching | T20 | — | −50–90% *token cost* on cached prefixes | request count unchanged |

**Net: first full scan ≈ −75% requests; incremental re-scans ≈ −95%.** And critically, the *remaining* requests are smarter: verification finally sees code (T2), domain hunt-prompts ride the router (T21), and every phase reports real token usage (T9) so the next tuning round is data-driven instead of guesswork.

### Sequencing suggestion (dependencies, not time)

1. **Measurement first**: T9 (real tokens/phase) + T30 (dry-run estimate) — you can't optimize what you can't see.
2. **Correctness**: T1–T4, T10, T12 (prompt, code-in-verification, JSON parsing, honest Multi-Verifier).
3. **Cheap infra**: T5–T8, T11, T13 (cache, client reuse, rate limit, retry policy, dedup).
4. **Structural**: T14–T20 (batching, cascade, prioritization, chunking, prefix layout).
5. **Ecosystem**: T28–T44 (Markdown report, diffing, PHP, presets, docs).

---

## Appendix A — Key file references

| Topic | File(s) |
|---|---|
| Phase graph | `src/scanner/pipeline/orchestrator.rs` |
| Parallel/sequential execution | `src/scanner/orchestrator.rs` (16-arm join: L120–187) |
| LLM client (no cache, per-request client, fake tokens) | `src/llm.rs` (retry ladder L208–330, metrics L292–305) |
| Per-file LLM analysis, 8k truncation | `src/llm_analysis.rs` (`analyze_file`, `truncate_code`) |
| Per-finding discovery (no code) | `src/scanner/phases/llm_phases/discovery.rs` L194–231 |
| Per-finding verification (no code, `contains()` verdicts) | `src/scanner/phases/llm_phases/verification.rs` L126–178 |
| Enrichment + retry | `src/report/ai_aggregation/enrichment.rs` L40–110 |
| Multi-Verifier stub | `src/multi_verifier.rs` L91–117 |
| Self-contradictory prompt | `prompts/phases/llm_static_analysis.md` L136–158 vs L197–203 |
| Phantom config options | `config.example.toml` L28–48, `docs/operator-tuning.md` |
| PHP indexed-but-skipped | `src/indexer.rs` L213 vs `src/llm_analysis.rs` `get_extensions` |
| Substring exclusion matching | `src/indexer.rs` `should_exclude` |
| Unused RateLimiter | `src/rate_limiter.rs` (referenced only by its own tests) |
| CI branch typo | `.github/workflows/ci.yml` (trigger `ain, master]`) |
| Router targets non-existent prompts | `src/router/registry.toml` vs `prompts/` tree |
| Hunt prompts loaded but placeholder-only | `src/scanner/phases/llm_phases/verification.rs` L140–147 |

