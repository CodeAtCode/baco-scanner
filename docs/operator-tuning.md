# Operator Tuning Guide

Performance tuning for the Baco SAST scanner. Adjust settings based on scan speed, LLM costs, or analysis depth.

## Scenario Profiles

### Fast CI Scans (Sub-10-Minute Turnaround)

```toml
[scanner.performance]
enable_incremental_scan = true
max_parallel_tasks = 2
enable_llm_cache = true
enable_threat_modeling = false
enable_multi_verifier = false
enable_confidence_refinement = false
enable_cve_bootstrap = false
enable_variant_search = false

[scanner]
exclude_paths = ["tests/", "docs/", "target/", "vendor/"]
```

**Trade-off:** Reduced recall on cross-file vulnerabilities. Incremental scans may miss dependency context changes.

### Deep Nightly Scans (Full Analysis)

```toml
[scanner.performance]
enable_incremental_scan = false
max_parallel_tasks = 8
enable_llm_cache = true
enable_threat_modeling = true
enable_root_cause_dedup = true
enable_multi_verifier = true
enable_confidence_refinement = true
enable_cve_bootstrap = true
enable_variant_search = true

[llm]
max_concurrent = 8
timeout_secs = 120
```

**Trade-off:** Higher LLM costs (3-5x baseline). Runtime 30-60 minutes for medium projects.

### LLM-Cost-Sensitive Runs

```toml
[scanner.performance]
enable_incremental_scan = true
max_parallel_tasks = 2
enable_llm_cache = true
enable_multi_verifier = false
enable_confidence_refinement = false
enable_variant_search = false

[llm]
max_concurrent = 2
```

**Trade-off:** Lower detection quality on nuanced vulnerabilities. Cache hits depend on code stability.

## Performance Flags Reference

| Flag | Type | Default | Effect |
|------|------|---------|--------|
| `enable_incremental_scan` | bool | false | Skips unchanged files via SHA256 hash comparison |
| `max_parallel_tasks` | int | 4 | Max concurrent scan tasks |
| `enable_llm_cache` | bool | false | Caches LLM responses by prompt hash |
| `enable_file_filtering` | bool | true | Filters low-value files (minified, vendor) |
| `enable_threat_modeling` | bool | false | STRIDE-based threat analysis |
| `enable_root_cause_dedup` | bool | true | Collapses findings with same root cause |
| `enable_multi_verifier` | bool | true | Additional LLM verification passes |
| `enable_auto_patching` | bool | false | Generates fix patches — opt-in |
| `enable_poc_compilation` | bool | false | Compiles PoC exploits — opt-in |
| `enable_confidence_refinement` | bool | true | Re-calibrates confidence scores |
| `enable_cve_bootstrap` | bool | true | Enriches findings with CVE data |
| `enable_variant_search` | bool | true | Searches for variant vulnerability instances |
| `early_termination_threshold` | float | 1000.0 | Stops scan after N findings (not in config.example.toml) |

## General Settings

| Setting | Section | Default | Effect |
|---------|---------|---------|--------|
| `commit_lookback_days` | `[scanner]` | 90 | Git history depth |
| `max_file_size_kb` | `[scanner]` | 512 | Skip larger files |
| `exclude_paths` | `[scanner]` | `["tests/", "docs/", "target/"]` | Glob patterns to skip |
| `exclude_rules` | `[scanner.semgrep]` | `[]` | Semgrep rule IDs to skip |

## Trade-off Callouts

### LLM Cost vs. Recall

Disabling `enable_multi_verifier`, `enable_confidence_refinement`, and `enable_variant_search` cuts LLM calls by ~60%. Expect 15-25% reduction in true positives.

### Incremental Scan Caveats

Incremental scanning compares file SHA256 hashes but does not track dependency changes or config drift. Full rescan recommended after major changes.

### Semgrep `exclude_rules`

```toml
[scanner.semgrep]
exclude_rules = ["html.security.plaintext-http-link"]
```

Use to suppress known false positives. Document each exclusion.

### Early Termination Threshold

Not exposed in `config.example.toml`. Add manually:

```toml
[scanner.performance]
early_termination_threshold = 500.0
```

Scan stops after N findings. Useful for very large codebases.