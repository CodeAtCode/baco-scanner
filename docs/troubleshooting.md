# Troubleshooting Guide

Common issues and solutions for the Baco SAST scanner.

## LLM/API Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No API key configured - skipping ...` | Missing API key | Add `api_key` inside each `[llm.phases.<slot>]` (discovery, verification, aggregation, static_analysis, security_agent_verification, threat_modeling) or set per-slot env vars (`LLM_DISCOVERY_KEY`, `LLM_VERIFICATION_KEY`, `LLM_AGGREGATION_KEY`, etc.) |
| Phases show "No API key configured - skipping" | LLM API key not set | Set per-phase API keys via `[llm.phases.discovery.api_key]` or env vars (`LLM_DISCOVERY_KEY`, `LLM_VERIFICATION_KEY`, etc.) |
| Duplicate LLM API calls during scan | Cache disabled by default | Set `enable_llm_cache = true` in `[llm]` section of config.toml |
| Threat modeling output is static STRIDE template | Feature disabled by default | Set `enable_threat_modeling = true` in config.toml (documentation-only output) |

## Scan Hangs/Slow

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scan hangs during CPG slicing | Joern binary not installed | Install Joern: `curl -L https://github.com/joernio/joern/releases/latest/download/joern-cli-linux-x64.zip -o joern.zip && unzip joern.zip && sudo mv joern-cli /usr/local/bin/` |
| CPG slicing phase shows "skipped" | Joern dependency missing | Install Joern binary (see above) or skip CPG analysis |
| Scan takes unusually long | Large codebase, no caching | Enable `enable_llm_cache = true` to avoid duplicate API calls |

## Report/Output Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scan fails mid-way, can't resume | No checkpoint created | Resume with: `baco resume --checkpoint <path-to-checkpoint.json>` |
| checkpoint.json not found | Output directory cleared | Re-run full scan; checkpoint is written to output dir |
| Report missing threat modeling section | Feature disabled | Set `enable_threat_modeling = true` in config.toml |

## External Tool Dependencies

| Symptom | Cause | Fix |
|---------|-------|-----|
| CPG slicing phase skipped | Joern binary not in PATH | Install Joern (see "Scan Hangs/Slow" section) |
| CPG errors about missing binary | Joern not executable | Ensure Joern has execute permissions: `chmod +x /usr/local/bin/joern-cli` |

## Configuration Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| Config parse errors at startup | Malformed TOML | Validate config.toml syntax; check for missing brackets or quotes. Serde silently ignores unknown keys. |
| "missing [project] path" error | Required field absent | Add `project.path = "src/"` to config.toml |
| Config parse errors at startup | Malformed TOML | Validate config.toml syntax; check for missing brackets or quotes |

## Common Error Messages

### Scan Failed
```
Scan failed: {error}
```

**When this appears:** At the end of a failed scan run.

**Why:** An unrecoverable error occurred (network failure, invalid input, resource exhaustion).

**Solution:** Resume from checkpoint:
```bash
baco resume --checkpoint <output-dir>/checkpoint.json
```

The checkpoint.json file contains the scan state and is written to the output directory after each completed phase.

### Ctrl+C Interruption
```
Resume with: baco resume --checkpoint <path>
```

**When this appears:** When you press Ctrl+C during a scan.

**Why:** The scanner gracefully shuts down and writes the current state to checkpoint.json.

**Solution:** Use the displayed command to resume from where you left off.

## Performance Tips

1. **Enable caching:** Set `enable_llm_cache = true` to avoid redundant API calls for identical code patterns.

2. **Parallelize:** For large codebases, split into smaller modules and scan separately.

3. **Use incremental scans:** After initial full scan, subsequent runs only process changed files.

4. **Disable unused phases:** If you don't need threat modeling, keep `enable_threat_modeling = false` to reduce scan time.

## Getting Help

- Check config.toml for syntax errors
- Verify Joern is installed and in PATH
- Ensure per-phase LLM API keys are set (`[llm.phases.discovery.api_key]` or env vars like `LLM_DISCOVERY_KEY`)
- Review checkpoint.json for scan state
- Clear output directory for fresh start

## Quick Reference

**Resume interrupted scan:**
```bash
baco resume --checkpoint <path-to-checkpoint.json>
```

**Force full rescan:**
```bash
rm -rf <output-dir>/
baco scan --config <config.toml>
```

**Enable LLM caching:**
```toml
[llm]
enable_llm_cache = true
```

**Set API key:**
```bash
export LLM_DISCOVERY_KEY=your_api_key_here
export LLM_VERIFICATION_KEY=your_api_key_here
export LLM_AGGREGATION_KEY=your_api_key_here
```

**Verify Joern installation:**
```bash
joern-cli --version
```