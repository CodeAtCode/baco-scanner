# Architecture

## PhaseGraph (Data-Driven Pipeline Orchestration)

BACO uses a **data-driven PhaseGraph** (`src/scanner/pipeline/orchestrator.rs`) that defines phase execution order, dependencies, and metadata in a single source of truth. This eliminates duplication across the codebase and enables:

- **Centralized phase ordering** - All phases defined in one place with execution metadata
- **Checkpoint/resume support** - Stable phase indices for reliable restart
- **Extensibility** - New phases can be added without modifying multiple files
- **Runtime validation** - Phase consistency checked on startup

## Pipeline Phases

**Core Pipeline (25+ phases):**

1. **Indexing**: Build file list and call graph
2. **Semgrep**: Static analysis with predefined rules
3. **LLM Static Analysis**: Independent LLM-based code analysis (uses discovery config)
4. **LLM Discovery**: Multi-model vulnerability detection (all configured models analyze each finding)
5. **LLM Verification**: Validation with PoC generation and mitigation code
6. **SecurityAgent Verification**: **Tool-based agent verification** using file_read, pattern_search, file_write, run_test to confirm true positives
7. **Ticket Cross-Ref**: Search GitHub/GitLab for existing reports
8. **Git Analysis**: Check commit history for related fixes
9. **Cross-File Analysis**: Trace data flow between files
10. **Confidence Scoring**: Calculate composite reliability score
11. **AI Aggregation**: Generate executive summary, semantic deduplication, and LLM-enriched descriptions
12. **Reporting**: Generate JSON, HTML, and SARIF outputs
13. **Threat Modeling**: Generate THREAT_MODEL.md with attack surface analysis
14. **Root Cause Dedup**: Deduplicate findings by root cause instead of location
15. **Multi-Verifier**: Multiple verification methods with majority voting
16. **Auto-Patching**: Generate and validate patches with staging
17. **CVE Bootstrap**: Enrich findings with NVD/CISA KEV data
18. **PoC Compiler**: Verify PoC code compiles successfully
19. **Variant Search**: Search for related vulnerability variants

## Data Flow

```
Config → Indexing → [Semgrep + LLM Static Analysis + LLM Discovery] → [LLM Verification + SecurityAgent Verification + Tickets + Git + Confidence] → Cross-File → AI Aggregation → Reporting → [Threat Modeling, CVE, PoC, Variants] → JSON/HTML/SARIF Output
                          ↑ Checkpoint after each major stage
```