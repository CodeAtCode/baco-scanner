# Configuration

## Project Settings

```toml
[project]
name = "my-project"
path = "/path/to/target"
languages = ["c", "cpp", "python"]
```

## Scanner Performance & Phase Flags

The `[scanner.performance]` section controls incremental scanning and which optional analysis phases run. Each phase flag defaults to a safe value; side-effect-heavy phases (auto-patching, PoC compilation) are opt-in.

```toml
[scanner.performance]
# Skip unchanged files based on SHA256 hash comparison (hashes persisted to output dir)
enable_incremental_scan = false
# Maximum number of parallel tasks for scanning operations
max_parallel_tasks = 4
# Enable LLM response caching to avoid redundant API calls
enable_llm_cache = false
# Enable file filtering to reduce false positives
enable_file_filtering = true

# --- Phase enable flags ---
# Each flag controls whether a specific analysis phase runs during the scan.

# Threat modeling using STRIDE analysis (adds LLM-based threat identification)
enable_threat_modeling = true
# Root-cause deduplication (collapses findings that share the same root cause)
enable_root_cause_dedup = true
# Multi-verifier cross-checking (runs additional LLM verification passes)
enable_multi_verifier = true
# Auto-patching (generates and validates fix patches in a staging worktree)
# Writes code files and runs git commands — opt-in for safety
enable_auto_patching = false
# PoC compilation (compiles proof-of-concept exploits to verify findings)
# Spawns external compilers — opt-in for safety
enable_poc_compilation = false
# Confidence refinement (re-calibrates finding confidence based on multi-source/cross-file signals)
enable_confidence_refinement = true
# CVE bootstrap (enriches findings with CVE data from external sources)
enable_cve_bootstrap = true
# Variant search (searches for variant instances of the same vulnerability pattern)
enable_variant_search = true
```

| Flag | Default | Side effects |
| --- | --- | --- |
| `enable_threat_modeling` | `true` | None (read-only analysis) |
| `enable_root_cause_dedup` | `true` | None |
| `enable_multi_verifier` | `true` | Additional LLM API calls |
| `enable_auto_patching` | `false` | Writes code files, runs git commands in a staging worktree |
| `enable_poc_compilation` | `false` | Spawns external compilers |
| `enable_confidence_refinement` | `true` | None |
| `enable_cve_bootstrap` | `true` | External network requests to NVD/CISA |
| `enable_variant_search` | `true` | Additional LLM API calls |

See [`docs/architecture.md`](architecture.md) for the full 20-phase pipeline description.

## LLM Configuration

BACO supports single or multiple models per phase. When multiple models are configured, they are used in round-robin fashion to distribute load across different models/providers.

**Detailed error logging**: When LLM requests fail, BACO reports the HTTP status code, error type (timeout, connection, request, body, decode), and the actual URL for easier debugging.

**Single model:**
```toml
[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
api_key = "${MISTRAL_API_KEY}"  # or set env var
model = "mistral-small"
```

**Multiple models:**
```toml
[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
api_key = "${MISTRAL_API_KEY}"
# 'models' takes precedence over 'model' if both are present
models = ["mistral-small", "mistral-medium", "codestral-latest"]

[llm.phases.verification]
base_url = "https://api.qwen.ai/v1"
api_key = "${QWEN_API_KEY}"
model = "qwen35"  # single model

[llm.phases.aggregation]
base_url = "https://api.openai.com/v1"
api_key = "${OPENAI_API_KEY}"
models = ["gpt-4o", "gpt-4o-mini"]  # multiple models for distributed load
```

**Note**: The `models` array takes precedence over `model` if both are present. Models are selected in round-robin fashion to distribute load across different providers.

## Agent Mode

BACO has **two distinct agent modes**:

### 1. Discovery Agent (`agent.enabled = true`)
When enabled, the LLM Discovery phase reads source files directly before analyzing findings:

```toml
[agent]
enabled = true
max_turns = 10           # Max conversation turns with tools
tool_timeout_secs = 60   # Timeout for tool execution
keep_artifacts = false   # Keep generated test files
```

**Benefits:**
- LLM reads actual source code before enriching findings
- Uses tools (file_read, pattern_search) for deeper analysis
- Provides more accurate vulnerability descriptions with context

### 2. SecurityAgent Verification (Phase 7)
A **separate verification phase** that uses an embedded security agent with tools to **prove or disprove** findings:

- **file_read**: Examine vulnerable code in context
- **pattern_search**: Look for related vulnerability patterns
- **file_write**: Create proof-of-concept test cases
- **run_test**: Execute tests to verify exploitability

The agent automatically removes false positives when tests pass, reducing noise in the final report. This phase runs **after** LLM Verification and **before** Ticket Cross-Reference.

## Prompt Customization

BACO uses prompt templates for each phase loaded from markdown files at runtime. You can override these via configuration:

**Default prompts** are stored in `prompts/phases/` as markdown files:
- `prompts/phases/indexing.md`
- `prompts/phases/semgrep.md`
- `prompts/phases/llm_static_analysis.md`
- `prompts/phases/llm_discovery.md`
- `prompts/phases/llm_verification.md`
- `prompts/phases/ticket_crossref.md`
- `prompts/phases/git_analysis.md`
- `prompts/phases/cross_file_analysis.md`
- `prompts/phases/confidence_scoring.md`
- `prompts/phases/ai_aggregation.md`
- `prompts/phases/reporting.md`

View the [full prompt templates on GitHub](prompts/phases/) to understand default behavior.

**Inline override in config.toml**:
```toml
[llm.phases.prompt_overrides.phases]
llm_static_analysis = """Analyze this %%LANGUAGE%% code for security vulnerabilities.
Focus on: memory safety, injection risks, and insecure API usage.

File: %%FILE_PATH%%
Code:
%%CODE_CONTENT%%
"""

llm_discovery = """Given this finding, determine if it's a true vulnerability:
Title: %%FINDING_TITLE%%
Location: %%FILE_PATH%%:%%LINE_NUMBER%%
Description: %%VULNERABILITY_DESCRIPTION%%
"""
```

**Available template variables:**
- `%%PROJECT_PATH%%` - Target project path
- `%%FILE_EXTENSIONS%%` - Detected file extensions
- `%%LANGUAGES%%` - Target languages
- `%%CODE_CONTENT%%` - Code snippet being analyzed
- `%%LANGUAGE%%` - Programming language of the file
- `%%FILE_PATH%%` - File path
- `%%LINE_RANGE%%` - Line numbers
- `%%FINDING_TITLE%%` - Vulnerability title
- `%%VULNERABILITY_DESCRIPTION%%` - Description text
- `%%FINDINGS_COUNT%%` - Total findings count
- `%%SCAN_DATE%%` - Scan date

Prompts are validated (max 10,000 characters, no null bytes) before use.

## Ticket Systems

```toml
[[tickets.systems]]
type = "github"
url = "https://api.github.com"
credentials.token = "${GITHUB_TOKEN}"
```

## Output Formats

- **findings.json**: Complete vulnerability data with all 16 fields
- **report.html**: Visual report with severity colors, code snippets, AI summary
- **report.sarif**: SARIF format for CI/CD integration