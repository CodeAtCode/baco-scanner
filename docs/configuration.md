# Configuration

## Quick Start

Minimal working configuration — copy-paste this block and fill in your API key:

```toml
[project]
name = "my-project"
path = "/path/to/target"
languages = ["c"]

[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
api_key = "${MISTRAL_API_KEY}"
model = "mistral-small"

[scanner.performance]
enable_incremental_scan = false
max_parallel_tasks = 4
enable_llm_cache = false
enable_file_filtering = true
```

**Experimental sections** (disabled by default):
- `[cpg]` — CPG-guided slicing (requires Joern binary)
- `[validate]` — LLM-as-judge rationale validation
- `[vuln_spec]` — VulTriage triple-path, policy sampling, agent scaffold
- `[agent_scaffold]` — Agent-assisted analysis
- `[agent_flow]` — Multi-agent harness synthesis
- `[threat_modeling]` — STRIDE threat modeling (now under `[scanner.performance]`)

Enable only after reviewing the detailed sections below.

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
enable_threat_modeling = false
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
| `enable_threat_modeling` | `false` | None (read-only analysis) |
| `enable_root_cause_dedup` | `true` | None |
| `enable_multi_verifier` | `true` | Additional LLM API calls |
| `enable_auto_patching` | `false` | Writes code files, runs git commands in a staging worktree |
| `enable_poc_compilation` | `false` | Spawns external compilers |
| `enable_confidence_refinement` | `true` | None |
| `enable_cve_bootstrap` | `true` | External network requests to NVD/CISA |
| `enable_variant_search` | `true` | Additional LLM API calls |

See [`docs/architecture.md`](architecture.md) for the full 24-phase pipeline description.

## LLM Configuration

BACO supports single or multiple models per phase. When multiple models are configured, they are used in round-robin fashion to distribute load across different models/providers.

**Default temperature:** `0.5` (controlled randomness for better security analysis)

**Default max_reasoning_tokens:** unset (`None` — no cap unless configured)

**Single model:**
```toml
[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
api_key = "${MISTRAL_API_KEY}"  # or set env var
model = "mistral-small"
temperature = 0.5
max_reasoning_tokens = 2048
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
enabled = false
max_turns = 10           # Max conversation turns with tools
tool_timeout_secs = 60   # Timeout for tool execution
trusted_paths = ["."]    # Paths allowed for tool operations
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
Current Description: %%CURRENT_DESCRIPTION%%
Description: %%VULNERABILITY_DESCRIPTION%%
"""
```

**Available template variables:**
- `%%PROJECT_PATH%%` - Target project path
- `%%PROJECT_NAME%%` - Project name
- `%%FILE_EXTENSIONS%%` - Detected file extensions
- `%%LANGUAGES%%` - Target languages
- `%%CODE_CONTENT%%` - Code snippet being analyzed
- `%%LANGUAGE%%` - Programming language of the file
- `%%FILE_PATH%%` - File path
- `%%LINE_NUMBER%%` - Specific line number
- `%%LINE_RANGE%%` - Line numbers range
- `%%CURRENT_DESCRIPTION%%` - Current vulnerability description (for iterative phases)
- `%%FINDING_TITLE%%` - Vulnerability title
- `%%VULNERABILITY_DESCRIPTION%%` - Description text
- `%%FINDINGS_COUNT%%` - Total findings count
- `%%SCAN_DATE%%` - Scan date
- `%%TOTAL_FINDINGS%%` - Total findings count (alias)
- `%%TOTAL_FILES%%` - Total files scanned
- `%%FILES_COUNT%%` - Files count (alias)
- `%%SOURCE_LIST%%` - List of source files
- `%%CONTEXT_LINES%%` - Context lines around finding
- `%%CWE_SPECS%%` - CWE specification details
- `%%EXCLUDE_PATHS%%` - Excluded paths
- `%%MAX_FILE_SIZE%%` - Maximum file size limit
- `%%PROJECT_TYPE%%` - Project type
- `%%SCAN_DURATION%%` - Scan duration
- `%%TICKET_SYSTEMS%%` - Configured ticket systems
- `%%TOOLS_USED%%` - Tools used in analysis
- `%%VULNERABILITY_LIST%%` - List of vulnerabilities
- `%%VULNERABILITY_TITLE%%` - Vulnerability title
- `%%FINDINGS_LIST%%` - Full findings list

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

## Paper-Integration Research Flags

> **Experimental — disabled by default.** These sections enable research-backed analysis augmentations. Enable only after understanding the tradeoffs.

### Validate (CORRECT paper arxiv:2504.13474)

LLM-as-judge rationale validation: evaluates the soundness of reasoning behind each finding and adjusts confidence accordingly (+0.10 sound, -0.20 flawed).

| Field    | Type | Default | Description                    |
|----------|------|---------|--------------------------------|
| `enabled`| bool | false   | Enable Validate phase          |

```toml
[validate]
enabled = false
```

### VulTriage (P1) — arXiv:2605.09461

Triple-path context augmentation. Prepends control path (AST/CFG/DFG), knowledge
path (CWE pattern RAG), and semantic path (function summary) to the LLM prompt
before the vulnerability judgement.

| Field          | Type | Default | Description                          |
|----------------|------|---------|--------------------------------------|
| `enabled`      | bool | false   | Enable triple-path augmentation      |
| `control_path` | bool | true    | Include AST/CFG/DFG verbalisation    |
| `knowledge_path`| bool | true    | Include CWE pattern RAG              |
| `semantic_path`| bool | true    | Include function summary             |

```toml
[vultriage]
enabled = false
control_path = true
knowledge_path = true
semantic_path = true
```

### VulnLLM-R Policy Sampling (P2.2) — arXiv:2605.09461

Policy-based CWE generation. Queries the LLM N times to build a candidate set,
then a final call picks one label. Increases LLM cost ~5x.

| Field     | Type | Default | Description                    |
|-----------|------|---------|--------------------------------|
| `enabled` | bool | false   | Enable policy sampling         |
| `samples` | int  | 4       | Number of candidate samples    |

```toml
[policy_sampling]
enabled = false
samples = 4
```

### VulnLLM-R Agent Scaffold (P2.5) — arXiv:2605.09461

Builds 3-path call-graph context + function-lookup tool per target for
agent-assisted analysis.

| Field            | Type | Default | Description                    |
|------------------|------|---------|--------------------------------|
| `enabled`        | bool | false   | Enable agent scaffold          |
| `max_rounds`     | int  | 5       | Max agent conversation rounds  |
| `paths_per_target`| int | 3       | Call-graph paths per target    |

```toml
[agent_scaffold]
enabled = false
max_rounds = 5
paths_per_target = 3
```

### Truncated Generation (P2.1) — arXiv:2605.09461

Caps reasoning tokens before forcing the final answer. Configured in the `[llm]` section.

| Field                | Type | Default | Description                    |
|----------------------|------|---------|--------------------------------|
| `max_reasoning_tokens`| int | None   | Max tokens for reasoning phase |

```toml
[llm]
max_reasoning_tokens = 2048
```

### MoCQ Neuro-Symbolic Rule Synthesis (P3) — arXiv:2605.13918

RuleSynthesis 2.0: LLM proposes patterns in a DSL → symbolic validator gives
feedback → iterative loop. Extends the `[scanner.rulesynth]` section.

| Field           | Type | Default | Description                    |
|-----------------|------|---------|--------------------------------|
| `mocq_mode`     | bool | false   | Enable MoCQ neuro-symbolic mode|
| `max_iterations`| int  | 5       | Max synthesis iterations       |
| `corpus_path`   | str  | None    | Path to pattern corpus         |

```toml
[scanner.rulesynth]
enabled = false
mocq_mode = false
max_iterations = 5
corpus_path = "tests/fixtures/"
```

### CPG-Guided Slicing (T3.1)

CPG (Code Property Graph) slicing using Joern. Requires Joern binary in PATH or specify path.

| Field         | Type | Default | Description                    |
|---------------|------|---------|--------------------------------|
| `enabled`     | bool | false   | Enable CPG slicing             |
| `joern_path`  | str  | None    | Path to Joern binary           |
| `slice_budget_lines`| int | 200  | Maximum lines per slice      |

```toml
[cpg]
enabled = false
joern_path = null
slice_budget_lines = 200
```

### PacVD Primitive-API Abstraction (P4) — arXiv:2605.07785

Appends callee abstraction at one of four granularity levels to the LLM prompt.
Level 1 = fuzzy branches only; Level 4 = concrete branches + key variables.

| Field         | Type | Default | Description                    |
|---------------|------|---------|--------------------------------|
| `enabled`     | bool | false   | Enable primitive-API abstraction|
| `level`       | int  | 2       | Abstraction granularity (1-4)  |
| `auto_level`  | bool | false   | Auto-select optimal level      |

```toml
[pacvd]
enabled = false
level = 2
auto_level = false
```

### AgentFlow Multi-Agent Harness Synthesis (P5) — arXiv:2605.11835

Represents the harness as a typed graph DSL with a search loop. Most invasive
integration — static harness only until P5.5.

| Field                      | Type | Default | Description                    |
|----------------------------|------|---------|--------------------------------|
| `enabled`                  | bool | false   | Enable AgentFlow harness       |
| `max_iterations`           | int  | 10      | Max synthesis iterations       |
| `requires_instrumented_target`| bool | false | Require instrumented target   |

```toml
[agent_flow]
enabled = false
max_iterations = 10
requires_instrumented_target = false
```

### Exploit Synthesis (T3.2)

Automated exploit generation to verify findings. Runs in sandboxed Docker containers.

| Field                        | Type | Default | Description                    |
|------------------------------|------|---------|--------------------------------|
| `enabled`                    | bool | false   | Enable exploit synthesis       |
| `sandbox_image`              | str  | "python:3.11-slim" | Docker image for sandbox |
| `timeout_secs`               | int  | 30      | Timeout for exploit execution  |
| `max_exploits_per_finding`   | int  | 1       | Max attempts per finding       |

```toml
[exploit]
enabled = false
sandbox_image = "python:3.11-slim"
timeout_secs = 30
max_exploits_per_finding = 1
```

### Confidence Normalization

Normalizes confidence scores using project baselines or isotonic regression.

| Field                  | Type | Default | Description                    |
|------------------------|------|---------|--------------------------------|
| `enabled`              | bool | false   | Enable normalization           |
| `normalization_tier`   | str  | "None"  | Normalization tier (None, ProjectRelative, Isotonic) |
| `project_baseline_path`| str  | None    | Path to project baseline file  |

```toml
[normalization]
enabled = false
normalization_tier = "None"
project_baseline_path = null
```