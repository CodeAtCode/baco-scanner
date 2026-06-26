# BACO - Bug Analysis & Cross-reference Orchestrator
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)   

A CLI-based security vulnerability scanner that combines static analysis, LLM-powered discovery, and ticket system cross-referencing (generated with Regolo.AI).  
[Example Report](report.html) generated with [Regolo.AI](https://regolo.ai/) models on [ins1gn1a/VulnServer-Linux](https://github.com/ins1gn1a/VulnServer-Linux).

## Features

- **Multi-phase scanning**: 13+ phases including Indexing → Semgrep → LLM Static Analysis → LLM Discovery → LLM Verification → **SecurityAgent Verification** → Ticket Cross-Ref → Git Analysis → Cross-File Analysis → Confidence Scoring → AI Aggregation → Reporting → Advanced V3 features (Threat Modeling, CVE Bootstrap, PoC Compilation, Variant Search)
- **Parallel execution**: Semgrep and LLM discovery run concurrently; verification, ticket cross-ref, and git analysis run in parallel
- **Checkpoint/resume**: Automatically saves state after each phase for crash recovery
- **Multiple output formats**: JSON, HTML, SARIF
- **Config-driven**: TOML configuration with environment variable overrides
- **Prompt customization**: Override default LLM prompts per phase via config
- **Ticket integration**: GitHub, GitLab, Bugzilla, Jira support
- **Cross-file analysis**: Traces data flow between files to identify exploitable chains
- **Composite confidence scoring**: Combines multiple signals into a single reliability score

## Architecture

### Pipeline Phases

**Core Pipeline (11 phases):**

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

### Data Flow

```
Config → Indexing → [Semgrep + LLM Static Analysis + LLM Discovery] → [LLM Verification + SecurityAgent Verification + Tickets + Git + Confidence] → Cross-File → AI Aggregation → Reporting → [Threat Modeling, CVE, PoC, Variants] → JSON/HTML/SARIF Output
                         ↑ Checkpoint after each major stage
```

## Installation

```bash
cargo build --release
./target/release/baco --version
```

## Usage

### 1. Create Configuration

```bash
cp config.example.toml myproject.toml
```

Edit `myproject.toml`:
- Set `project.path` to the target directory
- Configure LLM API keys (or use environment variables)
- Set up ticket system credentials if needed

### 2. Run Scan

```bash
baco scan --config myproject.toml
```

**Options:**
- `-c, --config <FILE>` - Configuration file (required)
- `-t, --target <PATH>` - Override target path from config
- `-f, --force` - Force fresh scan, ignore existing checkpoint

**Resume previous scan:**
```bash
baco scan --config myproject.toml --force
```
Use `--force` to start fresh and ignore the checkpoint file.

### 3. View Results

```bash
output/report.html
```

## Configuration

### Project Settings

```toml
[project]
name = "my-project"
path = "/path/to/target"
languages = ["c", "cpp", "python"]
```

### LLM Configuration

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

### Agent Mode

BACO has **two distinct agent modes**:

#### 1. Discovery Agent (`agent.enabled = true`)
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

#### 2. SecurityAgent Verification (Phase 6)
A **separate verification phase** that uses an embedded security agent with tools to **prove or disprove** findings:

- **file_read**: Examine vulnerable code in context
- **pattern_search**: Look for related vulnerability patterns
- **file_write**: Create proof-of-concept test cases
- **run_test**: Execute tests to verify exploitability

The agent automatically removes false positives when tests pass, reducing noise in the final report. This phase runs **after** LLM Verification and **before** Ticket Cross-Reference.

### Prompt Customization

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

**From external file:**
```toml
# In config.toml
prompt_overrides = "prompts.toml"
```

Create `prompts.toml`:
```toml
[phases]
llm_static_analysis = "Your custom prompt here..."
llm_verification = "Your verification prompt..."
```

Prompts are validated (max 10,000 characters, no null bytes) before use.

### Ticket Systems

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
