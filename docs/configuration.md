# Configuration

## Project Settings

```toml
[project]
name = "my-project"
path = "/path/to/target"
languages = ["c", "cpp", "python"]
```

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

### 2. SecurityAgent Verification (Phase 6)
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