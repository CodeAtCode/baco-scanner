# BACO Prompt Templates

This directory contains the default prompt templates used by BACO for each analysis phase.

## Structure

Each phase has its own markdown file:
- `indexing.md` - Project structure indexing
- `semgrep.md` - Semgrep static analysis
- `llm_static_analysis.md` - LLM-powered code analysis
- `llm_discovery.md` - Vulnerability enrichment and discovery
- `llm_verification.md` - Finding verification and validation
- `ticket_crossref.md` - GitHub/GitLab/Jira cross-referencing
- `git_analysis.md` - Git history analysis
- `cross_file_analysis.md` - Cross-file data flow analysis
- `confidence_scoring.md` - Confidence score recalculation
- `ai_aggregation.md` - Executive summary generation
- `reporting.md` - Report generation instructions

## How It Works

1. At runtime, BACO loads these markdown files from `prompts/phases/`
2. Markdown headers (lines starting with `#`) are stripped
3. The clean prompt text is embedded in the binary
4. Template variables (e.g., `%%FILE_PATH%%`, `%%CODE_CONTENT%%`) are substituted during execution
5. Users can override any prompt via `config.toml`

## Customization

### Option 1: Edit the markdown files (recommended for permanent changes)

Modify any `.md` file in this directory. Changes will be loaded automatically on next run.

### Option 2: Override via config.toml

```toml
[llm.phases.prompt_overrides.phases]
llm_static_analysis = """Your custom prompt here..."""
llm_discovery = """Another custom prompt..."""
```

Config overrides take precedence over the markdown files.

## Template Variables

Available variables in each prompt (check individual files for which ones apply):

- `%%PROJECT_PATH%%` - Target project directory
- `%%FILE_PATH%%` - Current file being analyzed
- `%%LINE_NUMBER%%` - Line number of the finding
- `%%CODE_CONTENT%%` - Code snippet content
- `%%LANGUAGE%%` - Programming language
- `%%FINDING_TITLE%%` - Vulnerability title
- `%%VULNERABILITY_DESCRIPTION%%` - Detailed description
- And many more (see individual prompt files)

## GitHub Reference

These prompt templates are available on GitHub at:
`prompts/phases/` directory in the BACO repository

## Best Practices

1. **Keep prompts specific** - Vague prompts produce vague results
2. **Include output format** - Always specify JSON structure when expecting JSON
3. **Use examples** - Show the LLM exactly what format you want
4. **Set constraints** - Specify what NOT to do (e.g., "DO NOT include comments")
5. **Test changes** - Run `baco scan` after modifying prompts to verify behavior
