# CLI Reference

Complete reference for all BACO subcommands, organized by category.

## Setup Commands

### `init` — Initialize project configuration

Scaffolds a `baco.toml` config file for a target project. Detects languages and suggests an appropriate preset.

```bash
baco init /path/to/project
```

**Options:**
- Takes a project path as argument
- Creates `baco.toml` in the target directory
- Auto-detects languages and suggests preset

### `doctor` — Pre-flight system checks

Validates the entire scan environment before running. Checks config parsing, preset resolution, LLM phase availability, semgrep installation, Python3, Joern (if CPG enabled), output directory writability, and disk space.

```bash
baco doctor              # Human-readable report
baco doctor --json       # JSON output for CI/CD
```

## Scanning Commands

### `scan` — Run the vulnerability scan

Executes the full 23-phase pipeline on a target project.

```bash
baco scan --config /path/to/baco.toml
```

**Options:**
- `--config <path>` — Path to TOML config file (required)
- `--dry-run` — Print cost/usage estimate and exit without scanning
- `--target <path>` — Override the target path from config
- `--force` — Force a full rescan, ignoring cached results
- `--diff <revspec>` — Limit report to files changed in git revspec (e.g., `main...HEAD`)
- `-q` — Suppress non-essential output (quiet mode)

**Example:**
```bash
# Estimate cost before running
baco scan --config my.toml --dry-run

# Scan with custom target override
baco scan --config my.toml --target /path/to/code

# Scan only changed files in a PR
baco scan --config my.toml --diff origin/main...HEAD
```

### `resume` — Resume an interrupted scan

Continues a scan from a saved checkpoint after interruption or crash.

```bash
baco resume --checkpoint baco-output/checkpoint.json
```

**Options:**
- `--checkpoint <path>` — Path to checkpoint.json file (required)

## Reporting Commands

### `report` — Generate standalone reports

Generates formatted reports from existing findings data.

```bash
baco report --input findings.json --format html [--config config.toml]
```

**Options:**
- `--input <path>` — Path to findings.json (required)
- `--format <type>` — Output format: `html`, `markdown`, `json` (required)
- `--config <path>` — Apply config settings (e.g., evidence gate) to standalone report

**Example:**
```bash
baco report --input findings.json --format html
baco report --input findings.json --format markdown
```

### `verify` — Verify findings

Runs verification checks on existing findings.

```bash
baco verify --input findings.json
```

**Options:**
- `--input <path>` — Path to findings.json (required)

## Evaluation Commands

### `eval` — Evaluate scanner precision/recall

Measures scanner accuracy against ground truth fixtures.

```bash
baco eval --target /path/to/fixtures --ground-truth eval/oracles/target.json
```

**Options:**
- `--target <path>` — Path to test fixtures directory (required)
- `--ground-truth <path>` — Path to oracle JSON file with expected results (required)

**Output:** Precision, recall, and F1 score metrics.

## Configuration Commands

### `preset list` — List built-in presets

Displays all available configuration presets.

```bash
baco preset list
```

**Output:** List of preset names and descriptions.
