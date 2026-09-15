# BACO Evaluation Harness

Known-answer oracle scoring for measuring discovery/verification quality.

## Method

The eval harness uses **labeled vulnerable/secure aligned pairs**:

- **Oracle files** contain the ground truth: expected findings (vulnerable) and expected suppressed (secure twins)
- **Blind validation only**: oracle data is NEVER loaded into LLM prompts
- **Scoring**: Findings from the scanner are compared against the oracle to compute:
  - **Recall**: matched_expected / total_expected
  - **Precision**: matched / (matched + false_flags)
  - **False flags**: Findings on secure twin files (should be zero)

## Running the Eval

### CLI mode (recommended)

```bash
# Evaluate precision/recall/F1 vs ground truth
baco eval --target /path/to/fixtures --ground-truth eval/oracles/target.json
```

The eval command:
1. Loads the oracle file from `--ground-truth` path
2. Scans the fixture files in `--target` path (or uses existing findings via `--findings`)
3. Scores findings against expected/expected_suppressed
4. Outputs precision, recall, and F1 score metrics

### Suite mode (offline regression gate)

```bash
# Run every bundled target offline: no scanner, no LLM keys, no network
baco eval            # no arguments = suite mode
baco eval --all      # explicit

cargo run --bin baco -- eval   # from a repository checkout
```

Suite mode iterates every `eval/oracles/*.json` target, scores its bundled
findings fixture (`eval/findings/<target>.json`) against its oracle, prints a
per-target pass-rate table plus the aggregate, and exits non-zero when the
aggregate does not exceed the floor.

**`[eval] floor` in the config is the knob.** Set a fraction in `0.0..=1.0`
(default `0.70`) in your `baco.toml`; the suite passes only when the aggregate
pass-rate (total matched / total expected across all targets) is *strictly
greater* than the floor. The `BACO_EVAL_FLOOR` environment variable overrides
the config value (unset or empty falls back to config).

```toml
[eval]
# Fail unless the suite exceeds a stricter floor
floor = 0.9
```

```bash
# Or override per invocation via the environment
BACO_EVAL_FLOOR=0.9 baco eval
```

### Environment mode (legacy)

```bash
# Set the environment variable to enable eval mode
export BACO_EVAL=1

# Provide your LLM key
export LLM_API_KEY=your-key-here

# Run baco with eval mode
cargo run -- --eval-target py-sqli
```

The scanner will:
1. Load the oracle file from `eval/oracles/<target>.json`
2. Scan the fixture files in `eval/fixtures/<target>/`
3. Score findings against expected/expected_suppressed
4. Output a ScoreReport with recall/precision/F1 metrics

## Adding New Targets

### 1. Create fixture directory

```
eval/fixtures/<target-name>/
├── vulnerable.<ext>    # Contains the vulnerability at a known line
├── safe_twin.<ext>     # Identical logic, secure implementation
└── innocent.<ext>      # Additional non-vulnerable files (optional)
```

### 2. Create oracle JSON

`eval/oracles/<target-name>.json`:

```json
{
  "target": "<target-name>",
  "description": "Brief description of the vulnerability type",
  "expected_findings": [
    {
      "file_path": "vulnerable.<ext>",
      "line": <exact-line-number>,
      "cwe_id": "CWE-XXX",
      "class": "Vulnerability Class Name"
    }
  ],
  "expected_suppressed": [
    {
      "file_path": "safe_twin.<ext>",
      "reason": "Why this is secure (e.g., 'Parameterized query twin')"
    }
  ]
}
```

### 3. Add integration tests

In `tests/integration/eval_oracle.rs`:

```rust
#[test]
fn test_<target-name>_oracle_parse() {
    // Verify oracle parses correctly
}

#[test]
fn test_<target-name>_fixtures_exist() {
    // Verify fixture files exist
}

#[test]
fn test_<target-name>_scoring() {
    // Unit test score_findings with synthetic findings
}

#[tokio::test]
#[ignore] // Requires BACO_EVAL=1 + LLM key
async fn test_<target-name>_e2e() {
    // End-to-end eval with real scanner output
}
```

## Existing Targets

| Target | Language | Vulnerability class | CWE |
|---|---|---|---|
| py-sqli | Python | SQL injection via f-string | CWE-89 |
| c-overflow | C | Buffer overflow via unbounded memcpy | CWE-120 |
| php-sqli | PHP | SQL injection via `$_GET` concatenation | CWE-89 |
| php-xss | PHP | Reflected XSS via unescaped `echo` | CWE-79 |
| js-eval | JavaScript | Code injection via `eval()` of user input | CWE-95 |
| js-path-traversal | JavaScript | Path traversal via `path.join` of user input | CWE-22 |
| py-weak-hash | Python | Weak hash (MD5) for password storage | CWE-327 |
| py-cmdi | Python | OS command injection via `os.system` | CWE-78 |
| c-sprintf | C | Out-of-bounds write via unbounded `sprintf` | CWE-787 |
| c-uaf | C | Use-after-free via dangling pointer read | CWE-416 |

## Fixture Guidelines

1. **Vulnerable file**: Single, clear vulnerability at a known line number
2. **Safe twin**: Same structure, secure implementation (parameterized, bounded, etc.)
3. **Line numbers**: Count carefully; use 1-indexed line numbers
4. **CWE IDs**: Use official CWE identifiers (e.g., "CWE-89", "CWE-120")
5. **Innocent files**: Add 1-2 files with no vulnerabilities to test false positive rate