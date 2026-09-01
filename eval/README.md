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
4. Output a ScoreReport with recall/precision metrics

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

- **py-sqli**: SQL injection via f-string (CWE-89)
- **c-overflow**: Buffer overflow via unbounded memcpy (CWE-120/787)

## Fixture Guidelines

1. **Vulnerable file**: Single, clear vulnerability at a known line number
2. **Safe twin**: Same structure, secure implementation (parameterized, bounded, etc.)
3. **Line numbers**: Count carefully; use 1-indexed line numbers
4. **CWE IDs**: Use official CWE identifiers (e.g., "CWE-89", "CWE-120")
5. **Innocent files**: Add 1-2 files with no vulnerabilities to test false positive rate