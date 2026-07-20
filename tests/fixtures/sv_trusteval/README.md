# SV-TrustEval-C Inspired Regression Fixtures

## Description

Synthetic paired vulnerable/safe C variants inspired by SV-TrustEval-C (SP 2025).

These fixtures are designed for regression testing the baco vulnerability scanner's ability to:
- Detect common vulnerability patterns in C code
- Differentiate between vulnerable and patched variants
- Produce consistent findings across similar code structures

## Attribution

**Inspired by SV-TrustEval-C** (arxiv:2505.20630, SP 2025)

SV-TrustEval-C is a benchmark with Structure-Oriented Variants Generator that perturbs Data Flow Graphs (DFG) and Control Flow Graphs (CFG), containing 9,401 Q&A pairs across 82 CWEs. The benchmark demonstrates that LLMs rely heavily on pattern-matching rather than deep semantic understanding.

**Important:** These fixtures are synthetic and created for the baco project. They are NOT copied from the SV-TrustEval-C dataset.

## License

GPL v3 - Same as the baco project

## Fixture Pairs

| Pair | CWE ID | Vulnerability Type | Vulnerable File | Safe File |
|------|--------|-------------------|-----------------|-----------|
| 1 | CWE-89 | SQL Injection | `cwe089_vuln.c` | `cwe089_safe.c` |
| 2 | CWE-79 | Cross-Site Scripting (XSS) | `cwe079_vuln.c` | `cwe079_safe.c` |
| 3 | CWE-120 | Buffer Overflow | `cwe120_vuln.c` | `cwe120_safe.c` |
| 4 | CWE-22 | Path Traversal | `cwe022_vuln.c` | `cwe022_safe.c` |
| 5 | CWE-416 | Use After Free | `cwe416_vuln.c` | `cwe416_safe.c` |

## Usage

These fixtures are used by the integration test in `tests/integration/sv_trusteval.rs` to verify:

1. Vulnerable files are detected with appropriate CWE classifications
2. Safe files produce no findings (or low-confidence findings)
3. Paired comparison shows higher confidence for vulnerable variants

## Building/Fixtures Verification

Each C file is compilable and can be tested:

```bash
gcc -Wall -Wextra -o cwe089_vuln tests/fixtures/sv_trusteval/cwe089_vuln.c
./cwe089_vuln "admin' OR '1'='1"
```

## Related

- SV-TrustEval-C paper: https://arxiv.org/abs/2505.20630
- baco vulnerability scanner: https://github.com/mte90/baco