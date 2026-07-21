# Test Fixture Dataset Hygiene Rules

> Source: PrimeVul — [arxiv:2403.18624](https://arxiv.org/abs/2403.18624)
> Legacy benchmarks overestimate vulnerability detection by up to 22×.
> Any dataset imported into this directory MUST follow the rules below.

## Mandatory Rules

### 1. Chronological Splits

Train/test splits must be ordered by commit timestamp, not random shuffling.

- **Wrong**: Random 80/20 split — the model sees future vulnerabilities during training.
- **Right**: Sort all vulnerable + safe samples by commit date. Training set = oldest 80%. Test set = newest 20%.

Rationale: In production, the scanner sees code written after the model was trained. Random splits leak future patterns into training, inflating recall by up to 22×.

### 2. Deduplication

No duplicated functions across train/test splits.

- Hash each function body (normalized whitespace).
- If a function appears in both train and test, remove it from test.
- If a function appears multiple times within the same split, keep one.

Rationale: Deduplication prevents the model from memorizing specific functions rather than learning vulnerability patterns.

### 3. No Data Leakage from CVE Fixes

If a vulnerable function is in the training set, the fixed (safe) version of the same function must NOT appear in the test set.

- Track CVE IDs for each sample.
- If train contains the vulnerable version of CVE-2024-XXXX, test must not contain the fixed version of the same CVE.

Rationale: The model learns "this function was patched for CVE-2024-XXXX" and trivially classifies the test version as safe — this is memorization, not detection.

### 4. Balanced Class Distribution

Vulnerable and safe samples should be roughly balanced (40–60% each).

- **Wrong**: 95% safe, 5% vulnerable — the model achieves 95% accuracy by always predicting "safe".
- **Right**: Stratifed sampling to maintain ~50/50 ratio in each split.

### 5. Repository Diversity

Samples should come from diverse repositories, not a single project.

- **Wrong**: All samples from one monorepo — model learns project-specific patterns.
- **Right**: Samples from 10+ repositories across different domains.

## File Organization

```
tests/fixtures/
├── README.md                  ← this file
├── sv_trusteval/              ← SV-TrustEval-C subset (T1.4)
│   ├── README.md              ← attribution + license
│   └── *.c                    ← paired vulnerable/safe variants
├── primevul/                  ← PrimeVul subset (future, X.3)
│   └── README.md
└── secvuleval/                ← SecVulEval subset (future, X.2)
    └── README.md
```

## Validation Script (Future)

Before adding any new dataset, run:

```bash
# Check for duplicates across splits
python3 scripts/validate_dataset.py tests/fixtures/<dataset>/ --check-dedup --check-chronological --check-leakage
```

Until the script exists, validate manually using the rules above.

## Attribution

Each dataset subdirectory MUST contain a `README.md` with:
- Paper citation (arXiv link)
- Dataset license
- Download date
- Any modifications made to the original dataset
