# CI Integration Guide

BACO outputs SARIF 2.1 format (`report.sarif`), which GitHub Code Scanning, Azure DevOps, and other CI tools can ingest to display findings as PR annotations and security alerts.

## GitHub Actions Setup

Add this workflow to `.github/workflows/baco-scan.yml`:

```yaml
name: BACO Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  baco-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build BACO
        run: cargo build --release

      - name: Install Semgrep
        run: pip install semgrep

      - name: Run BACO Scan
        env:
          MISTRAL_API_KEY: ${{ secrets.MISTRAL_API_KEY }}
        run: ./target/release/baco scan --config baco.toml

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: baco-output/report.sarif
```

**Required:** Set `MISTRAL_API_KEY` (or your LLM provider key) as a GitHub repository secret.

## Configuration

Create a `baco.toml` config file in your repository root. See [Configuration Reference](configuration.md) for all options.

For faster CI runs, disable heavy LLM phases:

```toml
[scanner.performance]
enable_threat_modeling = false
enable_root_cause_dedup = false
enable_multi_verifier = false
enable_cve_bootstrap = false
enable_variant_search = false
```

## Viewing Results

After the workflow runs:

- **Code Scanning alerts**: Navigate to **GitHub → Security → Code Scanning alerts**
- **PR annotations**: Findings automatically appear as inline annotations on changed lines in pull requests

## Other CI Systems

### Azure DevOps

Use the [SARIF results tab extension](https://marketplace.visualstudio.com/items?itemName=snyk.sarif-results-tab) to upload `report.sarif` as a pipeline artifact.

### GitLab CI

Add `report.sarif` as a SARIF report artifact:

```yaml
baco-scan:
  script:
    - cargo build --release
    - ./target/release/baco scan --config baco.toml
  artifacts:
    reports:
      sast: baco-output/report.sarif
```

### Generic SARIF Support

Any tool that reads SARIF 2.1 can ingest `report.sarif`:
- CodeQL CLI
- Semgrep CLI
- Microsoft SARIF Viewer
- Custom parsers and dashboards