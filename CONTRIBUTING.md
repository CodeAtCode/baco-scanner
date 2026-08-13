# Contributing to BACO

Welcome! BACO (Bug Analysis & Cross-reference Orchestrator) is a research-backed SAST scanner that augments static analysis with LLM-powered discovery across a 24-phase pipeline. Sponsored by [Regolo.AI](https://regolo.ai), this project integrates techniques from 18 academic papers to detect vulnerabilities with higher accuracy than traditional tools.

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CodeAtCode/baco-scanner.git
   cd baco-scanner
   ```

2. **Build from source:**
   ```bash
   cargo build
   ```

3. **Run the test suite:**
   ```bash
   cargo test
   ```

## Development Workflow

1. **Create a branch** from `master` for your feature or fix:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** following the code standards below.

3. **Run the CI gate locally** before committing:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

4. **Commit with conventional commit messages:**
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `refactor:` Code restructuring
   - `test:` Test additions/updates
   - `chore:` Maintenance tasks

## Code Standards

- **Rust 1.74+ MSRV**: Do not use APIs stabilized after Rust 1.74. The `rust-version` field in `Cargo.toml` enforces this.
- **Zero clippy warnings**: All code must pass `cargo clippy --all-targets -- -D warnings`.
- **All tests must pass**: No commits when tests fail.
- **No inline test modules**: `#[cfg(test)]` blocks are forbidden in `src/`. All tests go in `tests/unit/` or `tests/integration/`.
- **Test file naming**: Use `<module_name>_tests.rs` in the matching subdirectory (e.g., `tests/unit/scanner_phases_tests.rs`).
- **Test module declaration**: Declare tests in `tests/unit/mod.rs` using full crate paths.

## Adding a New Scanner Phase

Adding a phase requires updates in multiple locations:

1. **PhaseGraph**: Register the phase in `src/scanner/pipeline/orchestrator.rs` with stable index.
2. **Checkpoint transitions**: Add checkpoint handling for the new phase.
3. **Tests**: Update all phase-count references in test files.
4. **Documentation**: Update `docs/architecture.md` and `README.md` phase counts.

## Adding Tests

- **Unit tests**: Place in `tests/unit/` subdirectories matching the module structure.
- **Integration tests**: Place in `tests/integration/` for multi-phase or end-to-end scenarios.
- **Shared fixtures**: Use fixtures from `tests/unit/fixtures.rs` to avoid duplication.
- **Mock LLM calls**: Never hit real APIs in tests—use `mockito` for HTTP mocking.

## Reporting Issues

When filing a bug report, include:

- **Rust version**: `rustc --version`
- **OS**: Platform and version
- **BACO version**: From `Cargo.toml` or `baco --version`
- **Minimal repro**: Steps or code snippet to reproduce the issue
- **Expected vs actual behavior**: Clear description of the discrepancy

## License

BACO is licensed under GPL v3. By contributing, you agree that your contributions will be licensed under the same terms. See `LICENSE` for details.