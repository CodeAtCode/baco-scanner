# BACO — Agent Rules

Hard rules for every agent session on this repository. Violations block commits.

## CI gate (mandatory before every commit)

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

All three must pass: formatting clean, zero clippy warnings on all targets, zero failing tests. Run the full gate after any batch of changes, not only at the end.

## Test placement

- All tests live under `tests/unit/` (unit) and `tests/integration/` (integration).
- NO inline `#[cfg(test)]` blocks in `src/` files. Migrate them out when found.
- Test modules are declared in the matching `mod.rs` (`tests/unit/mod.rs` or the submodule directory's `mod.rs`); declare only modules that exist on disk.
- Tests import via the crate name (`baco::...`) and only public items. Making a production item `pub` to test it is acceptable; keep the visibility chain minimal.
- Every test must assert real behavior. No empty-body tests, no `assert!(true)`, no disabled tests left behind.

## Git

- Commit locally only. Never push — pushes are performed manually by the maintainer.
- Terse, factual commit messages. No references to internal plans, task numbers, waves, or tiers (`T1`, `phase 2`, `W3`) in commits, comments, or code.

## Config discipline

- Every configuration key accepted in TOML (including presets under `presets/`) must map to a real struct field and be consumed by production logic. No phantom options.
- A regression test (`tests/unit/preset_tests.rs::test_presets_contain_only_known_keys`) enforces this for presets — keep it passing.
