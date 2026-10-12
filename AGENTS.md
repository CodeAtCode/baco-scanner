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

## Tests must be able to fail

A test that passes no matter what the production code does is worse than no test: it inflates the count, reports coverage, and catches nothing. Line coverage cannot detect this class of defect, because a toothless test executes the code it claims to cover.

### Order: the regression test comes before the fix

For a bug fix, write the test first and run it against the unfixed code. If it passes, it is not a regression test — either the bug does not reproduce, or the test does not detect it. Both outcomes must be resolved before writing the fix.

Writing the fix and then the test produces a test that describes what the code does, not what it should do. That is how `map_chunk_line_clamps_out_of_range` came to assert the clamping it should have caught.

### The test must call production code

A test may not re-implement the rule it is checking. Copying a comparator, a loop, or a match into a test body makes it assert that the copy is correct, which is independent of the code under test. Call the function; if it is private and unreachable, add a seam rather than duplicating it.

Tautologies are the degenerate case of the same fault:

```rust
assert!(result.is_ok() || result.is_err());   // always true
assert_eq!(true, true);
assert!(findings.len() <= findings.len());     // always true
```

### A test asserting buggy behaviour is a defect, not coverage

When a fix breaks a test, the test is wrong until proven otherwise. Six tests asserted that a fabricated `diff_hunk` was correct; three asserted a finding was `Failed` when the agent merely timed out. Fix the assertion, and record in the commit which test was certifying the bug.

### Prove the teeth before committing

For any behaviour change, disable the production change and confirm at least one test fails. Then restore and confirm it passes. Report both counts. Zero failures means the test is toothless — delete it.

Corollaries worth stating, because they decide ambiguous cases:

- A test that is unaffected by a mutation to the function it names is testing something else. That is the signal, not the excuse.
- Mutating the production code is how the whole suite is checked, not just the new test.

## Git

- Commit locally only. Never push — pushes are performed manually by the maintainer.
- Terse, factual commit messages. No references to internal plans, task numbers, waves, or tiers (`T1`, `phase 2`, `W3`) in commits, comments, or code.

## Config discipline

- Every configuration key accepted in TOML (including presets under `presets/`) must map to a real struct field and be consumed by production logic. No phantom options.
- A regression test (`tests/unit/preset_tests.rs::test_presets_contain_only_known_keys`) enforces this for presets — keep it passing.
