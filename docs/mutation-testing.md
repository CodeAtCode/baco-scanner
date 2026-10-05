# Mutation Testing

Mutation testing answers a question the passing test suite cannot: **would these
tests fail if the code were wrong?**

## How it works

`cargo-mutants` takes each expression the tool can break and applies one mutation
at a time, then runs the full test suite against the mutated build:

| Mutation | Example |
|---|---|
| Swap a comparison | `if a > b` becomes `if a >= b` |
| Swap an operator | `a + b` becomes `a - b` |
| Replace a return value | `return x` becomes `return Default::default()` |
| Delete a match arm | a `match` arm handling a variant disappears |
| Replace with a constant | `return Ok(count)` becomes `return Ok(0)` |

Then:

- **Killed** — at least one test failed. The suite detects this bug. This is the
  desired outcome.
- **Survived** — every test still passed. The suite cannot tell the mutated code
  from the original. That branch, condition or return value is untested.

A surviving mutant is not necessarily a bug in the code. It is always a gap in the
tests.

## Why it runs at night, not on every pull request

Measured on this repository: a full-crate run generates **5414** mutants, and each
one relinks a test binary holding roughly **5750** tests. That is about **two
minutes per mutant** with eight parallel jobs — an **11 to 16 hour** job.

So `.cargo/mutants.toml` scopes the run to the seven modules that decide a verdict
a user acts on. `cargo mutants --list` counts **411** of them:

| Module | Mutants |
|---|---|
| `confidence_refinement.rs` | 172 |
| `scanner/phases/llm_phases/verification.rs` | 150 |
| `tools/diff_analysis.rs` | 30 |
| `citation_verification.rs` | 24 |
| `findings.rs` | 20 |
| `evidence.rs` | 9 |
| `report/sarif.rs` | 6 |

Even scoped, that is roughly two hours on a 4-core runner. It runs on a **nightly
cron** (03:17 UTC) split into four shards, plus `workflow_dispatch` to trigger it
by hand. Each shard skips the baseline test run because ordinary CI has already
established the tree is green.

## Running it locally

```bash
cargo install cargo-mutants --version 27.1.0 --locked

cargo mutants --list                    # list what would be tested
cargo mutants -j 4 -t 900               # run the configured scope
cargo mutants -- --test unit_tests      # narrow which test binary is built
```

Scoped to a single module, override the config:

```bash
cargo mutants -- src/evidence.rs
```

The output directory is `mutants.out/`, already ignored. `missed.txt` holds the
survivors.

## Reading the result

A survivor is worth investigating in this order:

1. **Is the mutated behaviour load-bearing?** Replacing a return value with its
   default is only interesting if the value reaches the user.
2. **Is it reachable?** A mutant in dead code can never be killed and is not worth
   a test. Check reachability before writing anything.
3. **Would a test catch it?** If the honest answer is that the branch does not
   matter, suppress that mutant rather than writing a test that asserts nothing.

Point 3 matters: adding a test to kill a mutant that does not matter produces a
passing test that will not catch anything either.

## What it is not

This is a **diagnostic, not a gate**. It does not block a pull request and it does
not decide whether code ships. It reports which parts of the verdict-deciding code
the test suite cannot detect a defect in.

`ci.yml` remains the gate: formatting, clippy with `-D warnings`, and the test
suite.

## Configuration reference

`.cargo/mutants.toml` holds the scope. Jobs and the absolute timeout are
command-line flags (`-j`, `-t`) and cannot be set in the file — the schema for
27.1.0 has no such keys. Verify against the installed version with:

```bash
cargo mutants --emit-schema config
```