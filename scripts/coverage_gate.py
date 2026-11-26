#!/usr/bin/env python3
"""Coverage gate for the files where defects actually surfaced.

Fails when the line coverage of a hot file drops below the versioned baseline
in scripts/coverage-baseline.json. The point is not the absolute number: it is
that a change which removes exercised behaviour cannot land silently.

Regenerating the baseline is a deliberate act, reviewed like code:

    cargo llvm-cov --lcov --output-path lcov.info
    python3 scripts/coverage_gate.py --write-baseline lcov.info scripts/coverage-baseline.json

Only ever move it upward in review.
"""

import fnmatch
import json
import sys

HOT_GLOBS = [
    "src/doctor.rs",
    "src/cli/**",
    "src/config/**",
    "src/scan_health.rs",
    "src/scanner/orchestrator.rs",
    "src/scanner/phases/llm_phases/**",
]


def canonical(path: str) -> str:
    path = path.replace("\\", "/")
    if "/src/" in path:
        return "src/" + path.split("/src/", 1)[1]
    if path.startswith("./"):
        return path[2:]
    return path


def parse_lcov(lcov_path):
    """Return {canonical_path: {line: hit_count}}, merging duplicate records.

    cargo-llvm-cov can emit one record per test binary; the same source line
    hit in either counts as hit, so records merge by summing counts per line.
    """
    records = {}
    current = None
    with open(lcov_path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("SF:"):
                current = canonical(line[3:])
                records.setdefault(current, {})
            elif line.startswith("DA:") and current is not None:
                fields = line[3:].split(",")
                try:
                    lineno = int(fields[0])
                    hits = int(fields[1])
                except (IndexError, ValueError):
                    continue
                records[current][lineno] = records[current].get(lineno, 0) + hits
            elif line == "end_of_record":
                current = None
    return {path: lines for path, lines in records.items() if lines}


def tally(lines):
    found = len(lines)
    hit = sum(1 for count in lines.values() if count > 0)
    return hit, found


def pct(hit, found):
    return f"{100.0 * hit / found:.2f}%" if found else "100.00%"


def write_baseline(records, baseline_path):
    files = {}
    for path, lines in sorted(records.items()):
        if not any(fnmatch.fnmatch(path, glob) for glob in HOT_GLOBS):
            continue
        hit, found = tally(lines)
        files[path] = {"lines_hit": hit, "lines_found": found}
    payload = {
        "comment": (
            "Line-coverage floor for the hot files, as (lines_hit, lines_found). "
            "The ci.yml coverage job fails a build when a file falls below its "
            "recorded pair. Regenerate with --write-baseline after adding tests; "
            "in review, only ever upward."
        ),
        "files": files,
    }
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"baseline written: {len(files)} hot files to {baseline_path}")


def gate(records, baseline_path):
    with open(baseline_path, encoding="utf-8") as fh:
        baseline = json.load(fh)
    problems = []
    checked = 0
    for path, entry in sorted(baseline["files"].items()):
        hit_b = int(entry["lines_hit"])
        found_b = int(entry["lines_found"])
        if path not in records:
            problems.append(
                f"{path}: in the baseline but absent from the coverage report - "
                f"renamed or deleted; update scripts/coverage-baseline.json"
            )
            continue
        hit_c, found_c = tally(records[path])
        checked += 1
        # Integer cross-multiplication: hit_c/found_c < hit_b/found_b exactly.
        if found_c == 0 and found_b > 0:
            problems.append(
                f"{path}: no instrumented lines in the coverage report "
                f"(baseline was {hit_b}/{found_b})"
            )
        elif hit_c * found_b < hit_b * found_c:
            problems.append(
                f"{path}: line coverage fell: {hit_c}/{found_c} ({pct(hit_c, found_c)}) "
                f"< baseline {hit_b}/{found_b} ({pct(hit_b, found_b)}) - add tests, "
                f"or update scripts/coverage-baseline.json deliberately"
            )
    if problems:
        print("coverage gate: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"coverage gate: {checked} hot files at or above the baseline")
    return 0


def main(argv):
    if "--help" in argv:
        print(__doc__)
        return 0
    if len(argv) == 4 and argv[1] == "--write-baseline":
        write_baseline(parse_lcov(argv[2]), argv[3])
        return 0
    if len(argv) == 3:
        return gate(parse_lcov(argv[1]), argv[2])
    print(
        "usage: coverage_gate.py <lcov.info> <baseline.json>   (gate)\n"
        "       coverage_gate.py --write-baseline <lcov.info> <baseline.json>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
