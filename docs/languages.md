# Supported Languages

BACO supports analysis of multiple programming languages through a combination of static analysis tools and LLM-powered verification.

## Analysis Methods

| Method | Description |
|--------|-------------|
| **Static analysis** | Uses tree-sitter for AST parsing and semgrep for pattern-based vulnerability detection. Fast, deterministic, zero false negatives for known patterns. |
| **LLM analysis** | Uses LLM-powered verification to confirm findings, reduce false positives, and discover complex vulnerabilities that require semantic understanding. |

## Language Coverage

| Language      | Static analysis          | LLM analysis |
| ------------- | ------------------------ | ------------ |
| C / C++       | tree-sitter + semgrep    | ✅           |
| Rust          | tree-sitter              | ✅           |
| Python        | tree-sitter + semgrep    | ✅           |
| JavaScript    | tree-sitter + semgrep    | ✅           |
| TypeScript    | tree-sitter + JS rules   | ✅           |
| PHP           | tree-sitter + semgrep    | ✅           |
| Go            | tree-sitter + semgrep    | ✅           |
| Java          | tree-sitter + semgrep    | ✅           |
| C#            | tree-sitter + semgrep    | ✅           |
| Ruby          | tree-sitter + semgrep    | ✅           |

## Notes

- All supported languages receive tree-sitter parsing and LLM verification
- The bundled semgrep taint rules cover C/C++, Python, JavaScript/TypeScript, PHP, Go, Java, C# and Ruby. Rust is parsed by tree-sitter but has no bundled taint rule file, so only the rulesets you configure apply
- Tree-sitter grammars must be available for each language (handled automatically by BACO)
