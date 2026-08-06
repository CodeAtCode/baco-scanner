//! LLM prompt template for semgrep YAML rule generation
//!
//! Based on MoCQ paper methodology: [arxiv:2504.16057](https://arxiv.org/abs/2504.16057)

/// Build a prompt for the LLM to generate semgrep rules
pub fn build_prompt(cwe: &str, language: &str, max_rules: usize) -> String {
    format!(
        r#"You are a security rule synthesizer. Generate semgrep YAML rules for the following vulnerability:

CWE: {cwe}
Language: {language}
Maximum rules to generate: {max_rules}

Generate semgrep rules that detect this vulnerability pattern. Follow these requirements:

1. Output MUST be valid YAML with a top-level "rules:" key
2. Each rule MUST have:
   - id: A unique identifier (format: cwe-{cwe}-<description>)
   - patterns: One or more pattern matchers
   - message: A clear description of the vulnerability
   - languages: [{language}]
   - severity: WARNING or ERROR

3. Pattern guidelines:
   - Use semgrep's pattern syntax ($VAR, pattern-equals, pattern-regex, etc.)
   - Focus on the specific vulnerability pattern for this CWE
   - Include taint tracking if appropriate (pattern-sources, pattern-sinks)
   - Be specific enough to avoid false positives

4. Output format:
   - Separate multiple rules with "---"
   - Each rule should be a complete, valid semgrep rule
   - Return at most {max_rules} rules

Example rule structure:
```yaml
rules:
  - id: cwe-{cwe}-example
    patterns:
      - pattern: |
          $FUNC($INPUT)
    message: "Potential {cwe} vulnerability detected"
    languages:
      - {language}
    severity: WARNING
    metadata:
      cwe: "{cwe}"
      category: security
      confidence: medium
---
rules:
  - id: cwe-{cwe}-alternative
    pattern: |
      $X
    message: "Alternative {cwe} pattern"
    languages:
      - {language}
    severity: ERROR
```

Generate {max_rules} rules for CWE-{cwe} in {language}:"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_prompt_contains_cwe() {
        let prompt = build_prompt("CWE-79", "python", 3);
        assert!(prompt.contains("CWE: CWE-79"));
        assert!(prompt.contains("Language: python"));
        assert!(prompt.contains("Maximum rules to generate: 3"));
    }

    #[test]
    fn test_build_prompt_contains_requirements() {
        let prompt = build_prompt("CWE-89", "javascript", 5);
        assert!(prompt.contains("top-level \"rules:\" key"));
        assert!(prompt.contains("id:"));
        assert!(prompt.contains("patterns:"));
        assert!(prompt.contains("message:"));
        assert!(prompt.contains("languages:"));
        assert!(prompt.contains("severity:"));
    }

    #[test]
    fn test_build_prompt_max_rules() {
        let prompt = build_prompt("CWE-22", "go", 10);
        assert!(prompt.contains("Maximum rules to generate: 10"));
        assert!(prompt.contains("Return at most 10 rules"));
    }

    #[test]
    fn test_build_prompt_empty_cwe() {
        let prompt = build_prompt("", "python", 3);
        assert!(prompt.contains("CWE: "));
        assert!(prompt.contains("Language: python"));
    }

    #[test]
    fn test_build_prompt_empty_language() {
        let prompt = build_prompt("CWE-79", "", 3);
        assert!(prompt.contains("CWE: CWE-79"));
        assert!(prompt.contains("Language: "));
    }

    #[test]
    fn test_build_prompt_zero_max_rules() {
        let prompt = build_prompt("CWE-79", "python", 0);
        assert!(prompt.contains("Maximum rules to generate: 0"));
        assert!(prompt.contains("Generate 0 rules"));
    }

    #[test]
    fn test_build_prompt_single_rule() {
        let prompt = build_prompt("CWE-79", "python", 1);
        assert!(prompt.contains("Maximum rules to generate: 1"));
        assert!(prompt.contains("Generate 1 rules"));
    }

    #[test]
    fn test_build_prompt_long_cwe_number() {
        let prompt = build_prompt("CWE-123456789", "python", 3);
        assert!(prompt.contains("CWE: CWE-123456789"));
        assert!(prompt.contains("Generate 3 rules for CWE-CWE-123456789"));
    }

    #[test]
    fn test_build_prompt_special_chars_language() {
        let prompt = build_prompt("CWE-79", "c++", 3);
        assert!(prompt.contains("Language: c++"));
        assert!(prompt.contains("languages: [c++]"));

        let prompt = build_prompt("CWE-89", "c#", 3);
        assert!(prompt.contains("Language: c#"));
        assert!(prompt.contains("languages: [c#]"));
    }

    #[test]
    fn test_build_prompt_contains_yaml_separator() {
        let prompt = build_prompt("CWE-79", "python", 3);
        assert!(
            prompt.contains("---"),
            "Prompt should contain YAML document separator"
        );
    }

    #[test]
    fn test_build_prompt_contains_example_structure() {
        let prompt = build_prompt("CWE-79", "python", 3);
        assert!(
            prompt.contains("rules:"),
            "Prompt should contain 'rules:' in example structure"
        );
    }
}
