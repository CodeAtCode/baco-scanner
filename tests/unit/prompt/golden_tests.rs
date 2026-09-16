#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn test_static_analysis_prompt_no_cwe_1000() {
        let content = fs::read_to_string(
            format!(
                "{}/prompts/phases/llm_static_analysis.md",
                env!("CARGO_MANIFEST_DIR")
            )
            .as_str(),
        )
        .expect("Could not read llm_static_analysis.md");

        assert!(
            !content.contains("CWE-1000"),
            "Prompt should not contain CWE-1000 (fake finding marker)"
        );
    }

    #[test]
    fn test_static_analysis_prompt_no_never_return_empty() {
        let content = fs::read_to_string(
            format!(
                "{}/prompts/phases/llm_static_analysis.md",
                env!("CARGO_MANIFEST_DIR")
            )
            .as_str(),
        )
        .expect("Could not read llm_static_analysis.md");

        let content_lower = content.to_lowercase();
        assert!(
            !content_lower.contains("never return empty"),
            "Prompt should not contain 'NEVER return empty' instruction"
        );
    }

    #[test]
    fn test_static_analysis_prompt_has_empty_array_instruction() {
        let content = fs::read_to_string(
            format!(
                "{}/prompts/phases/llm_static_analysis.md",
                env!("CARGO_MANIFEST_DIR")
            )
            .as_str(),
        )
        .expect("Could not read llm_static_analysis.md");

        // Count occurrences of empty array instruction
        let count = content.matches("[]").count();
        assert!(
            count >= 1,
            "Prompt should contain at least one empty array [] instruction for clean files"
        );
    }

    #[test]
    fn test_static_analysis_prompt_empty_array_section_exists() {
        let content = fs::read_to_string(
            format!(
                "{}/prompts/phases/llm_static_analysis.md",
                env!("CARGO_MANIFEST_DIR")
            )
            .as_str(),
        )
        .expect("Could not read llm_static_analysis.md");

        // Check for the section header
        assert!(
            content.contains("IF NO VULNERABILITIES FOUND"),
            "Prompt should contain 'IF NO VULNERABILITIES FOUND' section"
        );

        // Check that it shows empty array as the return value
        assert!(
            content.contains("```json\n[]\n```"),
            "Prompt should show empty JSON array in code block for no vulnerabilities"
        );
    }

    #[test]
    fn test_static_analysis_prompt_reasoning_present() {
        let content = fs::read_to_string(
            format!(
                "{}/prompts/phases/llm_static_analysis.md",
                env!("CARGO_MANIFEST_DIR")
            )
            .as_str(),
        )
        .expect("Could not read llm_static_analysis.md");

        // After the empty array, there should be reasoning text
        assert!(
            content.contains("**Reasoning**: After analyzing"),
            "Prompt should include reasoning explanation for empty result"
        );
    }
}
