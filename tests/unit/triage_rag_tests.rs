//! Tests for T17 (triage cascade) and T22 (smarter RAG queries)

#[cfg(test)]
mod rag_query_tests {
    use baco::llm_analysis::{build_rag_query, extract_imports, extract_sink_calls};

    #[test]
    fn test_extract_sink_calls() {
        let code = r#"
            eval(user_input);
            system("ls -la");
            const data = require('fs');
        "#;

        let sinks = extract_sink_calls(code);
        assert!(sinks.contains(&"eval".to_string()));
        assert!(sinks.contains(&"system".to_string()));
        assert!(sinks.contains(&"require".to_string()));
    }

    #[test]
    fn test_extract_imports() {
        let code = r#"
            import React from 'react';
            const fs = require('fs');
            use std::io;
            #include <stdio.h>
            const unused = 42;
        "#;

        let imports = extract_imports(code);
        assert_eq!(imports.len(), 4);
        assert!(imports.iter().any(|i| i.contains("import React")));
        assert!(imports.iter().any(|i| i.contains("require('fs')")));
        assert!(imports.iter().any(|i| i.contains("use std::io")));
        assert!(imports.iter().any(|i| i.contains("#include")));
    }

    #[test]
    fn test_build_rag_query_with_sinks() {
        let code = r#"
            eval(user_input);
            import React from 'react';
        "#;

        let query = build_rag_query("test.js", code, None);
        assert!(query.contains("test.js"));
        assert!(query.contains("sinks:"));
        assert!(query.contains("eval"));
        assert!(query.contains("imports:"));
    }

    #[test]
    fn test_build_rag_query_with_cwe_hints() {
        let code = "const x = 42;";
        let cwes = vec!["CWE-89".to_string(), "CWE-79".to_string()];

        let query = build_rag_query("test.js", code, Some(&cwes));
        assert!(query.contains("test.js"));
        assert!(query.contains("suspected CWEs:"));
        assert!(query.contains("CWE-89"));
        assert!(query.contains("CWE-79"));
    }

    #[test]
    fn test_build_rag_query_fallback() {
        let code = "const x = 42; const y = 5;";

        let query = build_rag_query("test.js", code, None);
        assert!(query.contains("test.js"));
        // Should fall back to first 20 lines when no sinks/imports/CWEs
        assert!(query.contains("const x = 42"));
    }
}

#[cfg(test)]
mod triage_config_tests {
    use baco::config::TriageConfig;

    #[test]
    fn test_triage_config_defaults() {
        let config = TriageConfig::default();

        assert!(!config.enabled, "Triage should be disabled by default");
        assert_eq!(
            config.model, "mistral-small",
            "Default model should be mistral-small"
        );
        assert_eq!(config.batch_size, 8, "Default batch size should be 8");
        assert_eq!(
            config.suspicion_threshold, 0.35,
            "Default threshold should be 0.35"
        );
    }

    use baco::scanner::phases::llm_phases::static_analysis::should_analyze_file;

    #[test]
    fn test_should_analyze_file_threshold_logic() {
        // Test boundary conditions for suspicion threshold
        let threshold = 0.35;

        // Below threshold - should skip
        assert!(
            !should_analyze_file(0.34, threshold),
            "0.34 < 0.35 should skip"
        );

        // At threshold - should analyze (>=)
        assert!(
            should_analyze_file(0.35, threshold),
            "0.35 >= 0.35 should analyze"
        );

        // Above threshold - should analyze
        assert!(
            should_analyze_file(0.36, threshold),
            "0.36 > 0.35 should analyze"
        );

        // Edge cases
        assert!(!should_analyze_file(0.0, threshold), "0.0 should skip");
        assert!(should_analyze_file(1.0, threshold), "1.0 should analyze");
    }

    #[test]
    fn test_triage_config_from_toml() {
        let toml_str = r#"
            enabled = true
            model = "custom-model"
            batch_size = 16
            suspicion_threshold = 0.5
        "#;

        let config: TriageConfig = toml::from_str(toml_str).expect("Failed to parse TOML");

        assert!(config.enabled);
        assert_eq!(config.model, "custom-model");
        assert_eq!(config.batch_size, 16);
        assert_eq!(config.suspicion_threshold, 0.5);
    }

    #[test]
    fn test_triage_config_partial_toml() {
        let toml_str = r#"
            enabled = true
        "#;

        let config: TriageConfig = toml::from_str(toml_str).expect("Failed to parse TOML");

        assert!(config.enabled);
        assert_eq!(config.model, "mistral-small", "Should use default model");
        assert_eq!(config.batch_size, 8, "Should use default batch size");
        assert_eq!(
            config.suspicion_threshold, 0.35,
            "Should use default threshold"
        );
    }
}
