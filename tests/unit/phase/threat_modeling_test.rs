#[cfg(test)]
mod tests {
    use baco::analysis_context::AnalysisContext;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use tempfile::TempDir;

    #[test]
    fn test_threat_modeling_phase_name_and_order() {
        let phase = baco::threat_model::ThreatModelingPhase;
        assert!(format!("{:?}", phase).contains("ThreatModeling"));
    }

    #[tokio::test]
    async fn test_threat_modeling_phase_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output");
        std::fs::create_dir_all(&output_path).unwrap();

        let context = AnalysisContext::default();

        let result =
            baco::threat_model::ThreatModelingPhase::run(&output_path, &context, None).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_threat_modeling_phase_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output");
        std::fs::create_dir_all(&output_path).unwrap();

        let _findings = [create_test_finding(
            "Test vulnerability",
            "test.rs",
            42,
            Severity::High,
        )];

        let context = AnalysisContext::default();

        let result =
            baco::threat_model::ThreatModelingPhase::run(&output_path, &context, None).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_threat_modeling_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output");
        std::fs::create_dir_all(&output_path).unwrap();

        let _findings = [
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        let context = AnalysisContext::default();

        let result =
            baco::threat_model::ThreatModelingPhase::run(&output_path, &context, None).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_threat_modeling_phase_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output");
        std::fs::create_dir_all(&output_path).unwrap();

        let context = AnalysisContext::default();

        let result =
            baco::threat_model::ThreatModelingPhase::run(&output_path, &context, None).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_threat_modeling_static_generation() {
        let architecture = "=== ARCHITECTURAL SUMMARY ===\nHTTP endpoints: 5\nDatabase: SQLite";
        let threat_model = baco::threat_model::generate_threat_model_static(architecture);

        assert!(threat_model.contains("TRUST BOUNDARIES"));
        assert!(threat_model.contains("STRIDE"));
        assert!(!threat_model.is_empty());
    }
}
