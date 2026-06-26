#[cfg(test)]
mod tests {
    use crate::config::{ScannerConfig, TicketSystemConfig};
    use crate::findings::Severity;
    use crate::phase::helpers::create_test_finding;
    use crate::phase::ticket_crossref::TicketCrossRefPhase;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ticket_crossref_phase_name_and_order() {
        let phase = TicketCrossRefPhase;
        assert_eq!(phase.name(), "TicketCrossRef");
        assert_eq!(phase.order(), 6);
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.tickets.systems.push(TicketSystemConfig {
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            api_key: None,
            project: None,
        });

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_without_ticket_systems() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("No ticket system test", "test.rs", 10, Severity::Medium);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_is_enabled_with_systems() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.tickets.systems.push(TicketSystemConfig {
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            api_key: None,
            project: None,
        });

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = TicketCrossRefPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_is_disabled_without_systems() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = TicketCrossRefPhase;
        assert!(!phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.tickets.systems.push(TicketSystemConfig {
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            api_key: None,
            project: None,
        });

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Ticket crossref test", "test.rs", 10, Severity::High);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_ticket_crossref_phase_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.tickets.systems.push(TicketSystemConfig {
            system_type: "jira".to_string(),
            url: "https://jira.example.com".to_string(),
            api_key: None,
            project: None,
        });

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("Finding 1", "file1.rs", 1, Severity::Critical),
            create_test_finding("Finding 2", "file2.rs", 10, Severity::High),
            create_test_finding("Finding 3", "file3.rs", 20, Severity::Medium),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 3);
    }
}
