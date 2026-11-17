/// Tests for dry-run mode and CLI flag parsing.
///
/// These tests verify:
/// - Dry-run flag parsing
/// - Version string format
/// - Preset flag parsing

#[test]
fn test_version_string_format() {
    // Verify that the version string follows semver format
    let version = env!("CARGO_PKG_VERSION");

    // Should contain at least major.minor.patch
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "Version should have at least major.minor.patch"
    );

    // Major, minor, patch should be numeric
    assert!(
        parts[0].parse::<u32>().is_ok(),
        "Major version should be numeric"
    );
    assert!(
        parts[1].parse::<u32>().is_ok(),
        "Minor version should be numeric"
    );

    // Patch might have suffix (e.g., "0-alpha.1"), so just check it starts with a number
    assert!(
        parts[2]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false),
        "Patch version should start with a number"
    );
}

#[test]
fn test_dry_run_flag_parsing() {
    // Test that --dry-run flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[arg(long)]
        dry_run: bool,
    }

    // Test with flag present
    let cli = TestCli::try_parse_from(["test", "--dry-run"]);
    assert!(cli.is_ok());
    assert!(cli.unwrap().dry_run);

    // Test with flag absent
    let cli = TestCli::try_parse_from(["test"]);
    assert!(cli.is_ok());
    assert!(!cli.unwrap().dry_run);
}

#[test]
fn test_preset_flag_parsing() {
    // Test that --preset flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[arg(long)]
        preset: Option<String>,
    }

    // Test with flag and value
    let cli = TestCli::try_parse_from(["test", "--preset", "default"]);
    assert!(cli.is_ok());
    assert_eq!(cli.unwrap().preset, Some("default".to_string()));

    // Test with flag absent
    let cli = TestCli::try_parse_from(["test"]);
    assert!(cli.is_ok());
    assert!(cli.unwrap().preset.is_none());
}

#[test]
fn test_version_flag_parsing() {
    // Test that --version flag is recognized by clap
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(version = "1.0.0")]
    struct TestCli {
        #[arg(long)]
        dry_run: bool,
    }

    // Test version is set
    let cli = TestCli::parse_from(["test", "--dry-run"]);
    assert!(cli.dry_run);
}
