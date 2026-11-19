//! The scan path must root its artifacts under the configured output
//! directory, never against the process CWD.
//!
//! A relative default resolves against the CWD, so a scan configured with an
//! output directory elsewhere still wrote its LLM cache into the repository.
//! `phase_llm_config` is the single chokepoint every phase builds its config
//! through, and it is the only place that holds both the global LLM settings
//! and `output.dir`.

use baco::config::ScannerConfig;

fn config_with_output_dir(dir: &str) -> ScannerConfig {
    let mut config = ScannerConfig::default();
    config.output.dir = dir.to_string();
    config.llm.phases.discovery.base_url = "https://example.invalid/v1".to_string();
    config.llm.phases.discovery.api_key = Some("test-key".to_string());
    config.llm.phases.discovery.model = "test-model".to_string();
    config
}

#[test]
fn test_cache_dir_is_rooted_under_the_configured_output_dir() {
    let config = config_with_output_dir("/tmp/baco-output-isolation");

    let llm = baco::llm::phase_llm_config(&config, "discovery", None)
        .expect("a complete phase config must build");

    let cache_dir = llm
        .cache_dir
        .expect("the scan must resolve a cache directory instead of leaving it unset");

    assert!(
        std::path::Path::new(&cache_dir).is_absolute(),
        "the cache directory must not be CWD-relative, got: {cache_dir}"
    );
    assert_eq!(
        cache_dir, "/tmp/baco-output-isolation/llm-cache",
        "the cache must live under the configured output directory"
    );
}

#[test]
fn test_explicit_llm_cache_dir_wins_over_the_output_dir() {
    let mut config = config_with_output_dir("/tmp/baco-output-isolation");
    config.llm.cache_dir = Some("/custom/cache".to_string());

    let llm = baco::llm::phase_llm_config(&config, "discovery", None)
        .expect("a complete phase config must build");

    assert_eq!(
        llm.cache_dir.as_deref(),
        Some("/custom/cache"),
        "an explicit [llm].cache_dir must be used verbatim"
    );
}

#[test]
fn test_empty_output_dir_leaves_the_cache_dir_unset() {
    let config = config_with_output_dir("   ");

    let llm = baco::llm::phase_llm_config(&config, "discovery", None)
        .expect("a complete phase config must build");

    assert!(
        llm.cache_dir.is_none(),
        "an empty output directory must not manufacture a cache path, got: {:?}",
        llm.cache_dir
    );
}
