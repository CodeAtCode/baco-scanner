//! `preset = "name"` in the config file.
//!
//! Presets were reachable only through `--preset`, so a workflow that depended
//! on one had to remember the flag. Naming it in the config makes the
//! dependency part of the config, which is where the rest of the behaviour lives.

use baco::config::ScannerConfig;
use tempfile::TempDir;

fn write_config(body: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("baco.toml");
    std::fs::write(&path, body).expect("write config");
    let path_str = path.to_string_lossy().to_string();
    (dir, path_str)
}

#[test]
fn test_preset_key_applies_the_preset() {
    // django ships python primitives (csrf_protect, CsrfViewMiddleware), which
    // is the setting a user would otherwise have to remember the flag for.
    let (_dir, path) = write_config(
        r#"
preset = "django"

[project]
name = "x"
path = "/tmp"
"#,
    );
    let config = ScannerConfig::from_file_with_preset(&path, None)
        .expect("a preset named in the config must load");

    let python = config
        .knowledge
        .required_security_primitives
        .get("python")
        .expect("the django preset's python primitives must be present");
    assert!(
        python.iter().any(|p| p == "csrf_protect"),
        "the preset's actual primitive list must arrive, got {python:?}"
    );
}

#[test]
fn test_wordpress_preset_key_arrives_with_php_primitives() {
    // The case that started this: a config whose preset carries the WordPress
    // primitives no longer depends on remembering --preset.
    let (_dir, path) = write_config(
        r#"
preset = "wordpress-plugin"

[project]
name = "x"
path = "/tmp"
"#,
    );
    let config = ScannerConfig::from_file_with_preset(&path, None)
        .expect("a preset named in the config must load");
    let php = config
        .knowledge
        .required_security_primitives
        .get("php")
        .expect("the wordpress-plugin preset's php primitives must be present");
    assert!(
        php.iter().any(|p| p == "check_admin_referer"),
        "got {php:?}"
    );
    assert!(
        config.knowledge.hook_registry.contains_key("php"),
        "the hook registry must arrive too, since the primitive check depends on it"
    );
}

#[test]
fn test_preset_key_does_not_reach_deserialisation() {
    // ScannerConfig denies unknown keys, so if `preset` leaked into the merge
    // the whole file would be rejected. That this parses at all is the check.
    let (_dir, path) = write_config(
        r#"
preset = "laravel"

[project]
name = "x"
path = "/tmp"
"#,
    );
    let config = ScannerConfig::from_file_with_preset(&path, None)
        .expect("preset is a directive, not a field, and must be stripped");
    // The file parsed at all is the real assertion: ScannerConfig denies
    // unknown keys, so a `preset` that reached deserialisation would fail here.
    assert_eq!(config.project.path, "/tmp");
    assert_eq!(config.project.name, "x");
}

#[test]
fn test_unknown_preset_name_is_reported_by_name() {
    let (_dir, path) = write_config(
        r#"
preset = "no-such-preset"

[project]
name = "x"
path = "/tmp"
"#,
    );
    let err = ScannerConfig::from_file_with_preset(&path, None)
        .expect_err("an unknown preset must not be silently ignored");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("no-such-preset"),
        "the error must name the preset that failed, got: {msg}"
    );
}

#[test]
fn test_explicit_preset_argument_wins_over_the_config_key() {
    // Passing --preset is a deliberate override, so it must take precedence.
    let (_dir, path) = write_config(
        r#"
preset = "django"

[project]
name = "x"
path = "/tmp"
"#,
    );
    let explicit = baco::preset::load_preset("litellm").expect("litellm loads");
    let config = ScannerConfig::from_file_with_preset(&path, Some(explicit))
        .expect("explicit overlay applies");

    // litellm is a python profile; django would have brought php primitives.
    assert!(
        !config
            .knowledge
            .required_security_primitives
            .contains_key("php"),
        "the explicit preset must win, got {:?}",
        config
            .knowledge
            .required_security_primitives
            .keys()
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_no_preset_anywhere_still_loads() {
    let (_dir, path) = write_config(
        r#"
[project]
name = "x"
path = "/tmp"
"#,
    );
    let config = ScannerConfig::from_file_with_preset(&path, None)
        .expect("a config with no preset loads as before");
    assert!(
        config.knowledge.required_security_primitives.is_empty(),
        "no preset means no preset settings"
    );
}
