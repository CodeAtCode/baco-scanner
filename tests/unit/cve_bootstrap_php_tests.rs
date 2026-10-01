//! The PHP branch that was missing.
//!
//! `detect_project_stack` checked for Cargo.toml, package.json,
//! requirements.txt and go.mod, then returned `Ok`. A WordPress plugin has none
//! of those, so it got an empty stack — and because the result was `Ok`, nothing
//! downstream could tell "not a PHP project" from "found nothing".
//!
//! The log said `[] languages, [] frameworks, 0 dependencies` on a plugin, and
//! the discovery phase had nothing to work with.

use baco::cve_bootstrap::CveBootstrapper;
use baco::scanner_types::project::DependencyEcosystem;

fn bootstrapper(dir: &std::path::Path) -> CveBootstrapper {
    CveBootstrapper::new(dir.to_string_lossy().to_string())
}

fn write(dir: &std::path::Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(path, body).expect("write");
}

#[test]
fn test_a_wordpress_plugin_is_recognised_with_no_manifest_at_all() {
    // The reported case: a plugin directory with no composer.json.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "captcha-code-auth.php",
        "<?php\nadd_action('init', 'x');\n",
    );
    write(
        dir.path(),
        "includes/class-helper.php",
        "<?php\nclass Helper {}\n",
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        stack.languages.iter().any(|l| l == "PHP"),
        "a .php file must register the language, got {:?}",
        stack.languages
    );
}

#[test]
fn test_wordpress_directory_shape_is_recognised() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), "wp-includes/version.php", "<?php\n");
    write(dir.path(), "wp-content/plugins/x/x.php", "<?php\n");

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        stack.frameworks.iter().any(|f| f == "WordPress"),
        "wp-includes/ must mean WordPress, got {:?}",
        stack.frameworks
    );
}

#[test]
fn test_composer_json_dependencies_are_read() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"php": ">=8.0", "guzzlehttp/guzzle": "^7.5"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(stack.languages.iter().any(|l| l == "PHP"));
    let guzzle = stack
        .dependencies
        .iter()
        .find(|d| d.name == "guzzlehttp/guzzle")
        .expect("guzzle must be a dependency");
    assert_eq!(guzzle.version, "^7.5");
    assert_eq!(guzzle.ecosystem, DependencyEcosystem::Packagist);
}

#[test]
fn test_the_php_runtime_is_not_reported_as_a_dependency() {
    // "php": ">=8.0" is a platform constraint, not a package with advisories.
    // Treating it as one produces a CVE lookup for the language runtime.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"php": ">=8.0", "monolog/monolog": "^3.0"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        !stack.dependencies.iter().any(|d| d.name == "php"),
        "the runtime must not be a dependency, got {:?}",
        stack.dependencies
    );
}

#[test]
fn test_require_dev_is_excluded() {
    // Dev tooling does not ship, so a vulnerability in it is not reachable by
    // an attacker.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"monolog/monolog": "^3.0"}, "require-dev": {"phpunit/phpunit": "^10"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        !stack
            .dependencies
            .iter()
            .any(|d| d.name == "phpunit/phpunit"),
        "dev dependencies must not be reported, got {:?}",
        stack.dependencies
    );
    assert!(
        stack
            .dependencies
            .iter()
            .any(|d| d.name == "monolog/monolog")
    );
}

#[test]
fn test_a_laravel_or_symfony_dependency_names_the_framework() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"laravel/framework": "^11.0", "symfony/console": "^7.0"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        stack.frameworks.iter().any(|f| f == "Laravel"),
        "{:?}",
        stack.frameworks
    );
    assert!(
        stack.frameworks.iter().any(|f| f == "Symfony"),
        "{:?}",
        stack.frameworks
    );
}

#[test]
fn test_a_framework_is_not_listed_twice() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"laravel/framework": "^11.0", "laravel/sanctum": "^4.0"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert_eq!(
        stack.frameworks.iter().filter(|f| *f == "Laravel").count(),
        1,
        "got {:?}",
        stack.frameworks
    );
}

#[test]
fn test_wordpress_from_the_directory_is_not_duplicated_by_a_manifest() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), "wp-content/plugins/x/x.php", "<?php\n");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"monolog/monolog": "^3.0"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert_eq!(
        stack
            .frameworks
            .iter()
            .filter(|f| *f == "WordPress")
            .count(),
        1
    );
}

#[test]
fn test_a_malformed_composer_json_does_not_fail_detection() {
    // A broken manifest must not take the whole stack down, and must not
    // produce a PHP dependency list built from a partial parse.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), "composer.json", "{ this is not json");

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must still succeed");
    assert!(stack.dependencies.is_empty(), "{:?}", stack.dependencies);
}

#[test]
fn test_an_empty_directory_still_reports_nothing() {
    // Nothing to detect is not the same as PHP. The function must not claim a
    // language it has no evidence for.
    let dir = tempfile::tempdir().expect("tmpdir");
    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");
    assert!(stack.languages.is_empty(), "{:?}", stack.languages);
    assert!(stack.frameworks.is_empty(), "{:?}", stack.frameworks);
    assert!(stack.dependencies.is_empty(), "{:?}", stack.dependencies);
}

#[test]
fn test_rust_is_still_detected_and_not_double_reported() {
    // The existing branches must keep working, and PHP must not disturb them.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), "Cargo.toml", "[package]\nname = \"x\"\n");
    write(
        dir.path(),
        "composer.json",
        r#"{"require": {"monolog/monolog": "^3.0"}}"#,
    );

    let stack = bootstrapper(dir.path())
        .detect_project_stack()
        .expect("detection must succeed");

    assert!(
        stack.languages.iter().any(|l| l == "Rust"),
        "{:?}",
        stack.languages
    );
    assert!(
        stack.languages.iter().any(|l| l == "PHP"),
        "{:?}",
        stack.languages
    );
    assert_eq!(
        stack.languages.iter().filter(|l| *l == "PHP").count(),
        1,
        "PHP must be listed once, got {:?}",
        stack.languages
    );
}
