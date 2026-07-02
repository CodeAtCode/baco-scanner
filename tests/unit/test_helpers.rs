//! Shared test helpers for TempDir management.
//!
//! This module provides a shared TempDir using LazyLock to reduce test startup time
//! by avoiding repeated TempDir::new() calls across tests that don't need isolation.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::test_helpers::shared_temp_dir;
//!
//! #[test]
//! fn test_something() {
//!     let temp_dir = shared_temp_dir();
//!     // Use temp_dir.path() for test files
//! }
//! ```
//!
//! For tests that need complete isolation, use `tempfile::tempdir()` directly.

use std::sync::LazyLock;
use tempfile::TempDir;

/// Shared static TempDir for tests that can reuse a single directory.
///
/// This is initialized lazily on first access and lives for the duration of the test run.
/// Use this for tests that:
/// - Don't modify shared state in ways that would affect other tests
/// - Create files in unique subdirectories
/// - Are read-only or use isolated paths
///
/// # Warning
///
/// Do NOT use this for tests that:
/// - Write to the same filenames (will cause collisions)
/// - Need complete filesystem isolation
/// - Test cleanup/deletion behavior
static SHARED_TEMP_DIR: LazyLock<TempDir> = LazyLock::new(|| {
    tempfile::tempdir().expect("Failed to create shared temp directory")
});

/// Get a reference to the shared temp directory.
///
/// This uses `LazyLock` to ensure the directory is created only once
/// on first access, reducing test startup overhead.
///
/// # Example
///
/// ```rust,ignore
/// #[test]
/// fn test_example() {
///     let temp_dir = shared_temp_dir();
///     let path = temp_dir.path().join("my_unique_test_file.txt");
///     std::fs::write(&path, "content").unwrap();
/// }
/// ```
pub fn shared_temp_dir() -> &'static TempDir {
    &SHARED_TEMP_DIR
}

/// Create a unique subdirectory within the shared temp directory.
///
/// This is useful for tests that need isolation but can share the parent temp directory.
/// Each call creates a new subdirectory with the given name.
///
/// # Arguments
///
/// * `subdir_name` - A unique name for the subdirectory (should include test name or ID)
///
/// # Returns
///
/// A `TempDir` pointing to the new subdirectory
///
/// # Example
///
/// ```rust,ignore
/// #[test]
/// fn test_foo() {
///     let temp_dir = create_subdir_in_shared("test_foo");
///     // temp_dir is isolated from other tests
/// }
/// ```
pub fn create_subdir_in_shared(_subdir_name: &str) -> TempDir {
    let shared = shared_temp_dir();
    tempfile::tempdir_in(shared.path())
        .expect("Failed to create subdirectory in shared temp dir")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_temp_dir_exists() {
        let temp_dir = shared_temp_dir();
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[test]
    fn test_shared_temp_dir_persistent() {
        let path1 = shared_temp_dir().path().to_path_buf();
        let path2 = shared_temp_dir().path().to_path_buf();
        assert_eq!(path1, path2);
    }

    #[test]
    fn test_create_subdir_in_shared() {
        let subdir = create_subdir_in_shared("test_subdir_123");
        assert!(subdir.path().exists());
        assert!(subdir.path().is_dir());
    }

    #[test]
    fn test_multiple_subdirs() {
        let subdir1 = create_subdir_in_shared("subdir_a");
        let subdir2 = create_subdir_in_shared("subdir_b");
        
        assert!(subdir1.path().exists());
        assert!(subdir2.path().exists());
        assert_ne!(subdir1.path(), subdir2.path());
    }
}
