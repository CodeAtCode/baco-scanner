/// Determinism tests: verify scanner produces identical results on repeated runs.
use std::collections::HashSet;

use baco::indexer::FileIndex;


use std::fs;
use tempfile::TempDir;

fn file_paths_set(index: &FileIndex) -> HashSet<String> {
    index
        .files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect()
}

fn index_project(path: &std::path::Path) -> Result<FileIndex, std::io::Error> {
    FileIndex::index_project(
        path.to_str().unwrap(),
        &["rust".to_string(), "python".to_string()],
        512 * 1024,
        &[],
    )
}



/// Indexing is purely filesystem-based and must be 100% deterministic.
#[tokio::test]
async fn test_indexing_determinism_same_fixture() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("main.rs"), "fn main() {}").unwrap();
    fs::write(temp_dir.path().join("lib.rs"), "pub fn lib() {}").unwrap();
    fs::write(temp_dir.path().join("test.py"), "print(1)").unwrap();

    let paths1 = file_paths_set(&index_project(temp_dir.path()).unwrap());
    let paths2 = file_paths_set(&index_project(temp_dir.path()).unwrap());

    assert_eq!(
        paths1, paths2,
        "FileIndex results must be identical across two runs"
    );
    assert!(paths1.len() >= 3, "At least 3 files should be indexed");
}

/// Large file set: determinism under scale.
#[tokio::test]
async fn test_indexing_determinism_many_files() {
    let temp_dir = TempDir::new().unwrap();

    for i in 0..20 {
        fs::write(
            temp_dir.path().join(format!("mod{i}.rs")),
            format!("pub fn func_{}() {{}}", i),
        )
        .unwrap();
    }

    let paths1 = file_paths_set(&index_project(temp_dir.path()).unwrap());
    let paths2 = file_paths_set(&index_project(temp_dir.path()).unwrap());

    assert_eq!(
        paths1, paths2,
        "Large project indexing must be deterministic"
    );
    assert!(paths1.len() >= 20, "All 20 files should be indexed");
}





/// Two different projects should each produce deterministic file sets.
#[tokio::test]
async fn test_multi_project_indexing_determinism() {
    let project_a = TempDir::new().unwrap();
    let project_b = TempDir::new().unwrap();

    fs::write(project_a.path().join("main.rs"), "fn main() {}").unwrap();
    fs::write(project_a.path().join("lib.rs"), "pub fn lib() {}").unwrap();

    fs::write(project_b.path().join("app.py"), "print('hi')").unwrap();
    fs::write(project_b.path().join("index.js"), "console.log(1)").unwrap();

    let paths_a1 = file_paths_set(&index_project(project_a.path()).unwrap());
    let paths_a2 = file_paths_set(&index_project(project_a.path()).unwrap());
    assert_eq!(
        paths_a1, paths_a2,
        "Project A indexing must be deterministic"
    );

    let paths_b1 = file_paths_set(&index_project(project_b.path()).unwrap());
    let paths_b2 = file_paths_set(&index_project(project_b.path()).unwrap());
    assert_eq!(
        paths_b1, paths_b2,
        "Project B indexing must be deterministic"
    );

    assert_ne!(
        paths_a1, paths_b1,
        "Different projects yield different file sets"
    );
}




