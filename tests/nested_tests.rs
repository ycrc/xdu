//! End-to-end tests for nested partitions: run the `xdu` binary with split settings and
//! check the resulting index layout and contents.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use duckdb::Connection;
use tempfile::TempDir;

use xdu::{all_parquet_glob, glob_match, list_partitions, resolve_split_points, sql_quote, Manifest, SplitSpec};

/// Files of the test tree (relative paths), with one heavy branch under projects/big.
const FILES: &[&str] = &[
    "top.txt",
    "alice/a.txt",
    "alice/sub/a2.txt",
    "projects/notes.txt",
    "projects/small/s.txt",
    "projects/big/b.txt",
    "projects/big/x/1.txt",
    "projects/big/x/deeper/2.txt",
    "projects/big/y/3.txt",
    "projects/big/z/4.txt",
];

fn make_tree() -> TempDir {
    let tmp = TempDir::new().unwrap();
    for rel in FILES {
        let path = tmp.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, rel.as_bytes()).unwrap();
    }
    tmp
}

fn xdu(tree: &Path, index: &Path, extra: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_xdu"))
        .arg(tree)
        .arg("-o")
        .arg(index)
        .args(["-j", "2"])
        .args(extra)
        .output()
        .unwrap();
    out
}

fn xdu_ok(tree: &Path, index: &Path, extra: &[&str]) {
    let out = xdu(tree, index, extra);
    assert!(out.status.success(), "xdu failed: {}", String::from_utf8_lossy(&out.stderr));
}

/// (partition key, path relative to the tree) for every row in the index.
fn index_rows(index: &Path, tree: &Path) -> Vec<(String, String)> {
    let conn = Connection::open_in_memory().unwrap();
    let root = tree.canonicalize().unwrap();
    let sql = format!(
        "SELECT {}, substr(path, {}) FROM read_parquet({}, filename=true) ORDER BY 2",
        xdu::partition_key_sql(index),
        root.to_string_lossy().chars().count() + 2,
        sql_quote(&all_parquet_glob(index)),
    );
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// Every file appears exactly once.
fn assert_complete(rows: &[(String, String)]) {
    let mut rels: Vec<&str> = rows.iter().map(|(_, r)| r.as_str()).collect();
    rels.sort();
    let mut expected: Vec<&str> = FILES.to_vec();
    expected.sort();
    assert_eq!(rels, expected);
}

fn owner<'a>(rows: &'a [(String, String)], rel: &str) -> &'a str {
    &rows.iter().find(|(_, r)| r == rel).unwrap().0
}

#[test]
fn test_glob_match() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("a*", "alice"));
    assert!(glob_match("*e", "alice"));
    assert!(glob_match("a?ice", "alice"));
    assert!(glob_match("a*c*", "alice"));
    assert!(!glob_match("b*", "alice"));
    assert!(!glob_match("alic", "alice"));
    assert!(!glob_match("a?", "alice"));
}

#[test]
fn test_resolve_split_points() {
    let tree = make_tree();
    let resolve = |depth, patterns: &[&str]| {
        let spec = SplitSpec { depth, patterns: patterns.iter().map(|s| s.to_string()).collect() };
        resolve_split_points(tree.path(), &spec).unwrap()
    };
    assert_eq!(resolve(1, &[]).0, vec!["alice", "projects"]);
    assert_eq!(resolve(2, &[]).0, vec!["alice", "alice/sub", "projects", "projects/big", "projects/small"]);
    assert_eq!(resolve(0, &["projects/big"]).0, vec!["projects/big"]);
    assert_eq!(
        resolve(1, &["projects/big/*"]).0,
        vec!["alice", "projects", "projects/big/x", "projects/big/y", "projects/big/z"]
    );
    let (points, warnings) = resolve(1, &["nope/*"]);
    assert_eq!(points, vec!["alice", "projects"]);
    assert_eq!(warnings.len(), 1);

    let bad = SplitSpec { depth: 1, patterns: vec!["../etc".to_string()] };
    assert!(resolve_split_points(tree.path(), &bad).is_err());
    let recursive = SplitSpec { depth: 1, patterns: vec!["projects/**".to_string()] };
    let msg = resolve_split_points(tree.path(), &recursive).unwrap_err().to_string();
    assert!(msg.contains("'**' is not supported"), "{}", msg);

    // Literal paths must be real directories; the error names the problem.
    let err = |p: &str| {
        let spec = SplitSpec { depth: 1, patterns: vec![p.to_string()] };
        resolve_split_points(tree.path(), &spec).unwrap_err().to_string()
    };
    assert!(err("projects/missing/x").contains("projects/missing does not exist"));
    assert!(err("top.txt").contains("is not a directory"));
    std::os::unix::fs::symlink(tree.path().join("projects/big"), tree.path().join("link")).unwrap();
    assert!(err("link/x").contains("is a symlink"));
}

#[test]
fn test_default_layout_is_unchanged() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(tree.path(), index.path(), &[]);

    assert_eq!(list_partitions(index.path()).unwrap(), vec!["__root__", "alice", "projects"]);
    let rows = index_rows(index.path(), tree.path());
    assert_complete(&rows);
    assert_eq!(owner(&rows, "projects/big/x/1.txt"), "projects");

    let m = Manifest::load(index.path()).unwrap().unwrap();
    assert_eq!(m.split, SplitSpec::default());
    assert_eq!(m.root, tree.path().canonicalize().unwrap().to_string_lossy());
}

#[test]
fn test_nested_split_points() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(tree.path(), index.path(), &["--split", "projects/big,projects/big/x"]);

    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec!["__root__", "alice", "projects", "projects/big", "projects/big/x"]
    );
    let rows = index_rows(index.path(), tree.path());
    assert_complete(&rows);
    assert_eq!(owner(&rows, "top.txt"), "__root__");
    assert_eq!(owner(&rows, "projects/notes.txt"), "projects");
    assert_eq!(owner(&rows, "projects/small/s.txt"), "projects");
    assert_eq!(owner(&rows, "projects/big/b.txt"), "projects/big");
    assert_eq!(owner(&rows, "projects/big/y/3.txt"), "projects/big");
    assert_eq!(owner(&rows, "projects/big/x/deeper/2.txt"), "projects/big/x");

    // A later run without split flags reuses the saved settings.
    xdu_ok(tree.path(), index.path(), &[]);
    assert_eq!(list_partitions(index.path()).unwrap().len(), 5);
    assert_complete(&index_rows(index.path(), tree.path()));
}

#[test]
fn test_split_depth_zero_and_wildcards() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(tree.path(), index.path(), &["--split-depth", "0", "--split", "projects/big/*"]);

    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec!["__root__", "projects/big/x", "projects/big/y", "projects/big/z"]
    );
    let rows = index_rows(index.path(), tree.path());
    assert_complete(&rows);
    assert_eq!(owner(&rows, "alice/sub/a2.txt"), "__root__");
    assert_eq!(owner(&rows, "projects/big/b.txt"), "__root__");
}

#[test]
fn test_changing_layout_removes_stale_partitions() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(tree.path(), index.path(), &["--split", "projects/big/*"]);
    assert_eq!(list_partitions(index.path()).unwrap().len(), 6);

    // Back to the default layout: nested partitions must go, or files would be counted twice.
    xdu_ok(tree.path(), index.path(), &["--split-depth", "1"]);
    assert_eq!(list_partitions(index.path()).unwrap(), vec!["__root__", "alice", "projects"]);
    assert_complete(&index_rows(index.path(), tree.path()));
    assert!(!index.path().join("projects/big").exists());
}

#[test]
fn test_partial_reindex() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(tree.path(), index.path(), &["--split", "projects/big,projects/big/x"]);

    // Re-index a nested partition and its children.
    fs::write(tree.path().join("projects/big/x/new.txt"), b"new").unwrap();
    fs::write(tree.path().join("projects/big/new.txt"), b"new").unwrap();
    xdu_ok(tree.path(), index.path(), &["-p", "projects/big", "-r"]);
    let rows = index_rows(index.path(), tree.path());
    assert_eq!(owner(&rows, "projects/big/x/new.txt"), "projects/big/x");
    assert_eq!(owner(&rows, "projects/big/new.txt"), "projects/big");
    assert_eq!(rows.len(), FILES.len() + 2);

    // Unknown partitions and layout changes are rejected for partial runs.
    assert!(!xdu(tree.path(), index.path(), &["-p", "projects/big/y"]).status.success());
    assert!(!xdu(tree.path(), index.path(), &["-p", "alice", "--split-depth", "2"]).status.success());
}
