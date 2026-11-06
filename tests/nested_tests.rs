//! End-to-end tests for nested partitions: run the `xdu` binary with split settings and
//! check the resulting index layout and contents.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

use common::{binary_path, find_count, run_binary_with_home};
use xdu::layout::{
    Manifest, SplitSpec, list_partitions, partition_key_sql, resolve_split_points, split_keys,
};
use xdu::{COMPLETION_MARKER, IndexLocator, index_glob, sql_quote};

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
    Command::new(binary_path("xdu"))
        .arg(tree)
        .arg("-o")
        .arg(index)
        .args(["-j", "2"])
        .args(extra)
        .output()
        .unwrap()
}

fn xdu_ok(tree: &Path, index: &Path, extra: &[&str]) {
    let out = xdu(tree, index, extra);
    assert!(
        out.status.success(),
        "xdu failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// (partition key, path relative to the tree) for every row in the index.
fn index_rows(index: &Path, tree: &Path) -> Vec<(String, String)> {
    let conn = xdu::engine::open_connection().unwrap();
    let root = tree.canonicalize().unwrap();
    let sql = format!(
        "SELECT {}, substr(path, {}) FROM read_parquet({}, filename=true) ORDER BY 2",
        partition_key_sql(&IndexLocator::Local(index.to_path_buf())),
        root.to_string_lossy().chars().count() + 2,
        sql_quote(&index_glob(index, None)),
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
fn test_resolve_split_points() {
    let tree = make_tree();
    let resolve = |depth, patterns: &[&str]| {
        let spec = SplitSpec {
            depth,
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        };
        let (points, warnings) = resolve_split_points(tree.path(), &spec).unwrap();
        (split_keys(&points), warnings)
    };
    assert_eq!(resolve(1, &[]).0, vec!["alice", "projects"]);
    assert_eq!(
        resolve(2, &[]).0,
        vec![
            "alice",
            "alice/sub",
            "projects",
            "projects/big",
            "projects/small"
        ]
    );
    assert_eq!(resolve(0, &["projects/big"]).0, vec!["projects/big"]);
    assert_eq!(
        resolve(1, &["projects/big/*"]).0,
        vec![
            "alice",
            "projects",
            "projects/big/x",
            "projects/big/y",
            "projects/big/z"
        ]
    );
    let (points, warnings) = resolve(1, &["nope/*"]);
    assert_eq!(points, vec!["alice", "projects"]);
    assert_eq!(warnings.len(), 1);

    let bad = SplitSpec {
        depth: 1,
        patterns: vec!["../etc".to_string()],
    };
    assert!(resolve_split_points(tree.path(), &bad).is_err());
    let recursive = SplitSpec {
        depth: 1,
        patterns: vec!["projects/**".to_string()],
    };
    let msg = resolve_split_points(tree.path(), &recursive)
        .unwrap_err()
        .to_string();
    assert!(msg.contains("'**' is not supported"), "{}", msg);

    // Literal paths must be real directories; the error names the problem.
    let err = |p: &str| {
        let spec = SplitSpec {
            depth: 1,
            patterns: vec![p.to_string()],
        };
        resolve_split_points(tree.path(), &spec)
            .unwrap_err()
            .to_string()
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

    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec!["__root__", "alice", "projects"]
    );
    let rows = index_rows(index.path(), tree.path());
    assert_complete(&rows);
    assert_eq!(owner(&rows, "projects/big/x/1.txt"), "projects");

    let m = Manifest::load(index.path()).unwrap().unwrap();
    assert_eq!(m.split, SplitSpec::default());

    // A flat index keeps the format version every reader of the flat layout accepts.
    let marker = fs::read_to_string(index.path().join(COMPLETION_MARKER)).unwrap();
    assert!(marker.contains("format=2\n"), "{marker}");
    assert_eq!(
        m.root,
        tree.path().canonicalize().unwrap().to_string_lossy()
    );
}

#[test]
fn test_nested_split_points() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(
        tree.path(),
        index.path(),
        &["--split", "projects/big,projects/big/x"],
    );

    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec![
            "__root__",
            "alice",
            "projects",
            "projects/big",
            "projects/big/x"
        ]
    );
    let rows = index_rows(index.path(), tree.path());
    assert_complete(&rows);
    assert_eq!(owner(&rows, "top.txt"), "__root__");
    assert_eq!(owner(&rows, "projects/notes.txt"), "projects");
    assert_eq!(owner(&rows, "projects/small/s.txt"), "projects");
    assert_eq!(owner(&rows, "projects/big/b.txt"), "projects/big");
    assert_eq!(owner(&rows, "projects/big/y/3.txt"), "projects/big");
    assert_eq!(
        owner(&rows, "projects/big/x/deeper/2.txt"),
        "projects/big/x"
    );

    // The marker says nested, so a reader that globs `*/*.parquet` refuses the index.
    let marker = fs::read_to_string(index.path().join(COMPLETION_MARKER)).unwrap();
    assert!(marker.contains("format=3\n"), "{marker}");

    // The readers include nested partitions below a scoped one.
    assert_eq!(find_count(index.path(), &[]), FILES.len() as i64);
    assert_eq!(find_count(index.path(), &["-u", "projects"]), 7);
    assert_eq!(find_count(index.path(), &["-u", "projects/big"]), 5);
    assert_eq!(find_count(index.path(), &["-u", "projects/big/x"]), 2);
    let home = TempDir::new().unwrap();
    let (out, err, ok) = run_binary_with_home(
        "xdu-du",
        home.path(),
        &["-i", index.path().to_str().unwrap()],
    );
    assert!(ok, "xdu-du failed: {err}");
    let tops: Vec<&str> = out.lines().map(|l| l.split('\t').nth(1).unwrap()).collect();
    assert_eq!(tops, vec!["__root__", "alice", "projects"], "{out}");

    // A later run without split flags reuses the saved settings.
    xdu_ok(tree.path(), index.path(), &[]);
    assert_eq!(list_partitions(index.path()).unwrap().len(), 5);
    assert_complete(&index_rows(index.path(), tree.path()));
}

#[test]
fn test_split_depth_zero_and_wildcards() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(
        tree.path(),
        index.path(),
        &["--split-depth", "0", "--split", "projects/big/*"],
    );

    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec![
            "__root__",
            "projects/big/x",
            "projects/big/y",
            "projects/big/z"
        ]
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
    assert_eq!(
        list_partitions(index.path()).unwrap(),
        vec!["__root__", "alice", "projects"]
    );
    assert_complete(&index_rows(index.path(), tree.path()));
    assert!(!index.path().join("projects/big").exists());
}

#[test]
fn test_partial_reindex() {
    let tree = make_tree();
    let index = TempDir::new().unwrap();
    xdu_ok(
        tree.path(),
        index.path(),
        &["--split", "projects/big,projects/big/x"],
    );

    // Re-index a nested partition and its children.
    fs::write(tree.path().join("projects/big/x/new.txt"), b"new").unwrap();
    fs::write(tree.path().join("projects/big/new.txt"), b"new").unwrap();
    xdu_ok(tree.path(), index.path(), &["-p", "projects/big", "-r"]);
    let rows = index_rows(index.path(), tree.path());
    assert_eq!(owner(&rows, "projects/big/x/new.txt"), "projects/big/x");
    assert_eq!(owner(&rows, "projects/big/new.txt"), "projects/big");
    assert_eq!(rows.len(), FILES.len() + 2);

    // Unknown partitions and layout changes are rejected for partial runs.
    assert!(
        !xdu(tree.path(), index.path(), &["-p", "projects/big/y"])
            .status
            .success()
    );
    assert!(
        !xdu(
            tree.path(),
            index.path(),
            &["-p", "alice", "--split-depth", "2"]
        )
        .status
        .success()
    );
}

#[test]
fn test_diff_binary_across_layouts() {
    let tree = make_tree();
    let flat = TempDir::new().unwrap();
    let nested = TempDir::new().unwrap();
    xdu_ok(tree.path(), flat.path(), &["--apparent-size"]);
    let home = TempDir::new().unwrap();
    let diff = |extra: &[&str]| {
        let mut args: Vec<&str> = extra.to_vec();
        args.push(flat.path().to_str().unwrap());
        args.push(nested.path().to_str().unwrap());
        let output = Command::new(binary_path("xdu-diff"))
            .args(&args)
            .env("HOME", home.path())
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            output.status.code(),
        )
    };

    // The same tree split differently is no change at all.
    xdu_ok(
        tree.path(),
        nested.path(),
        &["--apparent-size", "--split", "projects/big/*"],
    );
    let (out, code) = diff(&[]);
    assert_eq!(code, Some(0), "{out}");

    fs::write(
        tree.path().join("projects/big/x/1.txt"),
        b"grown well past its old size",
    )
    .unwrap();
    fs::write(tree.path().join("alice/added.txt"), b"new").unwrap();
    xdu_ok(tree.path(), nested.path(), &["--apparent-size"]);
    let (out, code) = diff(&["--files", "--csv"]);
    assert_eq!(code, Some(1), "{out}");
    let mut changed: Vec<&str> = out.lines().skip(1).collect();
    changed.sort();
    assert_eq!(changed.len(), 2, "{out}");
    assert!(
        changed[0].starts_with("added,alice/added.txt,0,3,3,"),
        "{out}"
    );
    assert!(
        changed[1].starts_with("modified,projects/big/x/1.txt,"),
        "{out}"
    );
}

#[test]
fn test_view_queries_fold_nested_partitions_and_compare() {
    use xdu::view_query::{self, Compare, Relation};
    use xdu::{QueryFilters, SortMode};

    let tree = make_tree();
    let old = TempDir::new().unwrap();
    let new = TempDir::new().unwrap();
    xdu_ok(tree.path(), old.path(), &["--apparent-size"]);
    fs::write(tree.path().join("projects/big/x/added.txt"), b"12345").unwrap();
    fs::remove_file(tree.path().join("alice/a.txt")).unwrap();
    xdu_ok(
        tree.path(),
        new.path(),
        &["--apparent-size", "--split", "projects/big,projects/big/x"],
    );

    let conn = xdu::engine::open_connection().unwrap();
    let index = IndexLocator::Local(new.path().canonicalize().unwrap());
    let filters = QueryFilters::new();

    // Nested partitions are listed under their top-level directory.
    let parts = view_query::partitions(&conn, &index, &filters, SortMode::Name).unwrap();
    let names: Vec<&str> = parts.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["alice", "projects"]);
    assert_eq!(parts[1].file_count, 8);
    let root = tree.path().canonicalize().unwrap();
    let big = format!("{}/projects/big", root.display());
    let entries = view_query::list_directory(
        &conn,
        &index,
        "projects",
        &big,
        &filters,
        SortMode::SizeDesc,
    )
    .unwrap();
    let x = entries.iter().find(|e| e.name == "x").unwrap();
    assert!(x.is_dir);
    assert_eq!(x.file_count, 3);
    assert!(x.uid >= 0 && x.mode > 0);

    // Compared against the flat index: the added and removed files show up as deltas.
    let new_path = new.path().canonicalize().unwrap();
    let cmp = Compare::open(
        &conn,
        &new_path,
        &root.display().to_string(),
        &list_partitions(&new_path).unwrap(),
        &old.path().canonicalize().unwrap(),
    )
    .unwrap();
    let rel = cmp.partitions_relation();
    let parts = view_query::partitions_in(&conn, &rel, &[], SortMode::DeltaDesc).unwrap();
    assert_eq!(parts[0].name, "projects");
    assert_eq!(parts[0].size_delta(), 5);
    assert_eq!(parts[0].change_marker(), '~');
    let alice = parts.iter().find(|e| e.name == "alice").unwrap();
    assert_eq!(alice.files_delta(), -1);
    let rel: Relation = cmp.relation(&conn, "projects").unwrap().unwrap();
    let entries = view_query::directory_in(
        &conn,
        &rel,
        &format!("{big}/x"),
        &["status = 'added'".to_string()],
        SortMode::Name,
    )
    .unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["added.txt"]);
    assert_eq!(entries[0].change_marker(), '+');
}
