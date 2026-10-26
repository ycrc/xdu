//! Tests for comparing two indices (root discovery and per-file diff status).

use std::collections::HashMap;
use std::path::Path;

use duckdb::Connection;
use tempfile::TempDir;

use xdu::{diff_partition_sql, diff_units, discover_index_root, list_partitions, DiffSide, DiffUnit};

/// (relative path, size, atime, mtime, ctime, uid, gid, mode)
type Row = (&'static str, i64, i64, i64, i64, i32, i32, i32);

/// Write a Hive-partitioned index whose paths are `<root>/<rel>`.
fn write_index(conn: &Connection, dir: &Path, root: &str, rows: &[Row]) {
    write_nested_index(conn, dir, root, rows, &[]);
}

/// Like [`write_index`], with extra split points: each file goes to the deepest split
/// containing it, else to its top-level directory.
fn write_nested_index(conn: &Connection, dir: &Path, root: &str, rows: &[Row], splits: &[&str]) {
    let mut by_partition: HashMap<String, Vec<&Row>> = HashMap::new();
    for row in rows {
        let deepest = splits.iter()
            .filter(|s| row.0.starts_with(&format!("{}/", s)))
            .max_by_key(|s| s.len());
        let partition = match (deepest, row.0.split_once('/')) {
            (Some(s), _) => s.to_string(),
            (None, Some((p, _))) => p.to_string(),
            (None, None) => "__root__".to_string(),
        };
        by_partition.entry(partition).or_default().push(row);
    }
    for (partition, rows) in by_partition {
        let pdir = dir.join(&partition);
        std::fs::create_dir_all(&pdir).unwrap();
        let values: Vec<String> = rows.iter().map(|r| {
            format!("('{}/{}', {}::BIGINT, {}::BIGINT, {}::BIGINT, {}::BIGINT, {}::INTEGER, {}::INTEGER, {}::INTEGER)",
                root, r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7)
        }).collect();
        let sql = format!(
            "COPY (SELECT * FROM (VALUES {}) t(path, size, atime, mtime, ctime, uid, gid, mode)) \
             TO '{}' (FORMAT PARQUET)",
            values.join(", "),
            pdir.join("000000.parquet").display()
        );
        conn.execute_batch(&sql).unwrap();
    }
}

fn open(conn: &Connection, dir: &Path) -> (DiffSide, Vec<String>) {
    let partitions = list_partitions(dir).unwrap();
    let root = discover_index_root(conn, dir, &partitions).unwrap();
    (DiffSide { index: dir.to_path_buf(), root }, partitions)
}

#[test]
fn test_discover_root_multiple_partitions() {
    let conn = Connection::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    write_index(&conn, tmp.path(), "/snap/@GMT-1/data", &[
        ("repos/a.txt", 1, 0, 0, 0, 0, 0, 0),
        ("repos2/b.txt", 1, 0, 0, 0, 0, 0, 0),
    ]);
    let (side, partitions) = open(&conn, tmp.path());
    assert_eq!(partitions, vec!["repos", "repos2"]);
    assert_eq!(side.root, "/snap/@GMT-1/data");
}

#[test]
fn test_discover_root_single_partition() {
    let conn = Connection::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    write_index(&conn, tmp.path(), "/data", &[
        ("alice/proj/x/1.txt", 1, 0, 0, 0, 0, 0, 0),
        ("alice/proj/x/2.txt", 1, 0, 0, 0, 0, 0, 0),
    ]);
    let (side, _) = open(&conn, tmp.path());
    assert_eq!(side.root, "/data");
}

#[test]
fn test_diff_statuses_across_snapshot_roots() {
    let conn = Connection::open_in_memory().unwrap();
    let old_dir = TempDir::new().unwrap();
    let new_dir = TempDir::new().unwrap();

    write_index(&conn, old_dir.path(), "/snap/@GMT-1/data", &[
        ("alice/same.txt",     10, 100, 100, 100, 1, 1, 0o100644),
        ("alice/grown.txt",    10, 100, 100, 100, 1, 1, 0o100644),
        ("alice/chmod.txt",    10, 100, 100, 100, 1, 1, 0o100644),
        ("alice/read.txt",     10, 100, 100, 100, 1, 1, 0o100644),
        ("alice/deleted.txt",  50, 100, 100, 100, 1, 1, 0o100644),
        ("gone/old.txt",        7, 100, 100, 100, 2, 2, 0o100644),
    ]);
    write_index(&conn, new_dir.path(), "/snap/@GMT-2/data", &[
        ("alice/same.txt",     10, 100, 100, 100, 1, 1, 0o100644),
        ("alice/grown.txt",    30, 100, 200, 200, 1, 1, 0o100644),
        ("alice/chmod.txt",    10, 100, 100, 200, 1, 1, 0o100600),
        ("alice/read.txt",     10, 200, 100, 100, 1, 1, 0o100644),
        ("alice/new.txt",       5, 200, 200, 200, 1, 1, 0o100644),
        ("bob/fresh.txt",       3, 200, 200, 200, 3, 3, 0o100644),
    ]);

    let (old, old_parts) = open(&conn, old_dir.path());
    let (new, new_parts) = open(&conn, new_dir.path());

    let mut results: HashMap<String, (String, i64)> = HashMap::new();
    for p in ["alice", "bob", "gone"] {
        let unit = DiffUnit {
            name: p.to_string(),
            subtree: false,
            in_old: old_parts.iter().any(|x| x == p),
            in_new: new_parts.iter().any(|x| x == p),
        };
        let sql = format!("SELECT rel, status, delta FROM ({})", diff_partition_sql(&old, &new, &unit));
        let mut stmt = conn.prepare(&sql).unwrap();
        let mut rows = stmt.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            let rel: String = r.get(0).unwrap();
            results.insert(rel, (r.get(1).unwrap(), r.get(2).unwrap()));
        }
    }

    let expect = |rel: &str, status: &str, delta: i64| {
        assert_eq!(results.get(rel), Some(&(status.to_string(), delta)), "{}", rel);
    };
    expect("alice/same.txt", "unchanged", 0);
    expect("alice/grown.txt", "modified", 20);
    expect("alice/chmod.txt", "meta", 0);
    expect("alice/read.txt", "accessed", 0);
    expect("alice/deleted.txt", "removed", -50);
    expect("alice/new.txt", "added", 5);
    expect("bob/fresh.txt", "added", 3);
    expect("gone/old.txt", "removed", -7);
    assert_eq!(results.len(), 8);
}

/// Rows of a tree with one heavy branch, used for nested-layout tests.
const TREE: &[Row] = &[
    ("top.txt",                          1, 100, 100, 100, 1, 1, 0o100644),
    ("alice/a.txt",                      2, 100, 100, 100, 1, 1, 0o100644),
    ("projects/notes.txt",               3, 100, 100, 100, 1, 1, 0o100644),
    ("projects/small/s.txt",             4, 100, 100, 100, 1, 1, 0o100644),
    ("projects/big/b.txt",               5, 100, 100, 100, 1, 1, 0o100644),
    ("projects/big/x/1.txt",             6, 100, 100, 100, 1, 1, 0o100644),
    ("projects/big/y/deep/2.txt",        7, 100, 100, 100, 1, 1, 0o100644),
];

#[test]
fn test_list_partitions_nested() {
    let conn = Connection::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    write_nested_index(&conn, tmp.path(), "/data", TREE, &["projects/big", "projects/big/x", "projects/big/y"]);
    assert_eq!(list_partitions(tmp.path()).unwrap(), vec![
        "__root__", "alice", "projects", "projects/big", "projects/big/x", "projects/big/y",
    ]);
    // Root discovery without a manifest still finds the crawl root.
    let (side, _) = open(&conn, tmp.path());
    assert_eq!(side.root, "/data");
}

#[test]
fn test_globs_cover_nested_partitions() {
    let conn = Connection::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    write_nested_index(&conn, tmp.path(), "/data", TREE, &["projects/big", "projects/big/x"]);
    let count = |glob: String| -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM read_parquet({})", xdu::sql_quote(&glob)), [], |r| r.get(0)).unwrap()
    };
    assert_eq!(count(xdu::all_parquet_glob(tmp.path())), 7);
    assert_eq!(count(xdu::subtree_glob(tmp.path(), "projects")), 5);
    assert_eq!(count(xdu::subtree_glob(tmp.path(), "projects/big")), 3);
    assert_eq!(count(xdu::partition_glob(tmp.path(), "projects/big")), 2);
    assert_eq!(count(xdu::partition_glob(tmp.path(), "projects")), 2);

    // Partition keys and top-level keys derived from file names.
    let sql = format!(
        "SELECT {} AS k, {} AS t, count(*) FROM read_parquet({}, filename=true) GROUP BY k, t ORDER BY k",
        xdu::partition_key_sql(tmp.path()),
        xdu::top_level_key_sql(tmp.path()),
        xdu::sql_quote(&xdu::all_parquet_glob(tmp.path())),
    );
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows, vec![
        ("__root__".into(), "__root__".into(), 1),
        ("alice".into(), "alice".into(), 1),
        ("projects".into(), "projects".into(), 2),
        ("projects/big".into(), "projects".into(), 2),
        ("projects/big/x".into(), "projects".into(), 1),
    ]);
}

/// Diff every unit and collect rel -> status.
fn diff_all(conn: &Connection, old: &DiffSide, new: &DiffSide, units: &[DiffUnit]) -> HashMap<String, String> {
    let mut results = HashMap::new();
    for unit in units {
        let sql = format!("SELECT rel, status FROM ({})", diff_partition_sql(old, new, unit));
        let mut stmt = conn.prepare(&sql).unwrap();
        let mut rows = stmt.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            let rel: String = r.get(0).unwrap();
            assert!(results.insert(rel.clone(), r.get(1).unwrap()).is_none(), "{} seen twice", rel);
        }
    }
    results
}

#[test]
fn test_diff_flat_against_nested_layout() {
    let conn = Connection::open_in_memory().unwrap();
    let flat = TempDir::new().unwrap();
    let nested = TempDir::new().unwrap();
    write_index(&conn, flat.path(), "/snap/1/data", TREE);
    write_nested_index(&conn, nested.path(), "/snap/2/data", TREE, &["projects/big", "projects/big/y"]);
    let (old, old_parts) = open(&conn, flat.path());
    let (new, new_parts) = open(&conn, nested.path());

    // Different layouts: compare whole top-level subtrees.
    let units = diff_units(&old_parts, &new_parts, false);
    let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, vec!["__root__", "alice", "projects"]);
    let results = diff_all(&conn, &old, &new, &units);
    assert_eq!(results.len(), TREE.len());
    assert!(results.values().all(|s| s == "unchanged"), "{:?}", results);
}

#[test]
fn test_diff_same_nested_layout_per_partition() {
    let conn = Connection::open_in_memory().unwrap();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let splits = ["projects/big", "projects/big/x"];
    write_nested_index(&conn, a.path(), "/snap/1/data", TREE, &splits);
    let mut changed: Vec<Row> = TREE.to_vec();
    changed[5].1 = 60; // projects/big/x/1.txt grows
    changed.push(("projects/big/new.txt", 8, 100, 100, 100, 1, 1, 0o100644));
    write_nested_index(&conn, b.path(), "/snap/2/data", &changed, &splits);
    let (old, old_parts) = open(&conn, a.path());
    let (new, new_parts) = open(&conn, b.path());

    let units = diff_units(&old_parts, &new_parts, true);
    assert!(units.iter().all(|u| !u.subtree));
    assert_eq!(units.len(), old_parts.len());
    let results = diff_all(&conn, &old, &new, &units);
    assert_eq!(results.len(), TREE.len() + 1);
    assert_eq!(results["projects/big/x/1.txt"], "modified");
    assert_eq!(results["projects/big/new.txt"], "added");
    assert_eq!(results["alice/a.txt"], "unchanged");
}
