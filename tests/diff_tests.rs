//! Tests for comparing two indices (root discovery and per-file diff status).

use std::collections::HashMap;
use std::path::Path;

use duckdb::Connection;
use tempfile::TempDir;

use xdu::{diff_partition_sql, discover_index_root, list_partitions, DiffSide};

/// (relative path, size, atime, mtime, ctime, uid, gid, mode)
type Row = (&'static str, i64, i64, i64, i64, i32, i32, i32);

/// Write a Hive-partitioned index whose paths are `<root>/<rel>`.
fn write_index(conn: &Connection, dir: &Path, root: &str, rows: &[Row]) {
    let mut by_partition: HashMap<String, Vec<&Row>> = HashMap::new();
    for row in rows {
        let partition = match row.0.split_once('/') {
            Some((p, _)) => p.to_string(),
            None => "__root__".to_string(),
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
        let in_old = old_parts.iter().any(|x| x == p);
        let in_new = new_parts.iter().any(|x| x == p);
        let sql = format!("SELECT rel, status, delta FROM ({})",
            diff_partition_sql(&old, &new, p, in_old, in_new));
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
