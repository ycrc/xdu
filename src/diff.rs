//! Comparing two indexes of the same tree, taken at different times.
//!
//! Files are matched on their path relative to each index's crawl root, so indexes of two
//! snapshot mounts (`.snapshots/@GMT-…/home` against a later one) line up. The comparison
//! runs one unit at a time — a partition, or a whole top-level subtree when the two indexes
//! were split differently — so memory stays bounded by the largest unit rather than the index.
//!
//! Both indexes are local directories. Their paths reach SQL as quoted literals
//! (`sql_quote`), which is the local-index exception `parquet_source` records.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use duckdb::Connection;

use crate::layout::{Manifest, top_level_partitions};
use crate::{ROOT_PARTITION, index_glob, sql_quote};

/// Per-file change classification, from most to least significant. A file takes the first
/// status that applies.
pub const DIFF_STATUSES: &[&str] = &[
    "added",    // only in the new index
    "removed",  // only in the old index
    "modified", // size or mtime changed
    "meta",     // only ctime, uid, gid or mode changed
    "accessed", // only atime changed
    "unchanged",
];

/// The glob of one partition's own chunks, without the partitions nested below it.
fn partition_only_glob(index: &Path, key: &str) -> String {
    format!("{}/{}/*.parquet", index.display(), key)
}

/// The crawl root of a local index (the directory passed to `xdu`), without a trailing
/// slash.
///
/// The manifest records it. An index without one has its root recovered from its paths: a
/// file of partition `p` lies at `<root>/p/...` and a `__root__` file at `<root>/file`, so
/// the root is the longest common directory of all paths — trimmed back above the partition
/// when the index holds a single top-level partition, where that common directory lies
/// inside it.
pub fn discover_index_root(
    conn: &Connection,
    index: &Path,
    partitions: &[String],
) -> Result<String> {
    if let Some(m) = Manifest::load(index)? {
        return Ok(m.root);
    }
    let sql = format!(
        "SELECT min(path), max(path) FROM read_parquet({}, hive_partitioning = false)",
        sql_quote(&index_glob(index, None))
    );
    let (lo, hi): (Option<String>, Option<String>) =
        conn.query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let (lo, hi) = match (lo, hi) {
        (Some(lo), Some(hi)) => (lo, hi),
        _ => anyhow::bail!("Index is empty: {}", index.display()),
    };

    let common: String = lo
        .chars()
        .zip(hi.chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    // Truncate to a whole directory: "/data/alice" and "/data/alfred" share "/data".
    let mut root = match common.rfind('/') {
        Some(pos) => common[..pos].to_string(),
        None => String::new(),
    };

    let tops = top_level_partitions(partitions);
    let named: Vec<&String> = tops.iter().filter(|p| *p != ROOT_PARTITION).collect();
    let has_root_files = tops.iter().any(|p| p == ROOT_PARTITION);
    if named.len() == 1 && !has_root_files {
        let marker = format!("/{}", named[0]);
        let probe = format!("{}/", root);
        if let Some(pos) = probe.rfind(&format!("{}/", marker)) {
            root = probe[..pos].to_string();
        }
    }
    Ok(root)
}

/// One side of a comparison: an index directory and its crawl root.
#[derive(Clone, Debug)]
pub struct DiffSide {
    pub index: PathBuf,
    pub root: String,
}

/// A unit of comparison: one partition, or a top-level directory with everything below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffUnit {
    /// Partition key, or top-level directory when `subtree` is set.
    pub name: String,
    /// Include the partitions nested below `name`.
    pub subtree: bool,
    pub in_old: bool,
    pub in_new: bool,
}

/// The units two indexes are compared by, given their partition keys.
///
/// When both were built with the same split spec every file lies in the same partition on
/// both sides, so partitions pair one-to-one. Otherwise a file can sit in different
/// partitions on each side, and only whole top-level subtrees are sure to line up.
pub fn diff_units(old: &[String], new: &[String], same_layout: bool) -> Vec<DiffUnit> {
    let (old_keys, new_keys, subtree) = if same_layout {
        (old.to_vec(), new.to_vec(), false)
    } else {
        (top_level_partitions(old), top_level_partitions(new), true)
    };
    let all: BTreeSet<&String> = old_keys.iter().chain(new_keys.iter()).collect();
    all.into_iter()
        .map(|name| DiffUnit {
            name: name.clone(),
            // The root partition never has partitions nested below it.
            subtree: subtree && name != ROOT_PARTITION,
            in_old: old_keys.contains(name),
            in_new: new_keys.contains(name),
        })
        .collect()
}

impl DiffSide {
    /// SQL relation for one unit of this side, keyed by path relative to the root. A typed
    /// empty relation when the unit is absent, so the join still has both sides.
    fn relation(&self, unit: &DiffUnit, present: bool) -> String {
        if !present {
            return "SELECT NULL::VARCHAR AS rel, NULL::BIGINT AS size, NULL::BIGINT AS atime, \
                    NULL::BIGINT AS mtime, NULL::BIGINT AS ctime, NULL::BIGINT AS uid, \
                    NULL::BIGINT AS gid, NULL::BIGINT AS mode WHERE false"
                .to_string();
        }
        let glob = if unit.subtree {
            index_glob(&self.index, Some(&unit.name))
        } else {
            partition_only_glob(&self.index, &unit.name)
        };
        format!(
            "SELECT substr(path, {start}) AS rel, size, atime, mtime, ctime, uid, gid, mode \
             FROM read_parquet({glob}, hive_partitioning = false)",
            start = self.root.chars().count() + 2,
            glob = sql_quote(&glob),
        )
    }
}

/// A query comparing one unit (see `diff_units`) between an old and a new index.
///
/// Output columns: `rel, status, size_old, size_new, delta, mtime_old, mtime_new`, then
/// `atime, mtime, ctime, uid, gid, mode` from the new index (the old one for a removed
/// file). The missing side's size is 0; `status` is one of `DIFF_STATUSES`.
pub fn diff_partition_sql(old: &DiffSide, new: &DiffSide, unit: &DiffUnit) -> String {
    format!(
        r#"
        WITH a AS ({rel_a}), b AS ({rel_b})
        SELECT
            COALESCE(a.rel, b.rel) AS rel,
            CASE
                WHEN a.rel IS NULL THEN 'added'
                WHEN b.rel IS NULL THEN 'removed'
                WHEN a.size <> b.size OR a.mtime <> b.mtime THEN 'modified'
                WHEN a.ctime <> b.ctime OR a.uid <> b.uid OR a.gid <> b.gid OR a.mode <> b.mode THEN 'meta'
                WHEN a.atime <> b.atime THEN 'accessed'
                ELSE 'unchanged'
            END AS status,
            COALESCE(a.size, 0) AS size_old,
            COALESCE(b.size, 0) AS size_new,
            COALESCE(b.size, 0) - COALESCE(a.size, 0) AS delta,
            a.mtime AS mtime_old,
            b.mtime AS mtime_new,
            COALESCE(b.atime, a.atime) AS atime,
            COALESCE(b.mtime, a.mtime) AS mtime,
            COALESCE(b.ctime, a.ctime) AS ctime,
            COALESCE(b.uid, a.uid) AS uid,
            COALESCE(b.gid, a.gid) AS gid,
            COALESCE(b.mode, a.mode) AS mode
        FROM a FULL OUTER JOIN b ON a.rel = b.rel
        "#,
        rel_a = old.relation(unit, unit.in_old),
        rel_b = new.relation(unit, unit.in_new),
    )
}

/// `diff_partition_sql` shaped like an index, so the index queries can run over it: `path`
/// is absolute under the new root (removed files included), `size` is the new size, and
/// `size_old` and `status` are added.
pub fn diff_as_index_sql(old: &DiffSide, new: &DiffSide, unit: &DiffUnit) -> String {
    format!(
        "SELECT {root} || '/' || rel AS path, size_new AS size, size_old, \
         atime, mtime, ctime, uid, gid, mode, status FROM ({diff})",
        root = sql_quote(&new.root),
        diff = diff_partition_sql(old, new, unit),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_diff_units_same_layout_pairs_partitions() {
        let units = diff_units(
            &keys(&["__root__", "a", "p/big"]),
            &keys(&["a", "b", "p/big"]),
            true,
        );
        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["__root__", "a", "b", "p/big"]);
        assert!(units.iter().all(|u| !u.subtree));
        assert!(units[0].in_old && !units[0].in_new);
        assert!(!units[2].in_old && units[2].in_new);
    }

    #[test]
    fn test_diff_units_different_layout_compares_subtrees() {
        let units = diff_units(
            &keys(&["__root__", "p"]),
            &keys(&["__root__", "p", "p/big"]),
            false,
        );
        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["__root__", "p"]);
        assert!(
            !units[0].subtree,
            "the root partition has nothing nested below it"
        );
        assert!(units[1].subtree);
    }

    #[test]
    fn test_diff_sql_globs_and_offsets() {
        let old = DiffSide {
            index: "/idx/old".into(),
            root: "/snap/a/home".into(),
        };
        let new = DiffSide {
            index: "/idx/new".into(),
            root: "/home".into(),
        };
        let unit = DiffUnit {
            name: "p".into(),
            subtree: true,
            in_old: true,
            in_new: false,
        };
        let sql = diff_partition_sql(&old, &new, &unit);
        assert!(sql.contains("'/idx/old/p/**/*.parquet'"), "{sql}");
        assert!(sql.contains("substr(path, 14)"), "{sql}");
        assert!(sql.contains("WHERE false"), "{sql}");
        let flat = DiffUnit {
            subtree: false,
            ..unit
        };
        assert!(diff_partition_sql(&old, &new, &flat).contains("'/idx/old/p/*.parquet'"));
        assert!(diff_as_index_sql(&old, &new, &flat).starts_with("SELECT '/home' || '/' || rel"));
    }
}
