//! The index queries behind `xdu-view`'s list and tree views.
//!
//! Every statement reads a `Relation`: the index itself, whose `FROM` comes from
//! `parquet_source` (so a local index gets its glob as text and an S3 index gets
//! `read_parquet(?)` with its glob bound), or one partition of a comparison against an older
//! index. The one other value a statement draws from the index, the directory prefix a listing
//! matches, is bound on the S3 arm as well. Each statement is built by a pure function
//! returning its text and the values it binds, so a unit test can pin the text without a
//! connection.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use duckdb::{Connection, params_from_iter};

use crate::diff::{DiffSide, DiffUnit, diff_as_index_sql, diff_units, discover_index_root};
use crate::layout::{list_partitions, top_level_key_sql};
use crate::{IndexLocator, QueryFilters, ROOT_PARTITION, SortMode, parquet_source, sql_quote};

/// One row of a view: a partition, a directory, or a file.
///
/// A directory's `uid` and `gid` are its files' common owner and group, or -1 when they
/// differ; its `mode` is the lowest of its files' permission bits. Outside a comparison the
/// `_old` fields equal the current ones and `changed` is 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub total_size: i64,
    pub file_count: i64,
    pub latest_atime: i64,
    pub latest_mtime: i64,
    pub latest_ctime: i64,
    pub uid: i64,
    pub gid: i64,
    pub mode: i64,
    /// Size in the older index.
    pub size_old: i64,
    /// File count in the older index.
    pub files_old: i64,
    /// Files added, removed or modified relative to the older index.
    pub changed: i64,
}

impl DirEntry {
    pub fn size_delta(&self) -> i64 {
        self.total_size - self.size_old
    }

    pub fn files_delta(&self) -> i64 {
        self.file_count - self.files_old
    }

    /// Change marker in a comparison: `+` new, `-` gone, `~` changed, blank if unchanged.
    pub fn change_marker(&self) -> char {
        if self.changed == 0 {
            ' '
        } else if self.files_old == 0 {
            '+'
        } else if self.file_count == 0 {
            '-'
        } else {
            '~'
        }
    }

    /// The `..` entry, which has no stats.
    pub fn parent() -> Self {
        DirEntry {
            name: "..".to_string(),
            path: "..".to_string(),
            is_dir: true,
            total_size: 0,
            file_count: 0,
            latest_atime: 0,
            latest_mtime: 0,
            latest_ctime: 0,
            uid: -1,
            gid: -1,
            mode: -1,
            size_old: 0,
            files_old: 0,
            changed: 0,
        }
    }
}

/// The aggregate columns of an index view, read back by `read_stats`.
const INDEX_AGGREGATES: &str = "
                SUM(size) as total_size,
                COUNT(*) as file_count,
                MAX(atime) as latest_atime,
                MAX(mtime) as latest_mtime,
                MAX(ctime) as latest_ctime,
                CASE WHEN MIN(uid) = MAX(uid) THEN MIN(uid) ELSE -1 END as min_uid,
                CASE WHEN MIN(gid) = MAX(gid) THEN MIN(gid) ELSE -1 END as min_gid,
                MIN(mode) as min_mode,
                SUM(size) as total_size_old,
                COUNT(*) as files_old,
                0 as changed,
                0 as size_delta";

/// The aggregate columns of a comparison view. A removed file counts toward the older index
/// only, and an added one toward the newer only.
const COMPARE_AGGREGATES: &str = "
                SUM(size) as total_size,
                COUNT(*) FILTER (WHERE status <> 'removed') as file_count,
                MAX(atime) as latest_atime,
                MAX(mtime) as latest_mtime,
                MAX(ctime) as latest_ctime,
                CASE WHEN MIN(uid) = MAX(uid) THEN MIN(uid) ELSE -1 END as min_uid,
                CASE WHEN MIN(gid) = MAX(gid) THEN MIN(gid) ELSE -1 END as min_gid,
                MIN(mode) as min_mode,
                SUM(size_old) as total_size_old,
                COUNT(*) FILTER (WHERE status <> 'added') as files_old,
                COUNT(*) FILTER (WHERE status IN ('added', 'removed', 'modified', 'meta')) as changed,
                SUM(size) - SUM(size_old) as size_delta";

/// The per-file equivalents of the aggregate columns, for listing loose files.
const INDEX_FILE_STATS: &str = "size, 1, atime, mtime, ctime, uid, gid, mode, size, 1, 0";
const COMPARE_FILE_STATS: &str = "size, CASE WHEN status = 'removed' THEN 0 ELSE 1 END, \
     atime, mtime, ctime, uid, gid, mode, size_old, CASE WHEN status = 'added' THEN 0 ELSE 1 END, \
     CASE WHEN status IN ('added', 'removed', 'modified', 'meta') THEN 1 ELSE 0 END";

/// The files a statement reads, with the values its text binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    pub from: String,
    pub params: Vec<String>,
    /// Rows carry a comparison's `size_old` and `status` columns.
    pub compare: bool,
    /// Bind the directory prefix of a listing rather than writing it into the text.
    pub bind_prefix: bool,
}

impl Relation {
    /// The files of `partition` and the partitions nested below it, or of the whole index.
    pub fn index(index: &IndexLocator, partition: Option<&str>) -> Relation {
        let (from, params) = parquet_source(index, partition, false);
        Relation {
            from,
            params,
            compare: false,
            bind_prefix: matches!(index, IndexLocator::S3(_)),
        }
    }

    /// Every file of the index with a `partition` column naming its top-level directory, so a
    /// nested partition is counted under the directory it lies in.
    pub fn index_partitions(index: &IndexLocator) -> Relation {
        let (source, params) = parquet_source(index, None, true);
        Relation {
            from: format!(
                "(SELECT *, {} AS partition FROM {source})",
                top_level_key_sql(index)
            ),
            params,
            compare: false,
            bind_prefix: matches!(index, IndexLocator::S3(_)),
        }
    }

    fn aggregates(&self) -> &'static str {
        if self.compare {
            COMPARE_AGGREGATES
        } else {
            INDEX_AGGREGATES
        }
    }

    fn file_stats(&self) -> &'static str {
        if self.compare {
            COMPARE_FILE_STATS
        } else {
            INDEX_FILE_STATS
        }
    }
}

/// Build an entry from the aggregate columns, starting at column `col`.
fn read_stats(
    row: &duckdb::Row,
    col: usize,
    name: String,
    path: String,
    is_dir: bool,
) -> duckdb::Result<DirEntry> {
    Ok(DirEntry {
        name,
        path,
        is_dir,
        total_size: row.get(col)?,
        file_count: row.get(col + 1)?,
        latest_atime: row.get(col + 2)?,
        latest_mtime: row.get(col + 3)?,
        latest_ctime: row.get(col + 4)?,
        uid: row.get(col + 5)?,
        gid: row.get(col + 6)?,
        mode: row.get(col + 7)?,
        size_old: row.get(col + 8)?,
        files_old: row.get(col + 9)?,
        changed: row.get(col + 10)?,
    })
}

fn where_clause(conditions: &[String]) -> String {
    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

/// The statement listing the loose files of `rel` (the `__root__` partition), with its
/// bound values.
pub fn root_files_in_sql(rel: &Relation, conditions: &[String]) -> (String, Vec<String>) {
    let sql = format!(
        "SELECT path, {stats} FROM {from} {where_clause}",
        stats = rel.file_stats(),
        from = rel.from,
        where_clause = where_clause(conditions),
    );
    (sql, rel.params.clone())
}

/// The loose files of `rel`, each with `is_dir` false and a count of 1.
///
/// An index without a `__root__` partition has no files to match, which DuckDB reports as an
/// error; that, like any failure here, yields no entries.
pub fn root_files_in(
    conn: &Connection,
    rel: &Relation,
    conditions: &[String],
) -> Result<Vec<DirEntry>> {
    let (sql, params) = root_files_in_sql(rel, conditions);

    let mut entries = Vec::new();
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Ok(entries);
    };
    let Ok(mut rows) = stmt.query(params_from_iter(&params)) else {
        return Ok(entries);
    };
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        entries.push(read_stats(row, 1, name, path, false)?);
    }
    Ok(entries)
}

/// The statement listing every top-level partition but `__root__` from a relation with a
/// `partition` column, with its bound values.
///
/// Not Hive partitioning: the layout uses bare directory names, so `hive_partitioning=true`
/// would yield no partition column at all. Filters apply before grouping, so only matching
/// files are counted and a partition with none is left out.
pub fn partitions_in_sql(
    rel: &Relation,
    conditions: &[String],
    sort_mode: SortMode,
) -> (String, Vec<String>) {
    let mut conditions = conditions.to_vec();
    conditions.push(format!(
        "partition IS NOT NULL AND partition != '' AND partition != '{}'",
        ROOT_PARTITION
    ));
    let sql = format!(
        r#"
            SELECT partition, {aggregates}
            FROM {from}
            {where_clause}
            GROUP BY partition
            ORDER BY {order}
            "#,
        aggregates = rel.aggregates(),
        from = rel.from,
        where_clause = where_clause(&conditions),
        order = sort_mode.to_partition_order_by()
    );
    (sql, rel.params.clone())
}

/// Every top-level partition but `__root__`, as directory entries in `sort_mode`'s order.
///
/// The caller merges in `root_files` and sorts the merged list itself.
pub fn partitions_in(
    conn: &Connection,
    rel: &Relation,
    conditions: &[String],
    sort_mode: SortMode,
) -> Result<Vec<DirEntry>> {
    let (sql, params) = partitions_in_sql(rel, conditions, sort_mode);

    let mut entries = Vec::new();
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(&params))?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        entries.push(read_stats(row, 1, name.clone(), name, true)?);
    }
    Ok(entries)
}

/// The statement finding a partition's shortest path, with its bound values.
pub fn partition_root_sql(index: &IndexLocator, partition: &str) -> (String, Vec<String>) {
    let (source, params) = parquet_source(index, Some(partition), false);
    let sql = format!("SELECT path FROM {} ORDER BY length(path) LIMIT 1", source);
    (sql, params)
}

/// The directory holding a partition's shortest path, or an empty string for an empty
/// partition. The fallback when the crawl root is unknown, as for an S3 index: a partition
/// whose files all lie deeper than its top opens at the shallowest of them.
pub fn partition_root(conn: &Connection, index: &IndexLocator, partition: &str) -> Result<String> {
    let (sql, params) = partition_root_sql(index, partition);

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(&params))?;

    if let Some(row) = rows.next()? {
        let sample_path: String = row.get(0)?;
        if let Some(pos) = sample_path.rfind('/') {
            return Ok(sample_path[..pos].to_string());
        }
    }

    Ok(String::new())
}

/// The statement listing the entries directly under `dir` in `rel`, with its bound values.
///
/// The prefix is matched with `starts_with`, never `LIKE`, so `%` and `_` in a directory name
/// are not wildcards. A local index writes it as a quoted literal; an S3 index binds it after
/// the glob.
pub fn directory_in_sql(
    rel: &Relation,
    dir: &str,
    conditions: &[String],
    sort_mode: SortMode,
) -> (String, Vec<String>) {
    let prefix = format!("{}/", dir);
    // The component starts after the prefix; substr counts characters.
    let prefix_len = prefix.chars().count();
    let mut params = rel.params.clone();

    let prefix_match = if rel.bind_prefix {
        params.push(prefix);
        "starts_with(path, ?)".to_string()
    } else {
        format!("starts_with(path, {})", sql_quote(&prefix))
    };
    let mut all_conditions = vec![prefix_match];
    all_conditions.extend(conditions.iter().cloned());

    let sql = format!(
        r#"
            WITH files AS (
                SELECT * FROM {from}
                {where_clause}
            ),
            components AS (
                SELECT
                    *,
                    CASE
                        WHEN position('/' IN substr(path, {prefix_len} + 1)) > 0
                        THEN substr(path, {prefix_len} + 1, position('/' IN substr(path, {prefix_len} + 1)) - 1)
                        ELSE substr(path, {prefix_len} + 1)
                    END as component,
                    CASE
                        WHEN position('/' IN substr(path, {prefix_len} + 1)) > 0 THEN true
                        ELSE false
                    END as is_dir
                FROM files
            )
            SELECT
                component,
                bool_or(is_dir) as is_dir,
                {aggregates}
            FROM components
            WHERE component != '' AND component IS NOT NULL
            GROUP BY component
            ORDER BY {order_by}
            "#,
        from = rel.from,
        where_clause = where_clause(&all_conditions),
        aggregates = rel.aggregates(),
        order_by = sort_mode.to_order_by(sort_mode == SortMode::Name),
    );
    (sql, params)
}

/// The entries directly under `dir` in `rel`.
pub fn directory_in(
    conn: &Connection,
    rel: &Relation,
    dir: &str,
    conditions: &[String],
    sort_mode: SortMode,
) -> Result<Vec<DirEntry>> {
    let (sql, params) = directory_in_sql(rel, dir, conditions, sort_mode);

    let mut entries = Vec::new();
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(&params))?;
    while let Some(row) = rows.next()? {
        let component: String = row.get(0)?;
        let is_dir: bool = row.get(1)?;
        let path = format!("{}/{}", dir, component);
        entries.push(read_stats(row, 2, component, path, is_dir)?);
    }
    Ok(entries)
}

// The index views by index and filters: each the `_in` function over `Relation::index`.

/// The statement listing the files of the `__root__` partition, with its bound values.
pub fn root_files_sql(index: &IndexLocator, filters: &QueryFilters) -> (String, Vec<String>) {
    root_files_in_sql(
        &Relation::index(index, Some(ROOT_PARTITION)),
        &filters.to_conditions(),
    )
}

/// Individual files from the `__root__` partition (see `root_files_in`).
pub fn root_files(
    conn: &Connection,
    index: &IndexLocator,
    filters: &QueryFilters,
) -> Result<Vec<DirEntry>> {
    root_files_in(
        conn,
        &Relation::index(index, Some(ROOT_PARTITION)),
        &filters.to_conditions(),
    )
}

/// The statement listing every top-level partition but `__root__`, with its bound values.
pub fn partitions_sql(
    index: &IndexLocator,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> (String, Vec<String>) {
    partitions_in_sql(
        &Relation::index_partitions(index),
        &filters.to_conditions(),
        sort_mode,
    )
}

/// Every top-level partition but `__root__`, as directory entries in `sort_mode`'s order.
pub fn partitions(
    conn: &Connection,
    index: &IndexLocator,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> Result<Vec<DirEntry>> {
    partitions_in(
        conn,
        &Relation::index_partitions(index),
        &filters.to_conditions(),
        sort_mode,
    )
}

/// The list view's statement for the entries directly under `dir`, with its bound values.
pub fn list_directory_sql(
    index: &IndexLocator,
    partition: &str,
    dir: &str,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> (String, Vec<String>) {
    directory_in_sql(
        &Relation::index(index, Some(partition)),
        dir,
        &filters.to_conditions(),
        sort_mode,
    )
}

/// The tree view's statement for the entries directly under `dir`: the list view's.
pub fn tree_directory_sql(
    index: &IndexLocator,
    partition: &str,
    dir: &str,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> (String, Vec<String>) {
    list_directory_sql(index, partition, dir, filters, sort_mode)
}

/// The entries directly under `dir` in `partition`, for the list view.
pub fn list_directory(
    conn: &Connection,
    index: &IndexLocator,
    partition: &str,
    dir: &str,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> Result<Vec<DirEntry>> {
    directory_in(
        conn,
        &Relation::index(index, Some(partition)),
        dir,
        &filters.to_conditions(),
        sort_mode,
    )
}

/// The entries directly under `dir` in `partition`, for the tree view.
pub fn tree_directory(
    conn: &Connection,
    index: &IndexLocator,
    partition: &str,
    dir: &str,
    filters: &QueryFilters,
    sort_mode: SortMode,
) -> Result<Vec<DirEntry>> {
    list_directory(conn, index, partition, dir, filters, sort_mode)
}

/// A view of one index compared against an older index of the same tree.
///
/// The view navigates by top-level directory, so each one is compared as a whole subtree.
/// A partition's diff is materialized into a temp table the first time it is opened, so
/// moving around inside it does not redo the join.
pub struct Compare {
    pub old: DiffSide,
    pub new: DiffSide,
    /// Top-level directory to the comparison unit covering its subtree.
    units: BTreeMap<String, DiffUnit>,
    /// Top-level directory to the temp table holding its diff.
    tables: RefCell<HashMap<String, String>>,
}

impl Compare {
    /// Compare the local index `new` (crawl root `new_root`, partitions `new_partitions`)
    /// against the local index `old`.
    pub fn open(
        conn: &Connection,
        new: &Path,
        new_root: &str,
        new_partitions: &[String],
        old: &Path,
    ) -> Result<Compare> {
        let old_partitions = list_partitions(old)?;
        let old_root = discover_index_root(conn, old, &old_partitions)?;
        let units = diff_units(&old_partitions, new_partitions, false)
            .into_iter()
            .map(|u| (u.name.clone(), u))
            .collect();
        Ok(Compare {
            old: DiffSide {
                index: old.to_path_buf(),
                root: old_root,
            },
            new: DiffSide {
                index: new.to_path_buf(),
                root: new_root.to_string(),
            },
            units,
            tables: RefCell::new(HashMap::new()),
        })
    }

    /// The diff of one top-level directory, or `None` when neither index has it.
    pub fn relation(&self, conn: &Connection, partition: &str) -> Result<Option<Relation>> {
        let Some(unit) = self.units.get(partition) else {
            return Ok(None);
        };
        if let Some(name) = self.tables.borrow().get(partition) {
            return Ok(Some(compare_relation(name.clone())));
        }
        let name = format!("xdu_diff_{}", self.tables.borrow().len());
        conn.execute_batch(&format!(
            "CREATE TEMP TABLE {} AS {}",
            name,
            diff_as_index_sql(&self.old, &self.new, unit)
        ))
        .with_context(|| format!("Comparing partition '{}'", partition))?;
        self.tables
            .borrow_mut()
            .insert(partition.to_string(), name.clone());
        Ok(Some(compare_relation(name)))
    }

    /// Every top-level directory's diff with a `partition` column. Directories already
    /// materialized are read from their tables; the rest are joined in place.
    pub fn partitions_relation(&self) -> Relation {
        let tables = self.tables.borrow();
        let parts: Vec<String> = self
            .units
            .iter()
            .filter(|(name, _)| name.as_str() != ROOT_PARTITION)
            .map(|(name, unit)| {
                let source = match tables.get(name) {
                    Some(table) => table.clone(),
                    None => format!("({})", diff_as_index_sql(&self.old, &self.new, unit)),
                };
                format!("SELECT {} AS partition, * FROM {}", sql_quote(name), source)
            })
            .collect();
        let from = if parts.is_empty() {
            "(SELECT NULL::VARCHAR AS partition, NULL::BIGINT AS size, \
             NULL::BIGINT AS size_old, NULL::VARCHAR AS status WHERE false)"
                .to_string()
        } else {
            format!("({})", parts.join(" UNION ALL "))
        };
        compare_relation(from)
    }
}

fn compare_relation(from: String) -> Relation {
    Relation {
        from,
        params: Vec::new(),
        compare: true,
        bind_prefix: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    use std::path::PathBuf;

    use crate::S3Locator;

    /// No filter, and one of every kind xdu-view accepts, with a quote in the pattern.
    fn condition_sets() -> Vec<Vec<String>> {
        let all = QueryFilters::new()
            .with_path_pattern(Some("*o'brien*.log".to_string()), false)
            .unwrap()
            .with_older_than(Some(30))
            .with_newer_than(Some(400))
            .with_min_size(Some("1K"))
            .unwrap()
            .with_max_size(Some("1G"))
            .unwrap();
        let regex = QueryFilters::new()
            .with_path_pattern(Some("\\.txt$".to_string()), true)
            .unwrap();
        vec![
            Vec::new(),
            all.to_conditions(),
            regex.to_conditions(),
            vec!["status = 'added'".to_string()],
        ]
    }

    #[test]
    fn local_view_sql_names_the_glob_and_quotes_the_prefix() {
        let index = IndexLocator::Local(PathBuf::from("/index/scratch"));
        for conditions in condition_sets() {
            let (sql, params) =
                root_files_in_sql(&Relation::index(&index, Some(ROOT_PARTITION)), &conditions);
            assert!(
                sql.contains("FROM read_parquet('/index/scratch/__root__/**/*.parquet')"),
                "{sql}"
            );
            assert!(params.is_empty());

            for sort_mode in SortMode::ALL {
                let (sql, params) =
                    partitions_in_sql(&Relation::index_partitions(&index), &conditions, sort_mode);
                assert!(
                    sql.contains("read_parquet('/index/scratch/**/*.parquet', filename=true)"),
                    "{sql}"
                );
                assert!(sql.contains("split_part("), "{sql}");
                assert!(sql.contains(sort_mode.to_partition_order_by()), "{sql}");
                assert!(params.is_empty());

                let rel = Relation::index(&index, Some("o'brien"));
                let (sql, params) =
                    directory_in_sql(&rel, "/data/scratch/o'brien/it's", &conditions, sort_mode);
                assert!(
                    sql.contains("starts_with(path, '/data/scratch/o''brien/it''s/')"),
                    "{sql}"
                );
                assert!(sql.contains("substr(path, 27 + 1)"), "{sql}");
                assert!(params.is_empty());
            }
        }
    }

    #[test]
    fn s3_view_sql_binds_the_glob_and_the_directory_prefix() {
        // A quote in the prefix, the partition or a directory would end a literal; bound, none
        // of them reaches the text.
        let index = IndexLocator::S3(S3Locator::parse(OsStr::new("s3://bucket/it's")).unwrap());
        let glob = |partition: &str| match partition {
            "*" => "s3://bucket/it's/**/*.parquet".to_string(),
            _ => format!("s3://bucket/it's/{partition}/**/*.parquet"),
        };
        let values = ["it's", "o'brien", "/data/x'y"];
        let assert_bound = |sql: &str| {
            for value in values {
                assert!(!sql.contains(value), "{value} reached the text: {sql}");
            }
            assert!(!sql.contains("s3://"), "the glob reached the text: {sql}");
        };

        for conditions in condition_sets() {
            let (sql, params) =
                root_files_in_sql(&Relation::index(&index, Some(ROOT_PARTITION)), &conditions);
            assert!(sql.contains("FROM read_parquet(?)"), "{sql}");
            assert_eq!(params, vec![glob(ROOT_PARTITION)]);
            assert_bound(&sql);

            let (sql, params) = partition_root_sql(&index, "o'brien");
            assert_eq!(
                sql,
                "SELECT path FROM read_parquet(?) ORDER BY length(path) LIMIT 1"
            );
            assert_eq!(params, vec![glob("o'brien")]);

            for sort_mode in SortMode::ALL {
                let (sql, params) =
                    partitions_in_sql(&Relation::index_partitions(&index), &conditions, sort_mode);
                assert!(sql.contains("FROM read_parquet(?, filename=true)"), "{sql}");
                assert_eq!(params, vec![glob("*")]);
                assert_bound(&sql);

                let rel = Relation::index(&index, Some("o'brien"));
                let (sql, params) = directory_in_sql(&rel, "/data/x'y", &conditions, sort_mode);
                assert!(sql.contains("FROM read_parquet(?)"), "{sql}");
                assert!(sql.contains("starts_with(path, ?)"), "{sql}");
                // The glob is the first placeholder and the prefix the second.
                assert_eq!(params, vec![glob("o'brien"), "/data/x'y/".to_string()]);
                // Outside the filter text, whose own pattern may hold a `?`, every `?` is a
                // placeholder.
                let placeholders = sql.replace(&conditions.join(" AND "), "");
                assert_eq!(placeholders.matches('?').count(), params.len(), "{sql}");
                assert_bound(&sql);
            }
        }
    }

    #[test]
    fn compare_relations_carry_the_diff_columns() {
        let rel = compare_relation("xdu_diff_0".to_string());
        let (sql, _) = directory_in_sql(&rel, "/data/a", &[], SortMode::DeltaDesc);
        assert!(sql.contains("SUM(size_old)"), "{sql}");
        assert!(sql.contains("ORDER BY size_delta DESC"), "{sql}");
        let (sql, _) = root_files_in_sql(&rel, &[]);
        assert!(sql.contains("status = 'removed'"), "{sql}");
    }

    #[test]
    fn dir_entry_change_markers() {
        let mut e = DirEntry::parent();
        assert_eq!(e.change_marker(), ' ');
        e.changed = 1;
        e.file_count = 3;
        assert_eq!(e.change_marker(), '+');
        e.files_old = 2;
        assert_eq!(e.change_marker(), '~');
        e.file_count = 0;
        assert_eq!(e.change_marker(), '-');
        e.total_size = 10;
        e.size_old = 4;
        assert_eq!(e.size_delta(), 6);
        assert_eq!(e.files_delta(), -2);
    }
}
