use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use duckdb::Connection;

use xdu::{
    diff_partition_sql, discover_index_root, format_bytes, format_bytes_signed, list_partitions,
    parse_size, sql_quote, DiffSide, DIFF_STATUSES,
};

#[derive(Parser, Debug)]
#[command(
    name = "xdu-diff",
    about = "Compare two file metadata indices (e.g. from two snapshots)",
    disable_help_flag = true,
    after_help = "Files are matched by path relative to each index's crawl root, so indices
built from different snapshot directories compare cleanly.

Statuses: added, removed, modified (size/mtime), meta (ctime/uid/gid/mode),
          accessed (atime only), unchanged

Exit status: 0 if no differences (ignoring atime), 1 if differences, 2 on error.

Examples:
  xdu-diff -h /index/snap-mon /index/snap-wed
  xdu-diff -h --sort delta /index/snap-mon /index/snap-wed
  xdu-diff -h --files /index/snap-mon /index/snap-wed
  xdu-diff -h --files --status added --min-delta 1G --sort delta -l 20 OLD NEW
  xdu-diff --files --csv -u alice OLD NEW"
)]
struct Args {
    /// Old (earlier) index directory
    old: PathBuf,

    /// New (later) index directory
    new: PathBuf,

    /// List individual files instead of a per-partition summary
    #[arg(short, long)]
    files: bool,

    /// Statuses to list with --files (comma-separated, or "all")
    #[arg(long, value_name = "LIST", default_value = "added,removed,modified,meta")]
    status: String,

    /// Restrict to a single partition
    #[arg(short = 'u', long, value_name = "NAME")]
    partition: Option<String>,

    /// Regular expression matched against relative paths
    #[arg(short, long, value_name = "REGEX")]
    pattern: Option<String>,

    /// With --files: only files whose size changed by at least SIZE (e.g. 10M)
    #[arg(long, value_name = "SIZE")]
    min_delta: Option<String>,

    /// Sort order: name, delta (largest growth first), shrink, abs (largest change first)
    #[arg(short, long, default_value = "name")]
    sort: String,

    /// Limit number of output rows
    #[arg(short, long)]
    limit: Option<usize>,

    /// Summary: include partitions with no changes
    #[arg(short, long)]
    all: bool,

    /// With --files: print absolute paths (new root, or old root for removed files)
    #[arg(long)]
    absolute: bool,

    /// Human-readable sizes
    #[arg(short = 'h', long)]
    human_readable: bool,

    /// Output as CSV with a header row (raw values)
    #[arg(long)]
    csv: bool,

    /// Override the detected crawl root of the old index
    #[arg(long, value_name = "PATH")]
    old_root: Option<String>,

    /// Override the detected crawl root of the new index
    #[arg(long, value_name = "PATH")]
    new_root: Option<String>,

    /// Show help
    #[arg(long, action = clap::ArgAction::Help)]
    help: Option<bool>,
}

/// Per-partition aggregate of a diff.
#[derive(Default, Clone)]
struct Summary {
    name: String,
    size_old: i64,
    size_new: i64,
    files_old: i64,
    files_new: i64,
    added: i64,
    removed: i64,
    modified: i64,
    meta: i64,
    accessed: i64,
}

impl Summary {
    fn delta(&self) -> i64 { self.size_new - self.size_old }
    fn changed(&self) -> i64 { self.added + self.removed + self.modified + self.meta }

    fn accumulate(&mut self, other: &Summary) {
        self.size_old += other.size_old;
        self.size_new += other.size_new;
        self.files_old += other.files_old;
        self.files_new += other.files_new;
        self.added += other.added;
        self.removed += other.removed;
        self.modified += other.modified;
        self.meta += other.meta;
        self.accessed += other.accessed;
    }
}

/// A single changed file.
struct FileDiff {
    rel: String,
    status: String,
    size_old: i64,
    size_new: i64,
    delta: i64,
    mtime_old: Option<i64>,
    mtime_new: Option<i64>,
    uid: i32,
}

fn status_marker(status: &str) -> &'static str {
    match status {
        "added" => "+",
        "removed" => "-",
        "modified" => "~",
        "meta" => "m",
        "accessed" => ".",
        _ => "=",
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn fmt_size(bytes: i64, human: bool) -> String {
    if human { format_bytes(bytes.max(0) as u64) } else { bytes.to_string() }
}

fn fmt_delta(delta: i64, human: bool) -> String {
    if human {
        format_bytes_signed(delta)
    } else if delta > 0 {
        format!("+{}", delta)
    } else {
        delta.to_string()
    }
}

fn fmt_count_delta(delta: i64) -> String {
    if delta > 0 { format!("+{}", delta) } else { delta.to_string() }
}

/// Sort key for a delta according to --sort (ties broken by name).
fn delta_key(sort: &str, delta: i64) -> i64 {
    match sort {
        "delta" => -delta,
        "shrink" => delta,
        "abs" => -(delta.saturating_abs()),
        _ => 0,
    }
}

fn open_side(conn: &Connection, path: &PathBuf, root_override: &Option<String>) -> Result<(DiffSide, Vec<String>)> {
    let index = path.canonicalize()
        .with_context(|| format!("Index directory not found: {}", path.display()))?;
    let partitions = list_partitions(&index)?;
    let root = match root_override {
        Some(r) => r.trim_end_matches('/').to_string(),
        None => discover_index_root(conn, &index, &partitions)?,
    };
    Ok((DiffSide { index, root }, partitions))
}

fn run(args: Args) -> Result<bool> {
    if !["name", "delta", "shrink", "abs"].contains(&args.sort.as_str()) {
        anyhow::bail!("Unknown sort '{}'. Valid: name, delta, shrink, abs", args.sort);
    }
    let statuses: Vec<String> = if args.status == "all" {
        DIFF_STATUSES.iter().map(|s| s.to_string()).collect()
    } else {
        args.status.split(',').map(|s| s.trim().to_string()).collect()
    };
    for s in &statuses {
        if !DIFF_STATUSES.contains(&s.as_str()) {
            anyhow::bail!("Unknown status '{}'. Valid: {}, all", s, DIFF_STATUSES.join(", "));
        }
    }
    let min_delta = args.min_delta.as_deref()
        .map(parse_size)
        .transpose()
        .map_err(|e| anyhow::anyhow!(e))?;

    let conn = Connection::open_in_memory()?;
    let (old, old_parts) = open_side(&conn, &args.old, &args.old_root)?;
    let (new, new_parts) = open_side(&conn, &args.new, &args.new_root)?;

    let old_set: BTreeSet<&String> = old_parts.iter().collect();
    let new_set: BTreeSet<&String> = new_parts.iter().collect();
    let mut partitions: Vec<&String> = old_set.union(&new_set).copied().collect();
    if let Some(ref p) = args.partition {
        partitions.retain(|name| *name == p);
        if partitions.is_empty() {
            anyhow::bail!("Partition '{}' not found in either index", p);
        }
    }

    let pattern_clause = match args.pattern {
        Some(ref re) => format!("WHERE regexp_matches(rel, {})", sql_quote(re)),
        None => String::new(),
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let human = args.human_readable && !args.csv;

    if !args.files {
        // Per-partition summary
        let mut rows: Vec<Summary> = Vec::new();
        for p in &partitions {
            let diff = diff_partition_sql(&old, &new, p, old_set.contains(p), new_set.contains(p));
            let sql = format!(
                "SELECT
                    COALESCE(SUM(size_old), 0)::BIGINT, COALESCE(SUM(size_new), 0)::BIGINT,
                    COUNT(*) FILTER (WHERE status <> 'added'),
                    COUNT(*) FILTER (WHERE status <> 'removed'),
                    COUNT(*) FILTER (WHERE status = 'added'),
                    COUNT(*) FILTER (WHERE status = 'removed'),
                    COUNT(*) FILTER (WHERE status = 'modified'),
                    COUNT(*) FILTER (WHERE status = 'meta'),
                    COUNT(*) FILTER (WHERE status = 'accessed')
                 FROM ({diff}) {pattern_clause}"
            );
            let s = conn.query_row(&sql, [], |r| Ok(Summary {
                name: p.to_string(),
                size_old: r.get(0)?,
                size_new: r.get(1)?,
                files_old: r.get(2)?,
                files_new: r.get(3)?,
                added: r.get(4)?,
                removed: r.get(5)?,
                modified: r.get(6)?,
                meta: r.get(7)?,
                accessed: r.get(8)?,
            })).with_context(|| format!("Comparing partition '{}'", p))?;
            rows.push(s);
        }

        let mut total = Summary { name: "TOTAL".to_string(), ..Default::default() };
        for s in &rows {
            total.accumulate(s);
        }
        let any_changes = total.changed() > 0;

        if !args.all {
            rows.retain(|s| s.changed() > 0 || s.accessed > 0);
        }
        rows.sort_by(|a, b| {
            delta_key(&args.sort, a.delta()).cmp(&delta_key(&args.sort, b.delta()))
                .then_with(|| a.name.cmp(&b.name))
        });
        if let Some(n) = args.limit {
            rows.truncate(n);
        }

        let header = ["partition", "old", "new", "delta", "files_old", "files_new",
                      "files_delta", "added", "removed", "modified", "meta", "accessed"];
        let format_row = |s: &Summary| -> Vec<String> {
            vec![
                s.name.clone(),
                fmt_size(s.size_old, human),
                fmt_size(s.size_new, human),
                fmt_delta(s.delta(), human),
                s.files_old.to_string(),
                s.files_new.to_string(),
                fmt_count_delta(s.files_new - s.files_old),
                s.added.to_string(),
                s.removed.to_string(),
                s.modified.to_string(),
                s.meta.to_string(),
                s.accessed.to_string(),
            ]
        };

        if args.csv {
            writeln!(out, "{}", header.join(","))?;
            for s in &rows {
                let mut cells = format_row(s);
                cells[0] = csv_escape(&cells[0]);
                writeln!(out, "{}", cells.join(","))?;
            }
        } else {
            writeln!(out, "old: {}  ({})", old.root, old.index.display())?;
            writeln!(out, "new: {}  ({})", new.root, new.index.display())?;
            writeln!(out)?;

            let mut table: Vec<Vec<String>> = vec![header.iter().map(|h| h.to_string()).collect()];
            table.extend(rows.iter().map(format_row));
            table.push(format_row(&total));
            let widths: Vec<usize> = (0..header.len())
                .map(|c| table.iter().map(|r| r[c].len()).max().unwrap_or(0))
                .collect();
            let last = table.len() - 1;
            for (i, row) in table.iter().enumerate() {
                if i == last {
                    let rule: usize = widths.iter().sum::<usize>() + 2 * (widths.len() - 1);
                    writeln!(out, "{}", "-".repeat(rule))?;
                }
                let line: Vec<String> = row.iter().enumerate().map(|(c, v)| {
                    if c == 0 { format!("{:<w$}", v, w = widths[c]) } else { format!("{:>w$}", v, w = widths[c]) }
                }).collect();
                writeln!(out, "{}", line.join("  "))?;
            }

            let only_old: Vec<&&String> = old_set.difference(&new_set).collect();
            let only_new: Vec<&&String> = new_set.difference(&old_set).collect();
            if args.partition.is_none() && (!only_old.is_empty() || !only_new.is_empty()) {
                writeln!(out)?;
                for p in only_new {
                    writeln!(out, "new partition: {}", p)?;
                }
                for p in only_old {
                    writeln!(out, "removed partition: {}", p)?;
                }
            }
        }
        return Ok(any_changes);
    }

    // --files: list individual changed files
    let status_list = statuses.iter().map(|s| sql_quote(s)).collect::<Vec<_>>().join(", ");
    let mut conditions = vec![format!("status IN ({})", status_list)];
    if let Some(ref re) = args.pattern {
        conditions.push(format!("regexp_matches(rel, {})", sql_quote(re)));
    }
    if let Some(n) = min_delta {
        conditions.push(format!("abs(delta) >= {}", n));
    }
    let order_by = match args.sort.as_str() {
        "delta" => "delta DESC, rel",
        "shrink" => "delta ASC, rel",
        "abs" => "abs(delta) DESC, rel",
        _ => "rel",
    };
    // Each partition is sorted and limited in DuckDB, then merged here.
    let limit_clause = args.limit.map(|n| format!("LIMIT {}", n)).unwrap_or_default();

    let mut files: Vec<FileDiff> = Vec::new();
    let mut any_changes = false;
    for p in &partitions {
        let diff = diff_partition_sql(&old, &new, p, old_set.contains(p), new_set.contains(p));
        let sql = format!(
            "SELECT rel, status, size_old, size_new, delta, mtime_old, mtime_new, uid
             FROM ({diff}) WHERE {} ORDER BY {order_by} {limit_clause}",
            conditions.join(" AND "),
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let f = FileDiff {
                rel: r.get(0)?,
                status: r.get(1)?,
                size_old: r.get(2)?,
                size_new: r.get(3)?,
                delta: r.get(4)?,
                mtime_old: r.get(5)?,
                mtime_new: r.get(6)?,
                uid: r.get(7)?,
            };
            any_changes |= !matches!(f.status.as_str(), "accessed" | "unchanged");
            files.push(f);
        }
    }

    files.sort_by(|a, b| {
        delta_key(&args.sort, a.delta).cmp(&delta_key(&args.sort, b.delta))
            .then_with(|| a.rel.cmp(&b.rel))
    });
    if let Some(n) = args.limit {
        files.truncate(n);
    }

    let display_path = |f: &FileDiff| -> String {
        if !args.absolute {
            return f.rel.clone();
        }
        let root = if f.status == "removed" { &old.root } else { &new.root };
        format!("{}/{}", root, f.rel)
    };

    if args.csv {
        writeln!(out, "status,path,size_old,size_new,delta,mtime_old,mtime_new,uid")?;
        let opt = |v: Option<i64>| v.map(|t| t.to_string()).unwrap_or_default();
        for f in &files {
            writeln!(out, "{},{},{},{},{},{},{},{}",
                f.status, csv_escape(&display_path(f)), f.size_old, f.size_new, f.delta,
                opt(f.mtime_old), opt(f.mtime_new), f.uid)?;
        }
    } else {
        for f in &files {
            let size = if f.status == "removed" { f.size_old } else { f.size_new };
            writeln!(out, "{}\t{}\t{}\t{}",
                status_marker(&f.status), fmt_delta(f.delta, human), fmt_size(size, human), display_path(f))?;
        }
    }

    Ok(any_changes)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(false) => ExitCode::from(0),
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("xdu-diff: {:#}", e);
            ExitCode::from(2)
        }
    }
}
