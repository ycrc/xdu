use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::DateTime;
use clap::Parser;
use duckdb::Connection;

use xdu::{format_bytes, index_glob, partition_key_sql, sql_quote, QueryFilters};

const VALID_FIELDS: &[&str] = &["path", "size", "atime", "mtime", "ctime", "uid", "gid", "mode"];

#[derive(Parser, Debug)]
#[command(
    name = "xdu-find",
    about = "Query a file metadata index for matching paths",
    after_help = "Examples:
  xdu-find -i /index/scratch -p '\\.py$' --min-size 1M
  xdu-find -i /index/scratch --older-than 90 -f path,size,atime
  xdu-find -i /index/scratch -u alice --count
  xdu-find -i /index/scratch --top 10
  xdu-find -i /index/scratch -f path,size,mtime,uid --csv"
)]
struct Args {
    /// Path to the Parquet index directory
    #[arg(short, long, value_name = "DIR", env = "XDU_INDEX")]
    index: PathBuf,

    /// Regular expression pattern to match paths
    #[arg(short, long, value_name = "REGEX")]
    pattern: Option<String>,

    /// Filter by partition (e.g. a user directory, or a nested path like projects/big); includes nested partitions
    #[arg(short = 'u', long, value_name = "NAME")]
    partition: Option<String>,

    /// Minimum file size (e.g., 1K, 10M, 1G)
    #[arg(long, value_name = "SIZE")]
    min_size: Option<String>,

    /// Maximum file size (e.g., 1K, 10M, 1G)
    #[arg(long, value_name = "SIZE")]
    max_size: Option<String>,

    /// Files not accessed in N days
    #[arg(long, value_name = "DAYS")]
    older_than: Option<u64>,

    /// Files accessed within N days
    #[arg(long, value_name = "DAYS")]
    newer_than: Option<u64>,

    /// Files not modified in N days
    #[arg(long, value_name = "DAYS")]
    modified_older_than: Option<u64>,

    /// Files modified within N days
    #[arg(long, value_name = "DAYS")]
    modified_newer_than: Option<u64>,

    /// Files whose ctime is older than N days
    #[arg(long, value_name = "DAYS")]
    changed_older_than: Option<u64>,

    /// Files whose ctime is within N days
    #[arg(long, value_name = "DAYS")]
    changed_newer_than: Option<u64>,

    /// Filter by owner user ID
    #[arg(long, value_name = "UID")]
    uid: Option<u32>,

    /// Filter by owner group ID
    #[arg(long, value_name = "GID")]
    gid: Option<u32>,

    /// Filter by exact file mode bits (decimal integer, e.g. 33188 for 0o100644)
    #[arg(long, value_name = "MODE")]
    mode: Option<u32>,

    /// Comma-separated list of fields to output: path, size, atime, mtime, ctime, uid, gid, mode
    #[arg(short, long, default_value = "path", value_name = "FIELDS")]
    format: String,

    /// Output as CSV with a header row (raw values). Default is human-readable tab-separated.
    #[arg(long)]
    csv: bool,

    /// Limit number of results
    #[arg(short, long)]
    limit: Option<usize>,

    /// Count matching records instead of listing them
    #[arg(short, long)]
    count: bool,

    /// Show top N partitions by file count (for identifying large partitions)
    #[arg(long, value_name = "N")]
    top: Option<usize>,
}

/// Format a Unix epoch timestamp as "YYYY-MM-DD HH:MM:SS".
fn format_timestamp(epoch: i64) -> String {
    match DateTime::from_timestamp(epoch, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => epoch.to_string(),
    }
}

/// Escape and quote a value for CSV output if needed.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Read and format a single field value from a DuckDB row.
fn read_field(field: &str, row: &duckdb::Row, col_idx: usize, human: bool) -> Result<String> {
    Ok(match field {
        "path" => {
            let v: String = row.get(col_idx)?;
            v
        }
        "size" => {
            let v: i64 = row.get(col_idx)?;
            if human { format_bytes(v as u64) } else { v.to_string() }
        }
        "atime" | "mtime" | "ctime" => {
            let v: i64 = row.get(col_idx)?;
            if human { format_timestamp(v) } else { v.to_string() }
        }
        "uid" | "gid" => {
            let v: i32 = row.get(col_idx)?;
            v.to_string()
        }
        "mode" => {
            let v: i32 = row.get(col_idx)?;
            if human { format!("{:o}", v) } else { v.to_string() }
        }
        _ => unreachable!("field validated earlier: {}", field),
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse and validate field list
    let fields: Vec<&str> = args.format.split(',').map(|s| s.trim()).collect();
    for f in &fields {
        if !VALID_FIELDS.contains(f) {
            anyhow::bail!(
                "Unknown field '{}'. Valid fields: {}",
                f,
                VALID_FIELDS.join(", ")
            );
        }
    }

    // Resolve index path
    let index_path = args.index.canonicalize()
        .with_context(|| format!("Index directory not found: {}", args.index.display()))?;

    // Build the glob pattern for Parquet files
    let glob_pattern = sql_quote(&index_glob(&index_path, args.partition.as_deref()));

    // Connect to DuckDB (in-memory)
    let conn = Connection::open_in_memory()?;

    // Build filters
    let filters = QueryFilters::new()
        .with_pattern(args.pattern.clone())
        .with_older_than(args.older_than)
        .with_newer_than(args.newer_than)
        .with_mtime_older_than(args.modified_older_than)
        .with_mtime_newer_than(args.modified_newer_than)
        .with_ctime_older_than(args.changed_older_than)
        .with_ctime_newer_than(args.changed_newer_than)
        .with_uid(args.uid)
        .with_gid(args.gid)
        .with_mode(args.mode)
        .with_min_size(args.min_size.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?
        .with_max_size(args.max_size.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?;

    let where_clause = filters.to_full_where_clause();

    let limit_clause = if let Some(n) = args.limit {
        format!("LIMIT {}", n)
    } else {
        String::new()
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();

    // --top mode
    if let Some(n) = args.top {
        let sql = format!(
            "SELECT
                {} as partition,
                COUNT(*) as file_count
            FROM read_parquet({}, filename=true) {}
            GROUP BY partition
            ORDER BY file_count DESC
            LIMIT {}",
            partition_key_sql(&index_path), glob_pattern, where_clause, n
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let partition: String = row.get(0)?;
            writeln!(out, "{}", partition)?;
        }
        return Ok(());
    }

    // --count mode
    if args.count {
        let sql = format!(
            "SELECT COUNT(*) FROM read_parquet({}) {}",
            glob_pattern, where_clause
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let count: i64 = row.get(0)?;
            writeln!(out, "{}", count)?;
        }
        return Ok(());
    }

    // Build SELECT query from requested fields
    let select_clause = fields.join(", ");
    let sql = format!(
        "SELECT {} FROM read_parquet({}) {} {}",
        select_clause, glob_pattern, where_clause, limit_clause
    );

    let human = !args.csv;

    // CSV header
    if args.csv {
        writeln!(out, "{}", fields.join(","))?;
    }

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(fields.len());
        for (i, field) in fields.iter().enumerate() {
            let v = read_field(field, row, i, human)?;
            values.push(v);
        }

        if args.csv {
            let escaped: Vec<String> = fields.iter().zip(values.iter()).map(|(f, v)| {
                if *f == "path" { csv_escape(v) } else { v.clone() }
            }).collect();
            writeln!(out, "{}", escaped.join(","))?;
        } else {
            writeln!(out, "{}", values.join("\t"))?;
        }
    }

    Ok(())
}
