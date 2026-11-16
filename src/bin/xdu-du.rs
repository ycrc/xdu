use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;
use duckdb::params_from_iter;

use xdu::cli::XduDuArgs;
use xdu::layout::top_level_key_sql;
use xdu::{IndexLocator, format_bytes, open_index, parquet_source};

fn fmt_size(bytes: i64, human: bool) -> String {
    if human {
        format_bytes(bytes.max(0) as u64)
    } else {
        bytes.to_string()
    }
}

fn main() -> Result<()> {
    let args = XduDuArgs::parse();
    let (index, conn) = open_index(&args.index)?;
    if let IndexLocator::Local(ref path) = index {
        xdu::note_unreadable(path, args.partition.as_deref())?;
    }
    let source = |filename: bool| parquet_source(&index, args.partition.as_deref(), filename);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut grand_total: i64 = 0;

    if args.paths.is_empty() && args.summarize {
        let (from, params) = source(false);
        let sql = format!("SELECT COALESCE(SUM(size), 0)::BIGINT FROM {from}");
        let total: i64 = conn.query_row(&sql, params_from_iter(&params), |r| r.get(0))?;
        grand_total = total;
        writeln!(out, "{}\t.", fmt_size(total, args.human_readable))?;
    } else if args.paths.is_empty() {
        // One line per top-level directory, nested partitions folded in.
        let (from, params) = source(true);
        let sql = format!(
            "SELECT {} AS partition, COALESCE(SUM(size), 0)::BIGINT AS total_size \
             FROM {from} \
             GROUP BY partition \
             HAVING partition IS NOT NULL AND partition != '' \
             ORDER BY partition",
            top_level_key_sql(&index)
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params_from_iter(&params))?;
        while let Some(row) = rows.next()? {
            let partition: String = row.get(0)?;
            let size: i64 = row.get(1)?;
            grand_total += size;
            writeln!(
                out,
                "{}\t{}",
                fmt_size(size, args.human_readable),
                partition
            )?;
        }
    } else {
        // The prefix is bound, never written into the text: a path may hold a quote, and
        // `LIKE` would read `%` and `_` in it as wildcards.
        let (from, source_params) = source(false);
        let sql = format!(
            "SELECT COALESCE(SUM(size), 0)::BIGINT FROM {from} \
             WHERE path = ? OR starts_with(path, ?)"
        );
        for path in &args.paths {
            let path = path.trim_end_matches('/');
            let mut params = source_params.clone();
            params.push(path.to_string());
            params.push(format!("{path}/"));
            let size: i64 = conn.query_row(&sql, params_from_iter(&params), |r| r.get(0))?;
            grand_total += size;
            writeln!(out, "{}\t{}", fmt_size(size, args.human_readable), path)?;
        }
    }

    if args.total {
        writeln!(out, "{}\ttotal", fmt_size(grand_total, args.human_readable))?;
    }

    Ok(())
}
