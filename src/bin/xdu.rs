#![allow(clippy::too_many_arguments)]

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{stderr, IsTerminal};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arrow::array::{Int32Array, Int64Array, StringBuilder};
use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use clap::Parser;
use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use jwalk::{Parallelism, WalkDir};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use rayon::ThreadPoolBuilder;

use xdu::{
    format_bytes, format_count, format_speed, get_schema, list_partitions, parse_size, resolve_split_points,
    FileRecord, Manifest, SizeMode, SplitSpec, MANIFEST_VERSION, ROOT_PARTITION,
};

#[derive(Parser, Debug)]
#[command(
    name = "xdu",
    about = "Build a distributed file metadata index in Parquet format",
    after_help = "\
Examples:
  xdu /data/scratch -o /index/scratch -j 8
  xdu /data/scratch -o /index/scratch --partition alice,bob
  xdu /data/scratch -o /index/scratch --split 'projects/*'
  xdu /data/scratch -o /index/scratch --split-depth 2
  xdu /data/scratch -o /index/scratch --apparent-size
  xdu /data/scratch -o /index/scratch --block-size 128K

Partitioning:
  Each split point (a directory relative to DIR) gets its own partition, stored in
  OUTDIR/<path>/. A file goes to the deepest split point containing it; files directly
  in DIR go to OUTDIR/__root__/. By default every top-level directory is a split point.
  The split settings are saved in OUTDIR/_xdu.json and reused by later runs."
)]
struct Args {
    /// Top-level directory to index
    #[arg(value_name = "DIR")]
    dir: PathBuf,

    /// Output directory for the Parquet index
    #[arg(short, long, value_name = "DIR")]
    outdir: PathBuf,

    /// Number of parallel threads
    #[arg(short, long, default_value = "4", env = "XDU_JOBS")]
    jobs: usize,

    /// Number of records per output chunk
    #[arg(short = 'B', long, default_value = "100000")]
    buffsize: usize,

    /// Report apparent sizes (file length) rather than disk usage.
    /// By default, xdu reports actual disk usage from st_blocks.
    #[arg(long)]
    apparent_size: bool,

    /// Round sizes up to this block size (e.g., 128K, 1M).
    /// Useful when st_blocks is inaccurate (e.g., over NFS) and you know the filesystem block size.
    /// Implies --apparent-size for the base size, then rounds up.
    #[arg(short = 'k', long, value_name = "SIZE")]
    block_size: Option<String>,

    /// Index only specific partitions (comma-separated, e.g. alice,projects/big, or __root__).
    #[arg(short, long, value_name = "NAMES", value_delimiter = ',')]
    partition: Option<Vec<String>>,

    /// With --partition, also re-index the partitions nested below the given ones.
    #[arg(short, long, requires = "partition")]
    recursive: bool,

    /// Make every directory down to depth N its own partition (0 = only --split paths).
    /// [default: the existing index's setting, or 1]
    #[arg(long, value_name = "N")]
    split_depth: Option<usize>,

    /// Extra directories to make their own partitions (relative to DIR, comma-separated).
    /// `*` and `?` match within a path component, e.g. 'projects/*'.
    #[arg(long, value_name = "PATHS", value_delimiter = ',')]
    split: Vec<String>,

    /// Read --split paths from a file (one per line; blank lines and # comments ignored).
    #[arg(long, value_name = "FILE")]
    split_file: Option<PathBuf>,
}

/// Per-partition buffer that accumulates records and flushes to Parquet.
struct PartitionBuffer {
    partition: String,
    outdir: PathBuf,
    records: Vec<FileRecord>,
    buffsize: usize,
    chunk_counter: usize,
    schema: Arc<Schema>,
    /// Track all .partial files written for atomic finalization
    partial_files: Vec<PathBuf>,
    /// Track statistics for this partition
    file_count: u64,
    byte_count: u64,
}

impl PartitionBuffer {
    fn new(partition: String, outdir: PathBuf, buffsize: usize, schema: Arc<Schema>) -> Self {
        Self {
            partition,
            outdir,
            records: Vec::with_capacity(buffsize),
            buffsize,
            chunk_counter: 0,
            schema,
            partial_files: Vec::new(),
            file_count: 0,
            byte_count: 0,
        }
    }

    fn add(&mut self, record: FileRecord) -> Result<()> {
        self.file_count += 1;
        self.byte_count += record.size as u64;
        self.records.push(record);
        if self.records.len() >= self.buffsize {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.records.is_empty() {
            return Ok(());
        }

        let chunk_id = self.chunk_counter;
        self.chunk_counter += 1;
        let partition_dir = self.outdir.join(&self.partition);
        fs::create_dir_all(&partition_dir)
            .with_context(|| format!("Failed to create partition dir: {}", partition_dir.display()))?;

        // Write to .partial file first
        let partial_path = partition_dir.join(format!("{:06}.parquet.partial", chunk_id));

        let mut path_builder = StringBuilder::new();
        let mut size_builder  = Vec::with_capacity(self.records.len());
        let mut atime_builder = Vec::with_capacity(self.records.len());
        let mut mtime_builder = Vec::with_capacity(self.records.len());
        let mut ctime_builder = Vec::with_capacity(self.records.len());
        let mut uid_builder   = Vec::with_capacity(self.records.len());
        let mut gid_builder   = Vec::with_capacity(self.records.len());
        let mut mode_builder  = Vec::with_capacity(self.records.len());

        for record in &self.records {
            path_builder.append_value(&record.path);
            size_builder.push(record.size);
            atime_builder.push(record.atime);
            mtime_builder.push(record.mtime);
            ctime_builder.push(record.ctime);
            uid_builder.push(record.uid as i32);
            gid_builder.push(record.gid as i32);
            mode_builder.push(record.mode as i32);
        }

        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(path_builder.finish()),
                Arc::new(Int64Array::from(size_builder)),
                Arc::new(Int64Array::from(atime_builder)),
                Arc::new(Int64Array::from(mtime_builder)),
                Arc::new(Int64Array::from(ctime_builder)),
                Arc::new(Int32Array::from(uid_builder)),
                Arc::new(Int32Array::from(gid_builder)),
                Arc::new(Int32Array::from(mode_builder)),
            ],
        )?;

        let file = File::create(&partial_path)
            .with_context(|| format!("Failed to create file: {}", partial_path.display()))?;

        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();

        let mut writer = ArrowWriter::try_new(file, self.schema.clone(), Some(props))?;
        writer.write(&batch)?;
        writer.close()?;

        self.partial_files.push(partial_path);
        self.records.clear();
        Ok(())
    }

    /// Atomically finalize all .partial files by renaming them and pruning stale chunks.
    fn finalize(&self) -> Result<usize> {
        let partition_dir = self.outdir.join(&self.partition);
        let num_chunks = self.partial_files.len();

        // Rename all .partial files to .parquet (atomic on POSIX)
        for partial_path in &self.partial_files {
            let final_path = partial_path.with_extension(""); // removes .partial, leaves .parquet
            fs::rename(partial_path, &final_path)
                .with_context(|| format!("Failed to rename {} to {}", partial_path.display(), final_path.display()))?;
        }

        // Prune any stale chunks beyond what we just wrote
        let mut pruned = 0;
        for chunk_id in num_chunks.. {
            let stale_path = partition_dir.join(format!("{:06}.parquet", chunk_id));
            if stale_path.exists() {
                fs::remove_file(&stale_path)
                    .with_context(|| format!("Failed to remove stale chunk: {}", stale_path.display()))?;
                pruned += 1;
            } else {
                break; // No more consecutive chunks
            }
        }

        Ok(pruned)
    }
}

/// A unit of work for a driver thread: one partition to crawl.
struct WorkItem {
    path: PathBuf,
    partition: String,
    /// Depth of `path` below the crawl root.
    depth: usize,
}

/// Split-point directories, which every walker must skip (they are crawled separately).
struct SplitDirs {
    paths: HashSet<PathBuf>,
    /// Deepest split point below the crawl root; walkers stop checking below this.
    max_depth: usize,
}

/// Statistics returned from a crawl operation.
struct CrawlStats {
    files: u64,
    bytes: u64,
    pruned: usize,
}

/// Crawl a directory tree using concurrent per-partition walks with a shared thread pool.
///
/// Architecture: A shared rayon thread pool (N threads) handles directory reads across all
/// active walkers. C driver threads (std::threads) each pull partitions from a work queue
/// and iterate their walker. Rayon work-stealing naturally balances load across all active
/// walkers. Thread budget: N pool + C drivers + 1 main.
fn crawl(
    top_dir: &Path,
    outdir: &Path,
    jobs: usize,
    buffsize: usize,
    size_mode: SizeMode,
    schema: &Arc<Schema>,
    work_queue: VecDeque<WorkItem>,
    split_dirs: Arc<SplitDirs>,
    filter_desc: &str,
    is_tty: bool,
) -> Result<CrawlStats> {
    // Build shared rayon thread pool for jwalk walkers
    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build()
            .context("Failed to build thread pool")?
    );

    let num_items = work_queue.len();
    if num_items == 0 {
        anyhow::bail!("No partitions found in {}", top_dir.display());
    }

    // Progress display
    let mp = MultiProgress::new();
    if !is_tty {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }

    if is_tty {
        eprintln!("{:>12} {}{}", style("Indexing").green().bold(), top_dir.display(), filter_desc);
    } else {
        eprintln!("Indexing {}{}", top_dir.display(), filter_desc);
    }

    // Global summary bar (positioned last, below per-partition bars)
    let global_style = ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap();
    let global_bar = mp.add(ProgressBar::new_spinner());
    global_bar.set_style(global_style);
    global_bar.enable_steady_tick(Duration::from_millis(200));

    // Shared state for cross-thread aggregation
    let queue = Arc::new(Mutex::new(work_queue));
    let global_files = Arc::new(AtomicU64::new(0));
    let global_bytes = Arc::new(AtomicU64::new(0));
    let global_pruned = Arc::new(AtomicUsize::new(0));

    // Global speed tracking (shared across drivers, protected by single Mutex)
    let global_speed_state = Arc::new(Mutex::new((
        Instant::now(),  // last sample time
        0_u64,           // last sample file count
        0.0_f64,         // current speed
        0.0_f64,         // peak speed
    )));

    let num_drivers = jobs.min(num_items).max(1);

    std::thread::scope(|s| -> Result<()> {
        let handles: Vec<_> = (0..num_drivers)
            .map(|driver_id| {
                let pool = pool.clone();
                let queue = queue.clone();
                let global_files = global_files.clone();
                let global_bytes = global_bytes.clone();
                let global_pruned = global_pruned.clone();
                let global_speed_state = global_speed_state.clone();
                let schema = schema.clone();
                let mp_ref = &mp;
                let global_bar_ref = &global_bar;
                let outdir = outdir.to_path_buf();
                let split_dirs = split_dirs.clone();

                s.spawn(move || -> Result<()> {
                    let bar_style = ProgressStyle::default_spinner()
                        .template("{spinner:.cyan} {msg}")
                        .unwrap();
                    let bar = mp_ref.insert_before(global_bar_ref, ProgressBar::new_spinner());
                    bar.set_style(bar_style);
                    bar.enable_steady_tick(Duration::from_millis(100));

                    loop {
                        let item = {
                            let mut q = queue.lock().unwrap();
                            q.pop_front()
                        };
                        let item = match item {
                            Some(i) => i,
                            None => break,
                        };

                        bar.set_message(format!("{}: scanning...", item.partition));

                        // Leave split-point subdirectories to their own work items.
                        let skip = split_dirs.clone();
                        let base_depth = item.depth;
                        let walker = WalkDir::new(&item.path)
                            .parallelism(Parallelism::RayonExistingPool {
                                pool: pool.clone(),
                                busy_timeout: None,
                            })
                            .skip_hidden(false)
                            .follow_links(false)
                            .process_read_dir(move |depth, dir, _, children| {
                                // `depth` is None for the walk root itself, which must be kept.
                                let Some(depth) = depth else { return };
                                if base_depth + depth + 1 > skip.max_depth {
                                    return;
                                }
                                children.retain(|child| match child {
                                    Ok(e) => !(e.file_type.is_dir() && skip.paths.contains(&dir.join(&e.file_name))),
                                    Err(_) => true,
                                });
                            });

                        let mut buffer = PartitionBuffer::new(
                            item.partition.clone(),
                            outdir.clone(),
                            buffsize,
                            schema.clone(),
                        );

                        let mut last_bar_update = Instant::now();
                        let bar_interval = Duration::from_millis(100);

                        // Per-partition speed tracking (1s rolling window)
                        let mut speed_sample_count: u64 = 0;
                        let mut speed_sample_time = Instant::now();
                        let mut current_speed: f64 = 0.0;
                        let mut peak_speed: f64 = 0.0;

                        for entry in walker {
                            let entry = match entry {
                                Ok(e) => e,
                                Err(_) => continue,
                            };

                            if !entry.file_type.is_file() {
                                continue;
                            }

                            let metadata = match fs::metadata(entry.path()) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };

                            let disk_usage = metadata.blocks() * 512;
                            let file_len = metadata.len();
                            let atime = metadata.atime();
                            let mtime = metadata.mtime();
                            let ctime = metadata.ctime();
                            let uid   = metadata.uid();
                            let gid   = metadata.gid();
                            let mode  = metadata.mode();
                            let file_size = size_mode.calculate(disk_usage, file_len);

                            let record = FileRecord {
                                path: entry.path().to_string_lossy().to_string(),
                                size: file_size as i64,
                                atime,
                                mtime,
                                ctime,
                                uid,
                                gid,
                                mode,
                            };

                            buffer.add(record)?;

                            // Update global atomics
                            global_files.fetch_add(1, Ordering::Relaxed);
                            global_bytes.fetch_add(file_size, Ordering::Relaxed);

                            // Update progress bars periodically
                            let now = Instant::now();
                            if now.duration_since(last_bar_update) >= bar_interval {
                                // Per-partition speed: 1-second rolling window
                                let speed_elapsed = now.duration_since(speed_sample_time).as_secs_f64();
                                if speed_elapsed >= 1.0 {
                                    let delta = buffer.file_count - speed_sample_count;
                                    current_speed = delta as f64 / speed_elapsed;
                                    if current_speed > peak_speed {
                                        peak_speed = current_speed;
                                    }
                                    speed_sample_count = buffer.file_count;
                                    speed_sample_time = now;
                                }

                                // Global speed: 1-second rolling window
                                let total_files = global_files.load(Ordering::Relaxed);
                                let global_speed_str = {
                                    let mut gs = global_speed_state.lock().unwrap();
                                    let g_elapsed = now.duration_since(gs.0).as_secs_f64();
                                    if g_elapsed >= 1.0 {
                                        let g_delta = total_files.saturating_sub(gs.1);
                                        gs.2 = g_delta as f64 / g_elapsed;
                                        if gs.2 > gs.3 {
                                            gs.3 = gs.2;
                                        }
                                        gs.0 = now;
                                        gs.1 = total_files;
                                    }
                                    if gs.2 > 0.0 {
                                        format!(
                                            " | {} (peak: {})",
                                            format_speed(gs.2),
                                            format_speed(gs.3)
                                        )
                                    } else {
                                        String::new()
                                    }
                                };

                                let speed_str = if current_speed > 0.0 {
                                    format!(
                                        " | {} (peak: {})",
                                        format_speed(current_speed),
                                        format_speed(peak_speed)
                                    )
                                } else {
                                    String::new()
                                };

                                bar.set_message(format!(
                                    "{}: {} files, {}{} [T{}]",
                                    item.partition,
                                    format_count(buffer.file_count),
                                    format_bytes(buffer.byte_count),
                                    speed_str,
                                    driver_id,
                                ));
                                global_bar_ref.set_message(format!(
                                    "{} files, {}{}",
                                    format_count(total_files),
                                    format_bytes(global_bytes.load(Ordering::Relaxed)),
                                    global_speed_str,
                                ));
                                last_bar_update = now;
                            }
                        }

                        buffer.flush()?;
                        let pruned = buffer.finalize()?;
                        global_pruned.fetch_add(pruned, Ordering::Relaxed);

                        let prune_info = if pruned > 0 {
                            format!(", pruned {} stale", pruned)
                        } else {
                            String::new()
                        };

                        if is_tty {
                            mp_ref.println(format!(
                                "{:>12} {} ({} files, {}{})",
                                style("Finished").green().bold(),
                                item.partition,
                                format_count(buffer.file_count),
                                format_bytes(buffer.byte_count),
                                prune_info,
                            ))?;
                        } else {
                            eprintln!(
                                "Finished {} ({} files, {}{})",
                                item.partition,
                                format_count(buffer.file_count),
                                format_bytes(buffer.byte_count),
                                prune_info,
                            );
                        }
                    }

                    bar.finish_and_clear();
                    Ok(())
                })
            })
            .collect();

        // Wait for all drivers and propagate errors
        let mut first_error: Option<anyhow::Error> = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error = Some(anyhow::anyhow!("Driver thread panicked"));
                    }
                }
            }
        }

        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(())
    })?;

    global_bar.finish_and_clear();

    Ok(CrawlStats {
        files: global_files.load(Ordering::Relaxed),
        bytes: global_bytes.load(Ordering::Relaxed),
        pruned: global_pruned.load(Ordering::Relaxed),
    })
}

/// Name of a size mode, as recorded in the manifest.
fn size_mode_name(mode: SizeMode) -> String {
    match mode {
        SizeMode::DiskUsage => "disk-usage".to_string(),
        SizeMode::ApparentSize => "apparent-size".to_string(),
        SizeMode::BlockRounded(n) => format!("block-rounded:{}", n),
    }
}

/// True for chunk files written by xdu (`NNNNNN.parquet`).
fn is_chunk_file(name: &str) -> bool {
    name.strip_suffix(".parquet")
        .is_some_and(|stem| stem.len() == 6 && stem.bytes().all(|b| b.is_ascii_digit()))
}

/// Delete the chunk files of one partition, then any directories left empty up to the index root.
/// Returns the number of chunks removed.
fn remove_partition_chunks(outdir: &Path, key: &str) -> Result<usize> {
    let dir = outdir.join(key);
    let mut removed = 0;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && is_chunk_file(&entry.file_name().to_string_lossy()) {
            fs::remove_file(entry.path())
                .with_context(|| format!("Failed to remove stale chunk: {}", entry.path().display()))?;
            removed += 1;
        }
    }
    let mut d = dir.as_path();
    while d != outdir && fs::remove_dir(d).is_ok() {
        match d.parent() {
            Some(p) => d = p,
            None => break,
        }
    }
    Ok(removed)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start_time = Instant::now();
    let is_tty = stderr().is_terminal();

    // Determine size calculation mode
    let size_mode = if let Some(ref bs) = args.block_size {
        let block_size = parse_size(bs).map_err(|e| anyhow::anyhow!(e))? as u64;
        SizeMode::BlockRounded(block_size)
    } else if args.apparent_size {
        SizeMode::ApparentSize
    } else {
        SizeMode::DiskUsage
    };

    let top_dir = args.dir.canonicalize()
        .with_context(|| format!("Failed to resolve directory: {}", args.dir.display()))?;

    fs::create_dir_all(&args.outdir)
        .with_context(|| format!("Failed to create output directory: {}", args.outdir.display()))?;

    let outdir = args.outdir.canonicalize()?;

    let schema = get_schema();

    // Decide the split spec: command line, else the existing index's, else the default.
    let existing = Manifest::load(&outdir)?;
    let existing_spec = existing.as_ref().map(|m| m.split.clone()).unwrap_or_default();
    let mut patterns = args.split.clone();
    if let Some(ref file) = args.split_file {
        let text = fs::read_to_string(file)
            .with_context(|| format!("Failed to read split file: {}", file.display()))?;
        patterns.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }
    let spec = if args.split_depth.is_some() || !patterns.is_empty() {
        SplitSpec { depth: args.split_depth.unwrap_or(1), patterns }.normalized()
    } else {
        existing_spec.normalized()
    };

    let existing_partitions = list_partitions(&outdir)?;
    if args.partition.is_some() && !existing_partitions.is_empty() && !spec.same_layout(&existing_spec) {
        anyhow::bail!(
            "The split settings differ from those of the existing index in {}; \
             run without --partition to rebuild it with the new layout",
            outdir.display()
        );
    }
    let size_mode_str = size_mode_name(size_mode);
    if let Some(ref m) = existing
        && args.partition.is_some()
        && !m.size_mode.is_empty()
        && m.size_mode != size_mode_str
    {
        eprintln!("warning: existing index uses size mode '{}', this run uses '{}'", m.size_mode, size_mode_str);
    }

    let (split_points, warnings) = resolve_split_points(&top_dir, &spec)?;
    for w in &warnings {
        eprintln!("warning: {}", w);
    }

    // One work item per partition: the root, then each split point.
    let mut items: Vec<WorkItem> = vec![WorkItem { path: top_dir.clone(), partition: ROOT_PARTITION.to_string(), depth: 0 }];
    items.extend(split_points.iter().map(|key| WorkItem {
        path: top_dir.join(key),
        partition: key.clone(),
        depth: key.split('/').count(),
    }));

    let split_dirs = Arc::new(SplitDirs {
        paths: split_points.iter().map(|key| top_dir.join(key)).collect(),
        max_depth: split_points.iter().map(|key| key.split('/').count()).max().unwrap_or(0),
    });

    // Restrict to the requested partitions, if any.
    let filter_desc = if let Some(ref wanted) = args.partition {
        let wanted: Vec<String> = wanted.iter().map(|p| p.trim_matches('/').to_string()).collect();
        for w in &wanted {
            if !items.iter().any(|i| &i.partition == w) {
                anyhow::bail!("Partition '{}' is not a split point in {}", w, top_dir.display());
            }
        }
        items.retain(|i| {
            wanted.iter().any(|w| {
                &i.partition == w
                    || (args.recursive && w != ROOT_PARTITION && i.partition.starts_with(&format!("{}/", w)))
            })
        });
        let names: Vec<&str> = items.iter().map(|i| i.partition.as_str()).collect();
        format!(" (partitions: {})", names.join(", "))
    } else {
        String::new()
    };

    let stats = crawl(
        &top_dir,
        &outdir,
        args.jobs,
        args.buffsize,
        size_mode,
        &schema,
        items.into_iter().collect(),
        split_dirs,
        &filter_desc,
        is_tty,
    )?;

    // A full crawl owns the whole index: drop partitions that are no longer split points.
    if args.partition.is_none() {
        let keep: HashSet<&str> = split_points.iter().map(String::as_str).chain([ROOT_PARTITION]).collect();
        for key in &existing_partitions {
            if !keep.contains(key.as_str()) {
                let n = remove_partition_chunks(&outdir, key)?;
                if n > 0 {
                    eprintln!("Removed stale partition {} ({} chunks)", key, n);
                }
            }
        }
    }

    Manifest {
        version: MANIFEST_VERSION,
        root: top_dir.to_string_lossy().to_string(),
        split: spec,
        size_mode: size_mode_str,
    }
    .save(&outdir)
    .with_context(|| format!("Failed to write manifest in {}", outdir.display()))?;

    let elapsed = start_time.elapsed();
    let prune_info = if stats.pruned > 0 { format!(", pruned {} stale", stats.pruned) } else { String::new() };

    if is_tty {
        eprintln!("{:>12} {} files ({}) in {:.2}s{}",
            style("Completed").green().bold(),
            format_count(stats.files),
            format_bytes(stats.bytes),
            elapsed.as_secs_f64(),
            prune_info
        );
    } else {
        eprintln!("Completed {} files ({}) in {:.2}s{}", format_count(stats.files), format_bytes(stats.bytes), elapsed.as_secs_f64(), prune_info);
    }

    Ok(())
}
