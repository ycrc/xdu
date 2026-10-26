<div align="center">

# xdu

**High-performance file system indexer for large-scale storage administration**

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/glentner/xdu)](https://github.com/glentner/xdu/releases)
[![Tests](https://img.shields.io/github/actions/workflow/status/glentner/xdu/test.yaml?branch=main&label=tests)](https://github.com/glentner/xdu/actions/workflows/test.yaml)

</div>

Builds Hive-partitioned Parquet indexes for instant analytics on filesystems with hundreds of millions of files.

## Motivation

System administrators managing large shared storage (e.g., HPC clusters, research computing, NAS appliances) need to regularly audit disk usage and file access patterns. Common tasks include:

- Identifying users consuming excessive space
- Finding stale data for purge policies
- Generating usage reports by user or project
- Enforcing quotas and retention policies

Traditional tools like `du` and `find` are designed for interactive, one-off queries. They re-traverse the filesystem every time, which is prohibitively slow on systems with hundreds of millions of files. They also produce flat text output that's difficult to analyze at scale.

**xdu** solves this by building a persistent, queryable index once—then enabling instant analytics via the included `xdu-find` command, interactive exploration with `xdu-view`, or external tools like DuckDB, Polars, or Apache Spark.

## Design

### Hive-Partitioned Output

By default the index is partitioned by top-level subdirectory (large directories can be
split further; see [Nested Partitions](#nested-partitions)). For a `/home` filesystem:

```
index/
├── alice/
│   ├── 000000.parquet
│   └── 000001.parquet
├── bob/
│   └── 000000.parquet
└── charlie/
    └── 000000.parquet
```

This layout enables:
- **Partition pruning**: Query a single user's data without scanning the entire index
- **Parallel writes**: Each partition is processed independently
- **Incremental updates**: Re-index individual partitions without rebuilding everything

Files directly in the top-level directory go to `index/__root__/`. The index also
contains `_xdu.json`, which records the crawl root and the split settings.

### Nested Partitions

When one top-level directory is much larger than the others, it can be split further.
Each *split point* (a directory, relative to the crawled directory) gets its own
partition at `index/<path>/`, and each file goes to the deepest split point containing it:

```bash
xdu /data -o /index/data --split 'projects/big,projects/big/*'
```

```
index/
├── _xdu.json
├── __root__/000000.parquet         files directly in /data
├── alice/000000.parquet            all of /data/alice
├── projects/000000.parquet         /data/projects, except projects/big
├── projects/big/000000.parquet     files directly in projects/big
├── projects/big/x/000000.parquet   all of projects/big/x
└── projects/big/y/000000.parquet   all of projects/big/y
```

- By default every top-level directory is a split point (`--split-depth 1`).
  `--split-depth 2` splits every second-level directory too; `--split-depth 0` keeps
  only the `--split` paths.
- `--split` paths may use `*` and `?` within a component. `--split-file` reads them from
  a file, one per line. Wildcards never cross a `/`, so `'a/*'` means the children of `a`.
  For grandchildren too, write `'a/*,a/*/*'`. `**` is rejected. Quote patterns so the
  shell doesn't expand them.
- A split path must be a real directory. xdu never follows symlinks, so a path through a
  symlink is rejected with an error naming the link. Nothing below a symlink is indexed anyway.
- The settings are saved in `_xdu.json`, so later runs (including `-p` re-indexes) reuse them.
  Changing them requires a full run, which removes partitions that are no longer split points.
- Split finely enough to balance the work, but keep the partition count modest: thousands of
  tiny Parquet files make queries slower.
- `xdu-find`, `xdu-du` and `xdu-rm` accept nested paths for `-u` and include everything
  below them. `xdu-du` and `xdu-view` group nested partitions under their top-level directory.
- `xdu-diff` compares partition by partition when both indices have the same split settings,
  and whole top-level directories otherwise.

### Schema

| Column | Type  | Description                    |
|--------|-------|--------------------------------|
| path   | UTF-8 | Absolute file path             |
| size   | INT64 | File size in bytes             |
| atime  | INT64 | Last access time (Unix epoch)  |

### Performance

**Why xdu is faster than `du` for this use-case:**

1. **Adaptive parallel traversal**: Using jwalk, threads dynamically balance work at every directory level—no partition gets bottlenecked to a single thread
2. **Parallel metadata**: File stat() calls happen in parallel within the thread pool, critical for high-latency network filesystems
3. **Columnar storage**: Parquet compresses paths efficiently (often 10:1) and enables predicate pushdown
4. **Buffered writes**: Records accumulate in memory before flushing, minimizing I/O syscalls
5. **One traversal, many queries**: Build the index once, query it thousands of times instantly

A typical 100M file filesystem might take 2-3 hours to `du`. With xdu, the index builds in 20-30 minutes and subsequent queries complete in seconds.

## Installation

### Quick Install (Recommended)

```bash
curl -sSfL https://raw.githubusercontent.com/glentner/xdu/main/install.sh | sh
```

This downloads the latest release binary for your platform and installs it to `~/.local/bin`.

**Options:**
- `XDU_VERSION=v0.1.0` — Install a specific version
- `XDU_INSTALL=/usr/local/bin` — Change install directory

### From Source

```bash
cargo install --git https://github.com/glentner/xdu.git
```

Requires [Rust](https://rustup.rs) nightly toolchain.

## Usage

### Building an Index

```bash
xdu /home -o /var/lib/xdu/home -j 16 -b 100000
```

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --outdir` | Output directory for index | Required |
| `-j, --jobs` | Parallel threads (`XDU_JOBS` env) | 4 |
| `-B, --buffsize` | Records per Parquet chunk | 100000 |
| `-p, --partition` | Index only specific partitions (comma-separated, e.g. `alice,projects/big`) | All |
| `-r, --recursive` | With `-p`, also index partitions nested below those given | |
| `--split-depth` | Make every directory down to depth N a partition | 1, or the index's saved setting |
| `--split` | Extra partition directories, relative to DIR (comma-separated, `*` and `?` allowed) | |
| `--split-file` | Read `--split` paths from a file | |
| `--apparent-size` | Report file length instead of disk usage (st_blocks) | |
| `-k, --block-size` | Round sizes up to block size (e.g., `128K`). Implies `--apparent-size` | |

### Querying with xdu-find

The `xdu-find` command provides a convenient CLI for common queries:

```bash
# Find all Python files
xdu-find -i /var/lib/xdu/home -p '\.py$'

# Find large files (>1GB) not accessed in 90 days
xdu-find -i /var/lib/xdu/home --min-size 1G --older-than 90

# Query a specific user's partition, sorted by size
xdu-find -i /var/lib/xdu/home -u alice --min-size 100M -f size

# Count matching files
xdu-find -i /var/lib/xdu/home -p '\.tmp$' --older-than 30 --count

# Pipe to xargs for bulk operations
xdu-find -i /var/lib/xdu/home -p '\.tmp$' --older-than 30 | xargs rm
```

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-p, --pattern` | Regex pattern to match paths | |
| `-u, --partition` | Filter by partition (user directory, or a nested path like `projects/big`; includes everything below it) | |
| `--min-size` | Minimum file size (e.g., 1K, 10M, 1G) | |
| `--max-size` | Maximum file size | |
| `--older-than` | Files not accessed in N days | |
| `--newer-than` | Files accessed within N days | |
| `-f, --format` | Output format: path, size, atime, csv, json | path |
| `-l, --limit` | Limit number of results | |
| `-c, --count` | Count matching records | |

### Interactive Exploration with xdu-view

The `xdu-view` command provides an ncdu-style TUI for browsing the index interactively, with powerful filtering and sorting capabilities.

```bash
# Browse all partitions
xdu-view -i /var/lib/xdu/home

# Start in a specific partition
xdu-view -i /var/lib/xdu/home -u alice

# View only files not accessed in 30 days, sorted by size
xdu-view -i /var/lib/xdu/home --older-than 30 -s size-desc

# View large Python files (>1MB)
xdu-view -i /var/lib/xdu/home -p '\.py$' --min-size 1M

# See what changed since an earlier index, biggest growth first
xdu-view -i /var/lib/xdu/home-wed --compare /var/lib/xdu/home-mon -s delta
```

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-u, --partition` | Start in a specific partition (top-level directory, or a nested path) | |
| `-p, --pattern` | Regex pattern to filter paths | |
| `--min-size` | Minimum file size (e.g., 1K, 10M, 1G) | |
| `--max-size` | Maximum file size | |
| `--older-than` | Files not accessed in N days | |
| `--newer-than` | Files accessed within N days | |
| `-s, --sort` | Sort order (see below) | name |
| `--compare` | Earlier index to compare against (see [Comparing Two Indices](#comparing-two-indices)) | |

**Sort modes:** `name` (default, directories first), `size-desc`, `size-asc`, `count-desc`, `count-asc`, `age-desc` (oldest first), `age-asc` (newest first), and with `--compare`: `delta-desc` (largest growth first), `delta-asc` (largest shrink first)

#### Keybindings

**Navigation:**
| Key | Action |
|-----|--------|
| `↑`/`k` | Move selection up |
| `↓`/`j` | Move selection down |
| `→`/`Enter`/`Space` | Enter directory |
| `←`/`Backspace` | Go up / back |
| `q`/`Esc` | Quit |

**Sorting:**
| Key | Action |
|-----|--------|
| `s` | Open sort selector (use `↑↓`/`jk` to choose, `Enter` to confirm, `Esc` to cancel) |

**Filtering (interactive):**
| Key | Action |
|-----|--------|
| `/` | Set path pattern filter (regex) |
| `o` | Set older-than filter (days) |
| `n` | Set newer-than filter (days) |
| `>` | Set minimum size filter |
| `<` | Set maximum size filter |
| `c` | Clear all filters |
| `d` | Cycle changes shown: all/changed/added/removed/modified (with `--compare`) |

When entering a filter value, type the value and press `Enter` to apply, or `Esc` to cancel.

#### UI Elements

**Title bar** shows the current location and any active filters:
```
┌─ alice/projects [older:30d] [min:1.00 MiB] [/\.py$/] ─────────────────────┐
```

**Status bar** shows entry count, current sort mode, and available keybindings:
```
 42 entries in 0.15s (filtered) │ sort:size-desc │ q:quit jk:nav /:pattern ...
```

**List entries** show name, total size, file count, and most recent access time:
```
▸ src                          1.23 GiB    4.2K files    3 days ago
▸ tests                      128.50 MiB      892 files    1 month ago
  README.md                    4.50 KiB        1 file     today
```

#### Comparing Two Indices

With `--compare OLD`, `xdu-view` browses the `-i` index and shows how each entry changed
since `OLD`, matching files by path relative to each index's crawl root (as `xdu-diff` does).
Removed files and directories stay visible so shrinkage can be traced too.

```
  name                       size        Δsize        files  Δfiles   accessed
+ ▸ new-project          3.14 MiB    +3.14 MiB   6.5K files   +6.5K      today
~ ▸ QuotaTable         353.15 MiB  +384.00 KiB    307 files              today
- ▸ old-scratch               0 B   -12.00 GiB      0 files   -1.2K  1 month ago
  ▸ Spring              17.02 MiB                34.9K files         20 days ago
```

- Markers: `+` new, `-` gone, `~` changed (added, removed, or modified files inside)
- **Δsize** and **Δfiles** are green for growth and red for shrinkage; in tree view, Δsize replaces the file count
- `d` cycles which files are shown: all → changed → added → removed → modified
- Sort with `s` → `delta-desc` / `delta-asc`, then drill into the top entry to find where growth happened
- The tree view's file preview shows the file's previous size

#### Common Use Cases

**Find where old data is hiding:**
```bash
# Launch with 90-day stale filter, sorted by size
xdu-view -i /var/lib/xdu/home --older-than 90 -s size-desc
```
Drill down into the largest directories to find purgeable data.

**Audit a specific user's storage:**
```bash
# Jump directly to a user, show files >100MB
xdu-view -i /var/lib/xdu/home -u alice --min-size 100M
```

**Identify recently active directories:**
```bash
# Show only data accessed in the last 7 days
xdu-view -i /var/lib/xdu/home --newer-than 7 -s count-desc
```

**Find specific file types:**
```bash
# Explore all Jupyter notebooks
xdu-view -i /var/lib/xdu/home -p '\.ipynb$' -s size-desc
```

### Bulk Deletion with xdu-rm

The `xdu-rm` command enables safe, parallel deletion of files matching query criteria. This is essential for enforcing retention policies at scale—purging millions of stale files that traditional `find | xargs rm` workflows can't handle efficiently.

```bash
# Preview files that would be deleted (dry-run)
xdu-rm -i /var/lib/xdu/home --older-than 60 --dry-run

# Delete files not accessed in 60 days, with confirmation
xdu-rm -i /var/lib/xdu/home --older-than 60

# Delete with 16 parallel threads for faster purging
xdu-rm -i /var/lib/xdu/home --older-than 60 -j 16 --force

# Delete only .tmp files older than 30 days in alice's partition
xdu-rm -i /var/lib/xdu/home -u alice -p '\.tmp$' --older-than 30 --force
```

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-p, --pattern` | Regex pattern to match paths | |
| `-u, --partition` | Filter by partition (user directory, or a nested path like `projects/big`; includes everything below it) | |
| `--min-size` | Minimum file size (e.g., 1K, 10M, 1G) | |
| `--max-size` | Maximum file size | |
| `--older-than` | Files not accessed in N days | |
| `--newer-than` | Files accessed within N days | |
| `-l, --limit` | Maximum number of files to delete | |
| `-n, --dry-run` | Show what would be deleted without deleting | |
| `--safe` | Verify file metadata before deletion | |
| `-f, --force` | Skip confirmation prompt | |
| `-v, --verbose` | Show per-file deletion status | |
| `-j, --jobs` | Number of parallel threads | 4 |

#### Safe Mode: Protecting Recently Accessed Files

The `--safe` flag addresses a critical edge case: **the index may be stale**. If you built the index yesterday and a user accessed their "old" file today, the index still shows the old access time. Without `--safe`, that file would be incorrectly deleted.

With `--safe` enabled, `xdu-rm` performs a fresh `stat()` on each file immediately before deletion and verifies:

- **For `--older-than`**: The file's current atime is still older than the threshold
- **For `--max-size`**: The file's current size still meets the criteria

Files that no longer match are skipped:

```bash
# Safe deletion: re-check atime before each delete
xdu-rm -i /var/lib/xdu/home --older-than 60 --safe --force -v

# Output shows protected files:
# SKIP (accessed since index): /home/alice/important_data.csv
# DELETE: /home/bob/old_cache.tmp
# ...
# Deleted: 1,234,567
# Skipped (safe mode): 42
```

**When to use `--safe`:**
- Production purge workflows where data loss is unacceptable
- When the index is more than a few hours old
- When users may have accessed files between indexing and purging

**When `--safe` may not be needed:**
- Immediately after building a fresh index
- When deleting from a read-only ZFS snapshot (files can't change)
- For low-risk file types (e.g., `.tmp`, `.cache`)

#### Common Workflows

**Enforce 60-day retention policy:**
```bash
# Nightly cron job with safe mode
0 3 * * * xdu-rm -i /var/lib/xdu/home --older-than 60 --safe -j 16 --force >> /var/log/xdu-purge.log 2>&1
```

**Clean up scratch space aggressively:**
```bash
# Delete files older than 7 days, no safe mode needed for scratch
xdu-rm -i /var/lib/xdu/scratch --older-than 7 -j 32 --force
```

**Targeted cleanup by file type:**
```bash
# Remove old Jupyter checkpoints
xdu-rm -i /var/lib/xdu/home -p '/\.ipynb_checkpoints/' --older-than 30 --force

# Remove old core dumps
xdu-rm -i /var/lib/xdu/home -p '/core\.\d+$' --older-than 7 --force
```

**Preview before production:**
```bash
# Always dry-run first to verify the query
xdu-rm -i /var/lib/xdu/home --older-than 60 --min-size 1G --dry-run | head -20

# Check count
xdu-rm -i /var/lib/xdu/home --older-than 60 --min-size 1G --dry-run | tail -1
# 847,231 file(s) would be deleted.
```

### Comparing Indices with xdu-diff

The `xdu-diff` command compares two indices of the same tree taken at different times—for
example, indices of two filesystem snapshots. Files are matched by their path relative to
each index's crawl root, so `/fs/.snapshots/@GMT-2026.10.14-…/home/alice/x` and
`/fs/.snapshots/@GMT-2026.10.16-…/home/alice/x` are treated as the same file.

```bash
# Per-partition summary of growth, new/deleted files
xdu-diff -h /var/lib/xdu/home-mon /var/lib/xdu/home-wed

# Partitions with the largest change first
xdu-diff -h --sort abs /var/lib/xdu/home-mon /var/lib/xdu/home-wed

# Top 20 files by growth
xdu-diff -h --files --sort delta -l 20 OLD NEW

# New files over 1 GiB in one partition, as absolute paths
xdu-diff --files --status added --min-delta 1G -u alice --absolute OLD NEW
```

Each file is classified as `added`, `removed`, `modified` (size or mtime changed), `meta`
(only ctime/uid/gid/mode changed), `accessed` (only atime changed), or `unchanged`. In
`--files` mode each line shows a marker (`+ - ~ m .`), the size delta, the current size, and the path.

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --files` | List individual files instead of a per-partition summary | |
| `--status` | Statuses to list with `--files` (comma-separated, or `all`) | `added,removed,modified,meta` |
| `-u, --partition` | Restrict to a partition or subdirectory (e.g. `alice`, `projects/big`) | |
| `-p, --pattern` | Regex matched against relative paths | |
| `--min-delta` | With `--files`: minimum absolute size change (e.g., `10M`) | |
| `-s, --sort` | `name`, `delta` (growth first), `shrink`, `abs` (largest change first) | `name` |
| `-l, --limit` | Limit number of output rows | |
| `-a, --all` | Summary: include partitions with no changes | |
| `--absolute` | With `--files`: print absolute paths | |
| `-h, --human-readable` | Human-readable sizes | |
| `--csv` | CSV output with header (raw values) | |
| `--old-root`, `--new-root` | Override the detected crawl root of each index | auto |

The exit status follows `diff`: 0 if there are no differences (atime-only changes don't count), 1 if there are differences, 2 on error.

### Querying with DuckDB

The Parquet index integrates seamlessly with DuckDB for instant analytics:

```sql
-- Total usage per user
SELECT
    regexp_extract(path, '/home/([^/]+)/', 1) AS user,
    sum(size) / 1e12 AS tb
FROM read_parquet('/var/lib/xdu/home/**/*.parquet')
GROUP BY user
ORDER BY tb DESC;

-- Files not accessed in 180 days
SELECT path, size, atime
FROM read_parquet('/var/lib/xdu/home/**/*.parquet')
WHERE atime < epoch(now()) - 86400 * 180
ORDER BY size DESC
LIMIT 100;

-- Query single user (partition pruning; ** includes any nested partitions)
SELECT sum(size) / 1e9 AS gb
FROM read_parquet('/var/lib/xdu/home/alice/**/*.parquet');
```

Use `**/*.parquet` rather than `*/*.parquet` so nested partitions are included.

## Scheduling

Run xdu via cron to maintain a fresh index:

```cron
0 2 * * * /usr/local/bin/xdu /home -o /var/lib/xdu/home -j 32
```

## Pro Tips

### Index ZFS Snapshots for Point-in-Time Accuracy

On large ZFS filesystems (multi-petabyte scale), a full index can take 8-12+ hours. During that time, users may create, modify, or delete files—leading to an index that represents a "smeared" view of the filesystem rather than a consistent point-in-time snapshot.

For accurate auditing, **index a ZFS snapshot instead of the live filesystem**:

```bash
#!/bin/bash
# snapshot-index.sh - Atomic snapshot + index workflow

POOL="tank/home"
SNAP="$POOL@xdu-$(date +%Y%m%d)"
MOUNT="/mnt/xdu-snapshot"
INDEX="/var/lib/xdu/home"

# Create snapshot (instantaneous)
zfs snapshot "$SNAP"

# Mount read-only
mkdir -p "$MOUNT"
mount -t zfs -o ro "$SNAP" "$MOUNT"

# Build index from snapshot
xdu "$MOUNT" -o "$INDEX" -j 32

# Cleanup
umount "$MOUNT"
zfs destroy "$SNAP"

echo "Index complete: $INDEX"
```

**Benefits:**
- **Consistency**: The index reflects an exact point-in-time state
- **Safety**: Indexing a read-only snapshot eliminates any risk of accidental modification
- **Reproducibility**: If questions arise about the data, you can re-mount the same snapshot
- **No user impact**: Snapshot creation is instantaneous; users don't experience slowdowns

For rolling retention, keep the last few snapshots:

```bash
# Keep snapshots for 7 days
zfs destroy tank/home@xdu-$(date -d '7 days ago' +%Y%m%d) 2>/dev/null || true
```

### Incremental Partition Updates

If only a few users have changed significantly, re-index just their partitions:

```bash
# Re-index only alice's data
xdu /home -o /var/lib/xdu/home -j 8 --partition alice
```

This is much faster than a full re-index and automatically prunes stale chunks from previous runs.

With nested partitions, name the partition by its path. Add `-r` to include the partitions below it:

```bash
xdu /data -o /index/data --partition projects/big -r
```

A partial run reuses the split settings saved in the index. To change them, do a full run.
A full run also removes partitions for directories that no longer exist.

### Adaptive Parallelism

Unlike traditional one-thread-per-partition approaches, xdu uses jwalk's adaptive parallelism. Work is dynamically distributed at every directory level:

- When a thread enters a directory with many subdirectories, those subdirectories are redistributed across idle threads
- This eliminates the "long tail" problem where a few large partitions bottleneck the entire crawl
- A filesystem with 1000 small partitions and 5 "whale" partitions (30M+ files each) now completes in 3-4 hours instead of 10+ hours

Adaptive parallelism balances the *crawl*. A whale partition is still one Parquet unit, though,
so drilling into it in `xdu-view`, diffing it, or re-indexing it with `-p` touches all of its files.
Splitting it with `--split` (see [Nested Partitions](#nested-partitions)) breaks it into smaller
units for those operations.

## License

MIT
