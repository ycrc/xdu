<div align="center">

# xdu

**High-performance file system indexer for large-scale storage administration**

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/xdu-project/xdu)](https://github.com/xdu-project/xdu/releases)
[![Tests](https://img.shields.io/github/actions/workflow/status/xdu-project/xdu/test.yaml?branch=main&label=tests)](https://github.com/xdu-project/xdu/actions/workflows/test.yaml)

</div>

Builds partitioned Parquet indexes for instant analytics on filesystems with hundreds of millions of files.

## Motivation

System administrators managing large shared storage (e.g., HPC clusters, research computing, NAS appliances) need to regularly audit disk usage and file access patterns. Common tasks include:

- Identifying users consuming excessive space
- Finding stale data for purge policies
- Generating usage reports by user or project
- Enforcing quotas and retention policies

Traditional tools like `du` and `find` are designed for interactive, one-off queries. They re-traverse the filesystem every time, which is prohibitively slow on systems with hundreds of millions of files. They also produce flat text output that's difficult to analyze at scale.

**xdu** solves this by building a persistent, queryable index once—then enabling instant analytics via the included `xdu-find` command, interactive exploration with `xdu-view`, or external tools like DuckDB, Polars, or Apache Spark.

## Design

### Partitioned Output

By default the index is partitioned by top-level subdirectory (large directories can be split
further; see [Nested Partitions](#nested-partitions)). For a `/home` filesystem:

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

Files directly in the top-level directory go to `index/__root__/`. The index also contains
`.xdu-complete`, the run's completion marker, and `_xdu.json`, which records the crawl root and the
split settings.

### Nested Partitions

When one top-level directory is much larger than the others, it can be split further. Each *split
point* (a directory, relative to the crawled directory) gets its own partition at `index/<path>/`,
and each file goes to the deepest split point containing it:

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

- By default every top-level directory is a split point (`--split-depth 1`). `--split-depth 2`
  splits every second-level directory too; `--split-depth 0` keeps only the `--split` paths.
- `--split` paths may use `*` and `?` within a component. `--split-file` reads them from a file, one
  per line. Wildcards never cross a `/`, so `'a/*'` means the children of `a`; for grandchildren
  too, write `'a/*,a/*/*'`. `**` is rejected. Quote patterns so the shell doesn't expand them.
- A split path must be a real directory. xdu never follows symlinks, so a path through a symlink is
  rejected with an error naming the link.
- The settings are saved in `_xdu.json`, so later runs (including `-p` re-indexes) reuse them.
  Changing them requires a full run, which removes partitions that are no longer split points.
- Split finely enough to balance the work, but keep the partition count modest: thousands of tiny
  Parquet files make queries slower.
- `xdu-find`, `xdu-du`, `xdu-rm` and `xdu-view` accept nested paths for `-u` and include everything
  below them. `xdu-du` and `xdu-view` group nested partitions under their top-level directory.
- `xdu-diff` compares partition by partition when both indexes have the same split settings, and
  whole top-level directories otherwise.
- A nested index records index format version 3 in its completion marker, so an older xdu, whose
  readers glob only one directory level, refuses it instead of missing the nested partitions. A flat
  index stays at version 2. Split settings are supported only for a local output directory.

### Schema

| Column | Type  | Description                         |
|--------|-------|-------------------------------------|
| path   | UTF-8 | Absolute file path                  |
| size   | INT64 | File size in bytes                  |
| uid    | INT64 | Owning user id                      |
| gid    | INT64 | Owning group id                     |
| mode   | INT64 | Permission bits (st_mode & 07777)   |
| atime  | INT64 | Last access time (Unix epoch)       |
| mtime  | INT64 | Last modification time (Unix epoch) |
| ctime  | INT64 | Last inode-change time (Unix epoch) |

### Performance

**Why xdu is faster than `du` for this use-case:**

1. **Adaptive parallel traversal**: Using jwalk, threads dynamically balance work at every directory level—no partition gets bottlenecked to a single thread
2. **Parallel metadata**: File stat() calls run on the shared thread pool alongside the directory reads, so even a single huge partition is stat'd in parallel—critical for high-latency network filesystems
3. **Columnar storage**: Parquet compresses paths efficiently (often 10:1) and enables predicate pushdown
4. **Buffered writes**: Records accumulate in memory before flushing, minimizing I/O syscalls
5. **One traversal, many queries**: Build the index once, query it thousands of times instantly

A typical 100M file filesystem might take 2-3 hours to `du`. With xdu, the index builds in 20-30 minutes and subsequent queries complete in seconds.

## Installation

### Quick Install (Recommended)

```bash
curl -sSfL https://xdu-project.org/install.sh | sh
```

This downloads the latest release binary for your platform and installs it to `~/.local/bin`.

**Options:**
- `XDU_VERSION=v0.1.0` — Install a specific version
- `XDU_INSTALL=/usr/local/bin` — Change install directory

The DuckDB extensions a release ships go to `../lib/xdu/extensions/` relative to the install
directory (`~/.local/lib/xdu/extensions` by default), where the tools look for them; nothing is
downloaded at run time. To keep them somewhere else, set `XDU_EXTENSION_DIR` to that directory.

### From Source

```bash
cargo install --git https://github.com/xdu-project/xdu.git
```

Requires [Rust](https://rustup.rs) nightly toolchain. A `cargo install` build carries no DuckDB
extensions, so a feature that needs one, such as querying an index in S3 (it needs `httpfs`), fails
naming the path it looked in; copy the files from a release tarball's `lib/xdu/extensions/` there,
or point `XDU_EXTENSION_DIR` at them.

### Containers

Container specs for Docker and Apptainer/Singularity live in [`hpccm/`](hpccm/), generated
from a single [HPCCM](https://github.com/NVIDIA/hpc-container-maker) recipe. They install
the published release binaries with no Rust toolchain, so they finish in seconds; see
[`hpccm/README.md`](hpccm/README.md) for usage. They track release tags, not the working
tree — for unreleased commits, build from source instead.

## Usage

### Building an Index

```bash
xdu /home -o /var/lib/xdu/home -j 16 -B 100000
```

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --outdir` | Output directory for index | Required |
| `-j, --jobs` | Parallel threads (`XDU_JOBS` env) | 4 |
| `-B, --buffsize` | Records per Parquet chunk | 100000 |
| `-p, --partition` | Index only specific partitions (comma-separated, e.g. `alice,projects/big`) | All |
| `-r, --recursive` | With `-p`, also index the partitions nested below those given | |
| `--split-depth` | Make every directory down to depth N a partition | 1, or the index's saved setting |
| `--split` | Extra partition directories, relative to DIR (comma-separated, `*` and `?` allowed) | |
| `--split-file` | Read `--split` paths from a file | |
| `--apparent-size` | Report file length instead of disk usage (st_blocks) | |
| `-k, --block-size` | Round sizes up to block size (e.g., `128K`). Implies `--apparent-size` | |
| `--include-snapshots` | Also index `.snapshots` directories (GPFS snapshots) | Skipped |

Directories named `.snapshots` are skipped wherever they occur: each GPFS snapshot is a copy of
the tree around it, so indexing it counts the same files again. A crawl root inside a snapshot
(e.g. `/fs/.snapshots/@GMT-…/home`) is still indexed. A `-p` run must use the setting the index
was built with.

### Querying with xdu-find

The `xdu-find` command provides a convenient CLI for common queries:

```bash
# Find all Python files
xdu-find -i /var/lib/xdu/home -p '*.py'

# Find large files (>1GB) not accessed in 90 days
xdu-find -i /var/lib/xdu/home --min-size 1G --older-than 90

# Query a specific user's partition, sorted by size
xdu-find -i /var/lib/xdu/home -u alice --min-size 100M -f size

# Count matching files
xdu-find -i /var/lib/xdu/home -p '*.tmp' --older-than 30 --count

# Choose the fields to print; --csv for raw values with a header
xdu-find -i /var/lib/xdu/home -u alice -f path,size,mtime,uid
xdu-find -i /var/lib/xdu/home -f path,size,uid --csv

# Pipe to xargs for bulk operations
xdu-find -i /var/lib/xdu/home -p '*.tmp' --older-than 30 | xargs rm
```

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-p, --pattern` | Glob pattern to match paths (e.g., `*.py`) | |
| `--regex` | Interpret `--pattern` as a regular expression | |
| `-u, --partition` | Filter by partition (user directory, or a nested path like `projects/big`; includes everything below it) | |
| `--min-size` | Minimum file size (e.g., 1K, 10M, 1G) | |
| `--max-size` | Maximum file size | |
| `--older-than` | Files not accessed in N days | |
| `--newer-than` | Files accessed within N days | |
| `--owner` | Files owned by this user (name or uid) | |
| `--group` | Files owned by this group (name or gid) | |
| `--mode` | Permission filter: `644` exact, `/002` any-bit, `&4000` all-bit | |
| `--mtime-older-than` | Files not modified in N days | |
| `--mtime-newer-than` | Files modified within N days | |
| `--ctime-older-than` | Files whose status (ctime) has not changed in N days | |
| `--ctime-newer-than` | Files whose status (ctime) changed within N days | |
| `-f, --format` | Output format: path, size, atime, csv, json, or a field list such as `path,size,mtime` (fields: path, size, uid, gid, mode, atime, mtime, ctime) | path |
| `--csv` | With a field list: CSV with a header row and raw values | |
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
xdu-view -i /var/lib/xdu/home -p '*.py' --min-size 1M

# See what changed since an earlier index, biggest growth first
xdu-view -i /var/lib/xdu/home-wed --compare /var/lib/xdu/home-mon -s delta
```

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-u, --partition` | Start in a specific partition (top-level directory, or a nested path) | |
| `-p, --pattern` | Glob pattern to filter paths (e.g., `*.py`) | |
| `--regex` | Interpret `--pattern` as a regular expression | |
| `--min-size` | Minimum file size (e.g., 1K, 10M, 1G) | |
| `--max-size` | Maximum file size | |
| `--older-than` | Files not accessed in N days | |
| `--newer-than` | Files accessed within N days | |
| `-s, --sort` | Sort order (see below) | name |
| `--compare` | Earlier local index to compare against (see [Comparing Two Indexes](#comparing-two-indexes)) | |

**Sort modes:** `name` (default, directories first), `size-desc`, `size-asc`, `count-desc`, `count-asc`, `age-desc` (oldest first), `age-asc` (newest first), `mtime-desc`, `mtime-asc`, `ctime-desc`, `ctime-asc`, `uid-asc`, `gid-asc`, `mode-asc`, and with `--compare`: `delta-desc` (largest growth first), `delta-asc` (largest shrink first)

#### Keybindings

**Navigation:**
| Key | Action |
|-----|--------|
| `↑`/`k` | Move selection up |
| `↓`/`j` | Move selection down |
| `→`/`Enter` | Enter directory |
| `Space` | Preview the selected file (list view); enter directory or focus the preview (tree view) |
| `←`/`Backspace` | Go up / back |
| `g`/`G` | Jump to first / last entry |
| `t` | Toggle list ↔ tree view |
| `?` | Show the key summary |
| `q`/`Esc` | Quit |

**Columns:**
| Key | Action |
|-----|--------|
| `a` | Cycle the timestamp column: accessed / modified / changed (`o` and `n` filter on it) |
| `u` | Toggle the user column |
| `r` | Toggle the group column |
| `x` | Toggle the permission column |

**Sorting:**
| Key | Action |
|-----|--------|
| `s` | Open sort selector (use `↑↓`/`jk` to choose, `Enter` to confirm, `Esc` to cancel) |

**Filtering (interactive):**
| Key | Action |
|-----|--------|
| `/` | Set path pattern filter (glob) |
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
┌─ alice/projects [older:30d] [min:1.00 MiB] [/*.py] ─────────────────────┐
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

#### Comparing Two Indexes

With `--compare OLD`, `xdu-view` browses the `-i` index and shows how each entry changed since
`OLD`, matching files by path relative to each index's crawl root (as `xdu-diff` does). Removed
files and directories stay visible so shrinkage can be traced too. Both indexes must be local.

```
  name                       size        Δsize        files  Δfiles   accessed
+ ▸ new-project          3.14 MiB    +3.14 MiB   6.5K files   +6.5K      today
~ ▸ QuotaTable         353.15 MiB  +384.00 KiB    307 files              today
- ▸ old-scratch               0 B   -12.00 GiB      0 files   -1.2K  1 month ago
  ▸ Spring              17.02 MiB                34.9K files         20 days ago
```

- Markers: `+` new, `-` gone, `~` changed (added, removed, or modified files inside)
- **Δsize** and **Δfiles** are green for growth and red for shrinkage; in tree view, Δsize replaces
  the file count
- `d` cycles which files are shown: all → changed → added → removed → modified
- Sort with `s` → `delta-desc` / `delta-asc`, then drill into the top entry to find where growth
  happened
- The file previews show the file's previous size

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
xdu-view -i /var/lib/xdu/home -p '*.ipynb' -s size-desc
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
xdu-rm -i /var/lib/xdu/home -u alice -p '*.tmp' --older-than 30 --force
```

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --index` | Path to Parquet index directory | Required |
| `-p, --pattern` | Glob pattern to match paths (e.g., `*.py`) | |
| `--regex` | Interpret `--pattern` as a regular expression | |
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
xdu-rm -i /var/lib/xdu/home --regex -p '/\.ipynb_checkpoints/' --older-than 30 --force

# Remove old core dumps
xdu-rm -i /var/lib/xdu/home --regex -p '/core\.\d+$' --older-than 7 --force
```

**Preview before production:**
```bash
# Always dry-run first to verify the query
xdu-rm -i /var/lib/xdu/home --older-than 60 --min-size 1G --dry-run | head -20

# Check count
xdu-rm -i /var/lib/xdu/home --older-than 60 --min-size 1G --dry-run | tail -1
# 847,231 file(s) would be deleted.
```

### Bulk Copy and Move with xdu-cp and xdu-mv

`xdu-cp` and `xdu-mv` select files with the same filters as `xdu-find` and copy or move exactly
that set into a tree under `--into`. Each file lands at its path relative to `--root` (default `/`,
which mirrors the absolute path), so `/home/alice/runs/r1.h5` with `--root /home --into /stage`
lands at `/stage/alice/runs/r1.h5`. They keep `xdu-rm`'s gates: a `y/N` prompt (`--force` skips
it), `--dry-run` listing each source and destination without writing anything, a deterministic
`--limit`, and `--safe`, which re-checks every given filter against each file's live metadata
just before acting on it.

Neither tool replaces an existing file: a taken destination is skipped, counted, and makes the run
exit non-zero. A copy appears at its final name only once it is complete, and carries the source's
permission bits and times, and its owner and group where permitted. Only regular files are acted
on, and no symlink is followed. The index is not updated; index the trees again to see the result.
A move within one filesystem is a rename; `xdu-mv(1)` describes moves to another filesystem.

```bash
# Preview copying alice's year-old logs into a staging tree
xdu-cp -i /var/lib/xdu/home -u alice -p '*.log' --older-than 365 --into /stage --root /home --dry-run

# Move a departed user's files into an attic on the same filesystem, re-checking each first
xdu-mv -i /var/lib/xdu/home -u bob --into /home/.attic --root /home --safe --force
```

### Disk Usage with xdu-du

`xdu-du` prints `du`-style totals from the index: one line per top-level directory (nested
partitions folded in), or one per path given.

```bash
xdu-du -i /var/lib/xdu/home -h -c
xdu-du -i /var/lib/xdu/home -h /home/alice /home/bob
xdu-du -i /var/lib/xdu/home -s -h -u projects/big
```

`-h` is `--human-readable`, as in `du`; help is `--help`.

### Comparing Indexes with xdu-diff

The `xdu-diff` command compares two local indexes of the same tree taken at different times—for
example, indexes of two filesystem snapshots. Files are matched by their path relative to each
index's crawl root, so `/fs/.snapshots/@GMT-2026.10.14-…/home/alice/x` and
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

Each file is classified as `added`, `removed`, `modified` (size or mtime changed), `meta` (only
ctime/uid/gid/mode changed), `accessed` (only atime changed), or `unchanged`. In `--files` mode each
line shows a marker (`+ - ~ m .`), the size delta, the current size, and the path.

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --files` | List individual files instead of a per-partition summary | |
| `--status` | Statuses to list with `--files` (comma-separated, or `all`) | `added,removed,modified,meta` |
| `-u, --partition` | Restrict to a partition or subdirectory (e.g. `alice`, `projects/big`) | |
| `-p, --pattern` | Glob matched against relative paths | |
| `--regex` | Interpret `--pattern` as a regular expression | |
| `--min-delta` | With `--files`: minimum absolute size change (e.g., `10M`) | |
| `-s, --sort` | `name`, `delta` (growth first), `shrink`, `abs` (largest change first) | `name` |
| `-l, --limit` | Limit number of output rows | |
| `-a, --all` | Summary: include partitions with no changes | |
| `--absolute` | With `--files`: print absolute paths | |
| `-h, --human-readable` | Human-readable sizes | |
| `--csv` | CSV output with header (raw values) | |
| `--old-root`, `--new-root` | Override the detected crawl root of each index | auto |

The exit status follows `diff`: 0 if there are no differences (atime-only changes don't count), 1 if
there are differences, 2 on error.

### Indexes in S3

`xdu` builds an index straight into an S3 bucket, on AWS or on an S3-compatible store: give `-o`
an `s3://bucket/prefix` locator instead of a directory. Each chunk is uploaded to its final key as
the crawl encodes it, and nothing of the index is staged on local disk. The completion marker
works as it does locally: the run lists the prefix first, so an unreachable endpoint, refused
credentials or a missing bucket fail it with any existing index untouched, then removes the marker,
and writes it again only when every partition has finished. A re-run leaves no stale chunk behind.
A top-level directory whose name would change on its way into a key or a glob (non-ASCII, or a
character such as `~`, `%`, `#` or `*`) is refused before anything is written.

```bash
export AWS_PROFILE=research
xdu /data/scratch -o s3://indexes/scratch -j 8
```

The index in the bucket is then queried in place: give
`xdu-find` or `xdu-view` an `s3://bucket/prefix` locator wherever it takes an index directory,
through `-i` or `XDU_INDEX`. Each query reads the Parquet footers and only the parts of each chunk it needs, with
HTTP range requests, so a `--count` costs the footers, a small fraction of the index. Nothing is copied
to local disk and nothing is downloaded at run time; the `httpfs` extension a release ships beside
the binaries does the reading.

```bash
# Credentials, region and endpoint come from where the AWS tools look for them:
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN), or a profile in
# ~/.aws/credentials and ~/.aws/config selected by AWS_PROFILE.
export AWS_PROFILE=research

# An S3-compatible store: name its endpoint (or set endpoint_url in the profile).
export AWS_ENDPOINT_URL=https://store.example.org:9000

xdu-find -i s3://indexes/scratch --count
xdu-find -i s3://indexes/scratch -u alice --min-size 1G -f size
xdu-view -i s3://indexes/scratch -u alice

# Or once for the session
export XDU_INDEX=s3://indexes/scratch
xdu-find --top 10
```

The proxy variables (`HTTP_PROXY` and friends) are not used by `xdu` or the readers: requests go
straight to the endpoint. Building needs no DuckDB extension; querying does. `xdu-rm` refuses an
`s3://` index. Unreachable endpoints, refused credentials, a missing
bucket or prefix, and an index without a readable completion marker each fail with the cause on
stderr and print no rows. The bucket must have a name S3 allows (3 to 63 lowercase letters, digits,
dots and hyphens, beginning and ending with a letter or digit); any other, and a locator carrying
credentials, is refused before a request is sent, without the locator being repeated.

Every `https` connection, the writer's and the readers', authenticates the server against one CA
file: the one `AWS_CA_BUNDLE` names, else the platform's bundle (the first of
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem` and `/etc/ssl/cert.pem` present).
`SSL_CERT_FILE` and the macOS keychain are not read, nothing turns verification off, and a
self-signed or unknown-CA endpoint is refused by all three tools; a store with a private CA needs
`AWS_CA_BUNDLE` set to that CA's file. That file must include the root certificate the chain ends
at (a file with no self-signed root, such as an intermediate CA alone, is refused before any
request), and the endpoint's certificate must name its host in the subject alternative name (SAN).
That root must be self-signed with SHA-256 or stronger, since a file whose only roots are
SHA-1-signed is refused the same way, and an intermediate must ship with its own root: beside an
unrelated root, `xdu` writes an index the readers refuse. Known limitation: `xdu-find` and `xdu-view` also accept a certificate whose subject common name
(CN) names the host when its SAN does not, which `xdu` refuses; a follow-up
([`issues/s3-reader-tls-hostname.md`](issues/s3-reader-tls-hostname.md)) will make the readers
check the SAN alone.

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

A partial run reuses the split settings saved in the index. To change them, do a full run. A full
run also removes partitions for directories that no longer exist.

### Adaptive Parallelism

Unlike traditional one-thread-per-partition approaches, xdu uses jwalk's adaptive parallelism. Work is dynamically distributed at every directory level:

- When a thread enters a directory with many subdirectories, those subdirectories are redistributed across idle threads
- File stat() calls run in the same pool tasks as the directory reads, so a whale partition's metadata lookups are spread across all `-j` threads too
- This eliminates the "long tail" problem where a few large partitions bottleneck the entire crawl
- A filesystem with 1000 small partitions and 5 "whale" partitions (30M+ files each) now completes in 3-4 hours instead of 10+ hours

Adaptive parallelism balances the *crawl*. Each partition still has one driver thread that builds
its rows and writes its Parquet chunks; that is far cheaper than a network-filesystem stat, but it
is the remaining serial step in a whale partition. A whale partition is also one Parquet unit, so
drilling into it in `xdu-view`, diffing it, or re-indexing it with `-p` touches all of its files.
Splitting it with `--split` (see [Nested Partitions](#nested-partitions)) breaks it into smaller units
for those operations.

#### Where the stat runs

Each indexed file costs a directory read, which yields its name and type, and a `stat`, which
yields everything else in the row. On GPFS or Lustre the `stat` is a round trip to a metadata
server and dominates the crawl.

The `-j` pool threads read directories through jwalk's `process_read_dir` callback, and the same
callback stats every regular file in the directory it has just read. The result travels with the
entry in jwalk's per-entry `client_state`, and the partition's driver thread takes it from there to
build the row. A partition's stats are therefore spread over all `-j` threads, wherever its
directories happen to be read, and a pool thread cannot read further ahead than it can stat, so
memory stays bounded.

Earlier versions ran the `stat` in the driver loop. A partition has one driver, so every stat in
that partition was serialized on one thread while the pool read directories far ahead of it and
queued the entries in memory. On `/gpfs/gibbs/pi`, a single 192M-file partition (its `.snapshots`
included) crawled at about 2,200 files/s for the last ~24 hours of a 29-hour run, which used ~7
CPU-hours and 132 GB of RSS.

| Run | Stat in driver loop | Stat on the pool |
|-----|---------------------|------------------|
| 9.1M-file GPFS tree, as root, `-j 16` | 1,694 files/s, 5,370 s, 14.9 GB RSS | ~28,500 files/s, 1.9 GB RSS |
| `/gpfs/gibbs/pi`, as root, `-j 32` on 4 cores | — | 755M files in 9.0 h, ~3.5 cores busy, 42 GB RSS |

The index is unchanged: the same files, and the same values in each row. The stat is an `lstat`
(`follow_links(false)`), so a file cannot be swapped for a symlink between the directory read and
the stat. A stat that fails on the pool leaves the slot empty, and the driver repeats it to report
the error as a vanished file or a hard error, as before. `test_metadata_matches_files`
(`tests/nested_tests.rs`) gives every file a distinct size and mtime and checks that each row
carries its own file's values.

## License

MIT
