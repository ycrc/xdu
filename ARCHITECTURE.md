# xdu architecture

xdu splits storage auditing into two phases. A **crawl** (`xdu`) walks a directory tree once and
writes one row per regular file into a Parquet index. Every other tool **reads that index** with an
embedded DuckDB engine and never walks the tree again, except for the bulk-action tools, which touch
exactly the files a query selected. This file describes the two phases, the index between them, and
every source module. `AGENTS.md` holds the load-bearing invariants and is ground truth where the
two disagree.

```
                     crawl (once)                                 query (many times)
 directory tree ──▶ xdu ──▶ <index>/                     ──▶ xdu-find   rows, counts, top-N
                             _xdu.json      (layout)     ──▶ xdu-du     totals per directory
                             .xdu-complete  (attests)    ──▶ xdu-view   interactive browser
                             alice/000000.parquet        ──▶ xdu-diff   two indexes compared
                             projects/000000.parquet     ──▶ xdu-rm     unlink selected files
                             projects/big/000000.parquet ──▶ xdu-cp/mv  copy/move selected files
                             __root__/000000.parquet
```

## The index

An index is a directory (or an `s3://` prefix) of Parquet files plus two small control files.

**Schema** (`lib::get_schema`): eight non-null columns, one row per regular file. Symlinks,
directories and special files are not indexed.

| Column | Type | Source |
|--------|------|--------|
| `path` | Utf8 | absolute path; a non-UTF-8 name is stored lossily and counted |
| `size` | Int64 | `st_blocks`×512 by default, `st_size` with `--apparent-size`, rounded with `-k` |
| `uid`, `gid` | Int64 | owner and group ids |
| `mode` | Int64 | permission bits (`st_mode & 0o7777`) |
| `atime`, `mtime`, `ctime` | Int64 | Unix epoch seconds |

**Partitions.** Rows are grouped by the directory they fall under. By default each top-level
subdirectory of the crawl root is a partition (`alice/`, `projects/`), and loose files directly
under the root go to the reserved partition `__root__`. With `--split` or `--split-depth`, deeper
directories become partitions too (`projects/big/`), and partition directories nest inside the
index the same way. Each file belongs to the deepest partition that contains it, so it is stored
exactly once. A partition holds sequentially numbered chunks, `000000.parquet`, `000001.parquet`,
each at most `-B` rows (default 100,000), Snappy-compressed.

Partitions are what make the index cheap to update and to query in pieces: `xdu -p NAME`
re-crawls one partition, `-u NAME` in the readers globs one partition's subtree, and `xdu-diff`
compares two indexes one partition at a time.

**Control files** at the index root. Their names, with `__root__`, are reserved
(`lib::RESERVED_INDEX_NAMES`), and a source tree whose top level uses one is refused.

- `.xdu-complete` — the completion marker. It is removed before a crawl writes anything and
  written only when the whole run succeeded, so its presence attests to a complete index. Its
  `key=value` body records the file and byte counts, tolerated errors (`--allow-errors`) and the
  index **format version**: 2 for the flat layout, 3 when any partition is nested. Every reader
  refuses an index with no marker or a version it does not understand, and warns when the marker
  records tolerated errors.
- `_xdu.json` — the manifest: crawl root, split spec, size mode, the skipped snapshot names and
  whether partition directories carry their sources' group access (`mirror_permissions`).
  A later run reuses the split spec, and a `-p` run refuses a different one, so partitions never
  overlap.

**Hive detection is off.** DuckDB would read a `key=value` directory name in the glob as a column.
Every reader passes `hive_partitioning = false`, so a partition named `size=0` stays a name.

## The crawl (`xdu`)

A run has three stages: pre-flight, walk, and attestation.

**Pre-flight** (`src/bin/xdu.rs::run`). Choose the size mode and the destination (a local
directory through `LocalSink`, or an S3 prefix through `S3Sink`). Load the manifest if one
exists, settle the split spec, and resolve it into split points against the live tree
(`layout::resolve_split_points`). Build the work queue (`crawl::build_split_work_queue`): one item
per partition, refusing reserved names and validating any `-p` filter. Nothing is written until
every check has passed.

**Walk** (`src/bin/xdu.rs::crawl`). The concurrency model is one shared thread pool plus a set of
driver threads:

- One rayon pool of `-j` threads backs every directory walker
  (`jwalk::Parallelism::RayonExistingPool`). Work stealing spreads directory reads across all
  threads, so one large partition cannot leave the others idle.
- Up to `-j` driver threads (`std::thread`, joined by `thread::scope`) each take the next partition
  from a shared queue, iterate its walker, and append rows to that partition's `PartitionBuffer`.
  The first driver error fails the run.
- The walker's `process_read_dir` callback runs on the pool thread that read each directory. It
  `lstat`s every regular file there and attaches the result to the entry (jwalk's `client_state`),
  so the metadata calls, which dominate on GPFS and Lustre, run on all `-j` threads even inside one
  partition. The same callback prunes snapshot directories (`.snapshots`, `.snapshot` and any
  `--snapshot-dir`, unless `--include-snapshots`) and the split points that belong to other
  partitions (`crawl::SplitSkip`).
- A driver turns each entry into a row (`crawl::file_measurements`, `crawl::lossy_path`). A stat
  that fails is repeated and classified (`crawl::classify_io_error`): a file that vanished is
  counted, anything else is an error that fails the run unless `--allow-errors`.

Moving the stat from the driver to the pool is the change behind the large speedup on network
filesystems; `README.md` § "How the crawl works" explains it with measurements.

**Writing chunks** (`crawl::PartitionBuffer`, `crawl::IndexSink`). A buffer encodes a Parquet chunk
each time it holds `-B` rows. `LocalSink` writes `NNNNNN.parquet.partial` and renames it into place
when the partition is finalized, then prunes higher-numbered chunks left by an earlier, larger run.
`S3Sink` PUTs each chunk at its final key and finalizes with a LIST and DELETE of stale chunks.
Each chunk is atomic; a partition as a whole is not.

**Access** (`--mirror-permissions`, `LocalSink::mirroring`). Before a partition's first chunk,
`LocalSink` creates each directory of its key mode 0700, gives it the group of the source directory
at the same relative path, and sets `crawl::mirrored_mode`: `rwx` for the crawler and whichever of
read and search the source grants its group and others, never write, setuid, setgid or sticky. The
source directory's owner, unless it is the crawler, gets its read and search bits through a POSIX
access ACL entry (`crawl::owner_acl`, written as `system.posix_acl_access`), never through
ownership, which would let it chmod its way to write access. `__root__` stays 0700 and chunks are
0644, so the directory alone decides who reads them. The manifest records the setting, and every
later run applies it.

**Attestation.** After a full run, partitions that are no longer split points are removed
(`crawl::remove_stale_partition`) and the manifest is saved. If any error was not tolerated the run
exits non-zero with the marker absent. Otherwise it writes `.xdu-complete` last.

## Reading the index

Every reader opens DuckDB through `engine::open_connection`, which turns extension autoinstall and
autoload off, so no query ever reaches the network. The DuckDB engine is compiled into each binary
(`duckdb` crate, `bundled`), so there is no external dependency. The one optional extension,
`httpfs` for `s3://` indexes, ships beside the binaries and loads by absolute path.

The query path is shared:

1. `lib::open_index` classifies the argument as a local path or an `s3://` locator and opens the
   connection (for S3, `engine::open_s3_connection` with credentials from `s3::S3Settings`).
2. The marker gates run: `lib::index_version_error` refuses, `lib::index_completion_warning` warns
   (`read_completion_marker_s3` and the `marker_*` pair for S3).
   On a local index `lib::note_unreadable` then lists the partitions with
   `layout::readable_partitions`. DuckDB's glob skips a directory it cannot open without a word,
   so the rows are already the readable ones; this prints the count of directories left out, and
   refuses a `-u` naming one. `xdu-diff` and `--compare` hide a directory unreadable in either
   index from both sides (`DiffSide::hidden`), or its files would read as added or removed.
3. `lib::parquet_source` builds the `FROM` clause: `read_parquet('<index>/**/*.parquet',
   hive_partitioning = false)`, or `<index>/<partition>/**/*.parquet` for `-u`. For S3 the glob is a
   bound parameter.
4. `lib::QueryFilters` turns the filter flags (pattern, size, age, owner, group, mode, times) into
   a `WHERE` clause, and `lib::SortMode` into `ORDER BY`.

User values reach SQL only through `sql_quote` or bound parameters (`AGENTS.md`, invariant 5).

### The tools

| Tool | What it does with the index | Index |
|------|-----------------------------|-------|
| `xdu-find` | Prints matching rows in a chosen format, or `--count`, or `--top N` partitions | local, S3 |
| `xdu-du` | Sums `size` per top-level directory or per given path prefix | local, S3 |
| `xdu-view` | Terminal browser over partitions and directories, aggregated in SQL per listing; `--compare OLD` shows changes | local, S3 (`--compare` local) |
| `xdu-diff` | Compares two indexes of one tree, per partition, by path relative to each crawl root | local |
| `xdu-rm` | Selects files, confirms, then unlinks them on a rayon pool; `--safe` re-stats first | local |
| `xdu-cp` | Selects files and copies each to `--into`/(path relative to `--root`), never replacing | local |
| `xdu-mv` | As `xdu-cp`, but moves; across filesystems copies, verifies, then unlinks the source | local |

**Comparison** (`xdu-diff`, `xdu-view --compare`). `diff::discover_index_root` finds each index's
crawl root (from the manifest, else from the paths), so files match by relative path even when the
roots differ, as for two snapshot mounts. `diff::diff_units` decides the unit of comparison: one
partition when both indexes share a layout, one whole top-level subtree when they were split
differently. `diff::diff_partition_sql` does a full outer join per unit and labels each file
`added`, `removed`, `modified` (size or mtime), `meta` (only ctime, owner, group or mode),
`accessed` (only atime) or `unchanged`. Neither tool checks that the two indexes used the same size
mode, so a pair must be crawled with the same one.

**Bulk actions** (`xdu-rm`, `xdu-cp`, `xdu-mv`). All three refuse an `s3://` index, require a
`y/N` confirmation unless `--force`, support `--dry-run`, and order by path whenever `--limit` is
given, so a dry run and the real run select the same rows. `xdu-cp` and `xdu-mv` share a
select-then-act engine: `select::select` runs one bound, path-ordered statement, and
`relocate` checks the whole mapped set before the first write, then acts in path order through the
primitives in `atomic_fs`, which publish a file only by a rename that refuses to replace.
`--safe` re-checks every filter against live metadata (`select::holds_live`) before acting.

## Modules

The crate is one library (`src/lib.rs` and its modules) and nine thin binaries. Logic that can be
tested without a terminal or a filesystem walk lives in the library.

### Library

| Module | Purpose |
|--------|---------|
| `lib.rs` | Shared core. The index schema (`get_schema`), layout constants (`ROOT_PARTITION`, `COMPLETION_MARKER`, `RESERVED_INDEX_NAMES`, format versions), index globs and `parquet_source`, `open_index`, the completion-marker reads and gates for local and S3 indexes, `SizeMode`, `SortMode`, `QueryFilters` (filters to SQL), size and mode parsing, user and group name resolution, output formatting, and the log-record format. |
| `cli.rs` | The single clap definition of every binary's arguments (`XduArgs`, `XduFindArgs`, `XduViewArgs`, `XduRmArgs`, `XduDuArgs`, `XduDiffArgs`, and `SelectArgs` shared by `XduCpArgs`/`XduMvArgs`). Completions and man pages describe exactly this. |
| `crawl.rs` | The crawler's testable parts: work-queue construction and reserved-name refusal, `SplitSkip` (which directories a walker prunes), per-file measurement and lossy path conversion, error classification, `PartitionBuffer`, the `IndexSink` trait with `LocalSink`, chunk naming and stale-chunk pruning, `remove_stale_partition`, and the completion marker's clear and write. |
| `layout.rs` | Nested partitions: `SplitSpec`, the `_xdu.json` `Manifest`, `resolve_split_points` (spec plus live tree to split points), `list_partitions` (partition keys present in an index), and the SQL that maps a chunk's file name back to its partition or top-level key. Also `SNAPSHOT_DIR`. |
| `engine.rs` | The only place a DuckDB connection is opened. Turns autoinstall and autoload off, locates the shipped extension directory (`XDU_EXTENSION_DIR`, else `<exe>/../../lib/xdu/extensions`), loads extensions by path, and opens the S3 reader connection with a bound `CREATE SECRET` and pinned TLS verification. `clippy.toml` forbids opening a connection anywhere else. |
| `s3.rs` | S3 support: `IndexLocator` (local path or `s3://`, classified on raw bytes), `S3Settings` (the one resolver for credentials, region, endpoint and CA bundle, used by both writer and readers), and `S3Sink`, the crawler's S3 destination. |
| `view_query.rs` | Every query `xdu-view` runs: partition list, files under `__root__`, directory listings for list and tree modes, and `Compare`, the per-partition comparison relations behind `--compare`. Each statement is built by a pure function so tests can check its text. |
| `diff.rs` | Index comparison shared by `xdu-diff` and `xdu-view --compare`: crawl-root discovery, the choice of comparison units, and the per-unit join SQL with its status labels. |
| `select.rs` | Selection for `xdu-cp`/`xdu-mv`: S3 refusal, marker gates, glob and partition-name checks, the one bound path-ordered statement, and `holds_live`, the `--safe` re-check. |
| `relocate.rs` | Action for `xdu-cp`/`xdu-mv`: the `--root`/`--into` mapping, whole-set refusals before any write, the confirmation prompt, the ordered executor on a local pool, per-file outcomes and the summary. Entry points `run_cp` and `run_mv`. |
| `atomic_fs.rs` | Filesystem primitives that never replace or truncate a file: component-by-component `O_NOFOLLOW` walks, `rename_noreplace` (`renameat2`, else a checked `linkat`), `copy_atomic` (temp file, flush, no-replace publish), same-filesystem and cross-filesystem moves, directory flushing, and a fault-injection seam for tests. |

### Binaries

| Binary | Source | Notes |
|--------|--------|-------|
| `xdu` | `src/bin/xdu.rs` | Argument handling, pre-flight, the pool and driver threads, progress output, and run sequencing around `crawl`. |
| `xdu-find` | `src/bin/xdu-find.rs` | Filters to SQL, output formats, `--count` and `--top`. |
| `xdu-du` | `src/bin/xdu-du.rs` | Totals per top-level directory or path prefix. |
| `xdu-view` | `src/bin/xdu-view.rs` | ratatui/crossterm TUI: list and tree modes, interactive filters, file preview, compare mode. Restores the terminal on every exit path, including panic. Queries live in `view_query.rs`. |
| `xdu-diff` | `src/bin/xdu-diff.rs` | Runs `diff.rs` over every unit and prints the per-partition summary or per-file rows; exits 0, 1 or 2 like `diff`. |
| `xdu-rm` | `src/bin/xdu-rm.rs` | Selection, confirmation, parallel unlink, `--safe` re-stat. |
| `xdu-cp`, `xdu-mv` | `src/bin/xdu-cp.rs`, `xdu-mv.rs` | Parse arguments and call `relocate::run_cp` / `run_mv`. |
| `gen-completions` | `src/bin/gen-completions.rs` | Build helper: writes bash and zsh completions from `cli.rs`. Not installed. |

`examples/extension-probe.rs` is a release-time helper, never installed. It prints the engine
version and pinned extension set, and checks that the shipped extensions load.

## Supporting files

| Path | Purpose |
|------|---------|
| `doc/*.scd` | Man page sources (scdoc), one per tool. Rendered into `share/` at build time. |
| `tests/` | Integration tests that drive the real binaries against temporary trees; see `TESTSUITE.md`. |
| `bench/` | Crawl benchmark: synthetic tree generator, runner, scenarios and baseline. |
| `packaging/`, `install.sh`, `Dockerfile`, `build.sh` | Release tarballs, installer, container image, RPM spec, extension checks. |
| `clippy.toml`, `rust-toolchain.toml`, `.cargo/config.toml` | Lint rules (no DuckDB connection outside `engine.rs`), pinned toolchain, static libstdc++ linking. |
| `.agents/`, `spec/`, `issues/`, `ROADMAP.md` | Upstream's spec-driven development process and its records. |
| `RUNS/` (untracked) | This clone's build and test scripts, commit-tagged binaries and Slurm job scripts. |
