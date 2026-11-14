# xdu test suite

This describes the tests in this clone (`nested-partitions` at 343c727, xdu 0.6.0): which of them
come from upstream xdu-project, which were added on this branch, and how to run them.

## How to run

All tests run with `cargo test` from the repo root. In the Claude container, and on any node where
the cluster's Rust is too old, use the wrapper, which runs Cargo in the same pinned pixi
environment as `RUNS/build.sh` and builds into the repo's `target/`:

```bash
RUNS/test.sh                                   # all three gates: fmt, clippy, cargo test
RUNS/test.sh --test nested_tests               # one integration-test file
RUNS/test.sh snapshot                          # every test whose name contains "snapshot"
RUNS/test.sh --test crawl_tests -- --nocapture # show output, e.g. to see self-skipped cases
RUNS/test.sh --lib layout::                    # unit tests of one module
```

Outside the wrapper, with a Rust 1.88+ toolchain and a C/C++ compiler on `PATH`:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

These three are the project's pre-release gate (CI runs the same). `cargo test` compiles the
**debug** profile, which is separate from the release build, so the first test run after a fresh
checkout or a compiler change compiles DuckDB once more (about 15 minutes on 4 cores); later runs
reuse it from `target/`. The whole suite then takes a few minutes.

The integration tests run the real binaries that Cargo built for the test profile, against
throwaway trees and indexes in temporary directories. They never touch a real index or real data.

## What it contains

About 440 tests in two kinds.

**Unit tests** live in `src/` next to the code (`#[cfg(test)] mod tests`) and test single
functions: size and date parsing, the SQL each reader builds, glob construction, the S3 settings
resolver, the atomic copy and rename primitives, split-point resolution.

| File | Tests | What it covers |
|------|------:|----------------|
| `src/lib.rs` | 81 | parsing, filters and their SQL, index globs, `parquet_source`, completion marker |
| `src/s3.rs` | 60 | S3 locators, credential and TLS trust resolution, the S3 index writer |
| `src/atomic_fs.rs` | 32 | no-replace rename, atomic copy, cross-filesystem move, failure injection |
| `src/crawl.rs` | 16 | work queue, reserved names, chunk writing and stale-chunk pruning |
| `src/engine.rs` | 11 | DuckDB connection setup, extension loading refusals |
| `src/layout.rs` | 10 | nested partitions: split specs, `_xdu.json` manifest, partition keys |
| `src/select.rs` | 10 | xdu-cp/xdu-mv selection: glob and partition-name checks, `--safe` re-check |
| `src/relocate.rs` | 6 | `--root`/`--into` path mapping |
| `src/bin/xdu-view.rs`, `src/view_query.rs` | 9 | xdu-view queries and display helpers |
| `src/diff.rs` | 3 | xdu-diff comparison units |

**Integration tests** live in `tests/`. Each builds a small directory tree, indexes it with
`xdu`, runs one of the other tools against the index, and checks the result: rows in the index,
stdout, exit status, and for the destructive tools which files are actually gone, copied or moved.
Shared helpers (finding the binaries, building an index, backdating atimes) are in
`tests/common/mod.rs`.

| File | Tests | What it covers |
|------|------:|----------------|
| `crawl_tests.rs` | 28 | `xdu`: index contents, partitions, `--partition` runs, errors, marker, `.snapshots` |
| `cp_tests.rs` | 33 | `xdu-cp`: selection, never-replace, `--safe`, owner/group/mode carried over |
| `mv_tests.rs` | 21 | `xdu-mv` on one filesystem |
| `rm_tests.rs` | 21 | `xdu-rm`: confirm/dry-run/force gates, `--safe`, `--limit` ordering |
| `find_tests.rs` | 11 | `xdu-find` filters and output formats |
| `nested_tests.rs` | 9 | nested partitions end to end (all tools), parallel-stat correctness |
| `diff_tests.rs` | 7 | `xdu-diff` and root discovery, flat and nested layouts |
| `version_tests.rs` | 6 | readers refuse an index format they do not understand |
| `view_tests.rs` | 3 | `xdu-view` queries |
| `offline_tests.rs` | 1 | readers never download a DuckDB extension |
| `cli_version_tests.rs` | 1 | every binary answers `--version` with the `Cargo.toml` version |
| `s3_tests.rs` | 56 | S3 index read/write (54 need a local S3 endpoint, see below) |
| `mv_xfs_tests.rs` | 3 | `xdu-mv` to another filesystem (need a second filesystem, see below) |

### Tests added on this branch

Most of the suite is upstream's. These were written here, for the features this branch adds:

- **Nested partitions** (`tests/nested_tests.rs`, `tests/diff_tests.rs`, unit tests in
  `src/layout.rs`). Split points from `--split` and `--split-depth`, including wildcards and
  depth 0; that every file lands in exactly one partition; that the default layout and format
  version 2 are unchanged without split options; that changing the layout removes stale
  partitions; `--partition` re-indexing of a nested partition and the refusal of a changed layout;
  `-u projects/big` scoping in the readers; `xdu-view` folding nested partitions under their
  top-level directory and `--compare`; `xdu-diff` between two flat, two nested, or a flat and a
  nested index of the same tree.
- **Parallel stat** (`test_metadata_matches_files` in `nested_tests.rs`). Files are now stat'ed
  on the crawl's thread pool and the result travels with the directory entry. The test gives every
  file a distinct size and mtime, indexes it (default thread count, nested layout), and checks
  that each row's size, mtime, uid and mode match that file's own `stat`, so a mix-up between
  entries would fail.
- **`.snapshots` skipping** (three tests in `crawl_tests.rs`). `.snapshots` directories are
  skipped by default at any depth and never become partitions, while a name like `.snapshotsx` is
  still indexed and a crawl root inside a snapshot is still walked; `--include-snapshots` indexes
  them; a `--partition` run refuses a setting different from the one the index was built with.
- **The 343c727 merge** extended upstream's xdu-cp/xdu-mv partition check (`src/select.rs`) to
  accept nested names like `projects/big` and reject `bob//big` or `bob/./big`, and updated the
  reader-SQL tests to the combined nested-glob plus `hive_partitioning = false` form.

## Expected results

The last full run in the Claude container (2026-11-11, 343c727): fmt and clippy clean;
**384 passed, 3 failed, 55 ignored**.

- **The 3 failures are an artifact of the container.** `a_refused_owner_still_carries_the_group`
  (`src/atomic_fs.rs`), `cp_carries_owner_and_group_when_permitted` and
  `cp_safe_skips_a_file_that_no_longer_matches_each_filter` (`cp_tests.rs`) change a file's group
  to another group the user belongs to. Inside the container the only other group is `nobody`,
  which the kernel refuses (`EINVAL`). They are expected to pass on a normal login or compute node;
  that has not been checked yet.
- **The 55 ignored tests** are the two tiers below, which plain `cargo test` lists as ignored.
- **Some cases skip themselves** when the platform cannot host them (for example permission tests
  when run as root). A skipped case still prints `ok`; run with `-- --nocapture` to see the skip
  message.

## Extra tiers (not run by plain `cargo test`)

**S3 tier** (`tests/s3_tests.rs`, 54 tests). Runs a local S3 server on loopback inside the test
process and needs DuckDB's `httpfs` extension, which is downloaded once (an outbound download from
DuckDB's extension site; nothing is uploaded):

```bash
cargo build --locked --example extension-probe
sh packaging/extensions/fetch.sh target/debug/examples/extension-probe target/test-ext
XDU_TEST_EXTENSION_DIR=target/test-ext sh tests/s3-wire.sh "" 56
```

**Cross-filesystem tier** (`tests/mv_xfs_tests.rs`, 3 tests). Needs a writable directory on a
different filesystem from the temp directory, so a rename fails with `EXDEV`. On Linux `/dev/shm`
works:

```bash
mkdir -p /dev/shm/xdu-xfs
XDU_TEST_XFS_DIR=/dev/shm/xdu-xfs sh tests/xfs-wire.sh "" 3
```

The last number in each command is the minimum count of tests that must run and pass. Neither tier
has been run in this clone; CI runs both on every push to the upstream repo.

## Other checks

- **Man pages:** `for scd in doc/*.scd; do scdoc < "$scd" > /dev/null || echo "FAILED $scd"; done`
  (needs `scdoc`, available from conda-forge). See `AGENTS.md` § Commands for the literal checks.
- **Trying the tools by hand:** `.agents/factory/bin/temp_index.sh xdu-find --count` builds a
  throwaway index and runs a command against it.
- **Crawl benchmark:** `sh bench/run.sh smoke` builds a synthetic tree and checks that the index
  holds exactly its files. Real-filesystem timing is done with the scripts in `RUNS/`.
