# Nested (multi-level) partitions for xdu indexes

## Context
Today an index is exactly one level deep: `index/<top-level-dir>/*.parquet` plus `index/__root__/` for loose files.
On unbalanced trees (e.g. `Indexes/support_unbalanced`), one huge partition becomes one crawl work item, one
progress bar, one serial writer, and one large unit that every per-partition query (`xdu-view` drill-down,
`xdu-diff` joins, `-p` re-index) has to scan. The goal is to allow splitting at deeper directories
(e.g. `projects/bigproj/*`), so parquet files can live at several levels.

**Why this is feasible:** every row stores the absolute `path`. The partition is used only for (a) the
file layout and work unit, and (b) query pruning. The tree is never derived from the partition structure,
so only the code that assumes "partition = one path component" needs to change.

## Proposed layout
A partition key becomes a **relative directory path** (`alice`, `projects/bigproj/sub1`). The index mirrors it:

```
index/
  _xdu.json                 # NEW manifest: crawl root, version, split spec, size mode
  000000.parquet            # files directly in <root>          (replaces __root__/)
  alice/000000.parquet
  projects/000000.parquet   # files in projects/ not covered by a deeper partition
  projects/bigproj/000000.parquet
```

A partition directory holds the files under it that **no deeper partition owns**. Results:
- Whole index: `index/**/*.parquet` (DuckDB supports `**`).
- One partition's own files: `index/P/*.parquet`.
- A whole subtree: `index/P/*.parquet` + `index/P/**/*.parquet`. Pruning works directly on the path.
- Old indexes stay readable: if there's no manifest, treat it as the current layout (`*/*.parquet`, `__root__`).

## What has to change

### 1. Crawler, `src/bin/xdu.rs` `crawl()` (~l.227)

#### How crawl configuration works (detail)

TODAY the rule is fixed and not configurable:
- Each immediate subdirectory D of ROOT  ->  INDEX/D/000000.parquet, 000001.parquet, ...
- Loose files directly in ROOT           ->  INDEX/__root__/
- `-p a,b` only limits WHICH top-level dirs get crawled. It does not change WHERE the files go.

PROPOSED: the user chooses a set of "split points". A split point is a directory, given relative to ROOT,
that gets its own partition. ROOT itself is always a split point.

Ownership rule (the only rule): each file is written to the partition of the DEEPEST split point that
contains it. Its parquet chunks go to INDEX/<that split point's relative path>/.

How split points are specified (all optional, and they add together):
- `--split-depth N`: every directory at depth 1..N below ROOT is a split point.
  Default N=1, which gives exactly today's layout, so nothing changes unless asked.
- `--split P1,P2,...`: extra split points. Simple wildcards are allowed and are expanded by listing the
  directory at crawl start, e.g. `--split 'projects/*'` means every child of projects/.
- `--split-file FILE`: the same list, one path per line, for long lists.
- (later) `--split-from OLD_INDEX --max-files N`: pick split points automatically from file counts in a
  previous index, by repeatedly splitting any partition that has more than N files.

Worked example. Tree:
    ROOT/
      README                   (file)
      alice/...                (small)
      projects/
        notes.txt              (file)
        small/...              (small)
        bigproj/
          a/...  b/...  c/...  (huge)

Command:  xdu ROOT -o INDEX --split projects/bigproj,'projects/bigproj/*'
Split points: ROOT, alice, projects (depth 1 default), projects/bigproj, projects/bigproj/{a,b,c}
Resulting layout:
    INDEX/_xdu.json
    INDEX/000000.parquet                    README
    INDEX/alice/000000.parquet              everything under alice/
    INDEX/projects/000000.parquet           notes.txt + everything under projects/small/
    INDEX/projects/bigproj/000000.parquet   only files directly in bigproj/ (if any)
    INDEX/projects/bigproj/a/...            everything under bigproj/a/
    INDEX/projects/bigproj/b/...            (same for b, c)

How the crawl executes it:
- There is one work item per split point (it replaces today's one per top-level dir, plus __root__).
- Each work item walks its directory, but skips any child directory that is itself a split point
  (using jwalk `process_read_dir`). That is how the ownership rule is enforced: each file is seen by exactly
  one walker. The `__root__` + `max_depth(1)` special case goes away, because ROOT is just a split point
  whose children are all split points.
- Work items still share the one thread pool, so the huge branch is now several items running in parallel
  instead of one long tail.
- Split points that don't exist produce a warning and are skipped. Split points that are symlinks are not
  followed (same as today: follow_links=false).
- At the end, the resolved split list (wildcards already expanded) is written to `_xdu.json`. Readers use it
  as the authoritative partition list, and `-p` re-crawls reuse it, so the layout stays consistent.
- Changing the split points on an existing index requires a full re-crawl. The crawler removes parquet dirs
  that are not in the new list, or refuses to run without `--force`.

#### Implementation notes
- Build work items from the resolved split list. Each interior node gets a walker that **excludes child directories that are
  their own partitions**, using jwalk `process_read_dir` to drop those children. This replaces the
  current `__root__` + `max_depth(1)` special case.
- `PartitionBuffer` (`outdir.join(&self.partition)`) already works with a nested relative path. `finalize()`
  only prunes `NNNNNN.parquet`, so it won't touch sub-partition directories.
- Write `_xdu.json` at the end (root path, split list, size mode, schema version).
- `-p/--partition` re-index: the key becomes a relative path (a split point from the manifest). It re-crawls
  that one partition only. `-p projects --recursive` re-crawls it and every split point below it.

### 2. Shared helpers, `src/lib.rs`
- `list_partitions()` (l.723): make it a recursive walk that returns relative paths of directories containing `*.parquet`.
- `discover_index_root()` (l.747): read the root from the manifest. Keep the current heuristic as a fallback for old indexes.
  The heuristic is the fragile part today, so this is a robustness gain.
- `DiffSide::relation()` (l.790): glob `index/{P}/*.parquet`. This already works when `P` contains `/`.
- New helpers: `partition_glob(index, P)`, `all_glob(index)`, `partition_of_filename_sql()`. The last one is a regex
  that strips `index/` and `/NNNNNN.parquet` from `filename`, replacing the `.*/([^/]+)/[^/]+\.parquet$` regex
  that is now copied into several files.

### 3. Query tools
- `xdu-find`, `xdu-du`, `xdu-rm`: switch the `*/*.parquet` glob to `all_glob()`. `-u/-p P` should mean the subtree
  (P + descendants), which is what users expect. `--top-partitions` reports relative paths.
- `xdu-du` per-partition summary: group by **first path component** for the top level, which matches `du` output,
  rather than by raw partition.

### 4. `xdu-view` (the largest change)
Navigation is currently two-mode: a partition list (`current_partition == None`) and then a path tree inside one
partition (`partition_root`, `partition_source`). With nesting, the cleanest model is **path-only navigation**:
- The source for viewing path X is the partitions that are ancestor-or-self of X, or descendants of X (this is pruning).
- The top-level listing is just `query_directory_entries(root)`. The partition list and the `__root__` merge
  (`query_partition_entries`, `query_root_files`) go away.
- Compare mode: cache diff tables per partition as now, then union the relevant ones for X.
This means refactoring `current_partition` / `partition_root` / `Column.partition` across about 30 call sites.
A smaller interim option is to keep the two-level UI and treat nested partitions as invisible for navigation
(top-level entries = first component, source = subtree glob). That gets most of the benefit with a much smaller diff.

### 5. `xdu-diff`
The per-partition FULL OUTER JOIN is only correct if **both indexes use the same partition layout**.
Plan: join per **top-level component** using subtree globs, which is correct for any layout, or per shared partition
when the manifests show identical split specs (faster).

## Limitations / risks
1. **Layout mismatch in diffs:** if the old and new indexes split differently, per-partition comparison is wrong unless you fall back to coarser units (see 5).
2. **Stale sub-partitions:** if you re-crawl with a different split spec, old parquet files at the previous split
   points stay behind and files get counted twice. Mitigation: the manifest records the spec, and readers only glob the
   listed partitions. The crawler warns about, or removes, parquet dirs that aren't in the spec.
3. **Name collisions:** a real directory named `__root__`, or a file called `000000.parquet` in the index layout. Also
   glob metacharacters (`*?[]`) in directory names, which is already a latent bug. Readers using the manifest's
   explicit file lists instead of globs avoid this.
4. **Many small files:** splitting too finely creates thousands of small parquet files. DuckDB's per-file
   open and metadata cost dominates, and GPFS metadata load rises. The split should stay coarse (tens to low thousands of partitions).
5. **Choosing split points:** this has to be done by hand (`--split`) unless you add a pre-scan or reuse a previous index's counts
   (e.g. `--split-from old_index --max-files 5M`). That's a good follow-up, since `xdu-find --top-partitions` already reports sizes.
6. **Partition key semantics change** for `-p/-u` flags (path vs. name). Bare names still work for top-level keys.
7. **External consumers** using `index/*/*.parquet` will miss nested data. Document that they should use `index/**/*.parquet`.

## Suggested order
1. lib helpers + manifest + backward-compatible reader (no behavior change for old indexes).
2. Crawler `--split` with exclusion walker.
3. find/du/rm glob switch.
4. xdu-diff top-level-component joins.
5. xdu-view: interim subtree-glob approach first, path-only navigation refactor later.

## Verification
- `tests/crawl_tests.rs`: build a temp tree with a deep heavy branch. Crawl with `--split a,a/b` and check that every file
  appears exactly once across `**/*.parquet`, and that row counts match a flat crawl.
- `tests/diff_tests.rs`: diff a flat index against a nested index of the same tree. Expect all `unchanged`.
- Old-index compatibility: run `xdu-du`, `xdu-find --count`, and `xdu-diff` against the existing `Indexes/GMT-*` and check that results are unchanged.
- Manual: `xdu-view -i <nested index>`, drill into the split branch and confirm the totals match `xdu-du`.
- `cargo test`.

## Implementation status (2026-10-23)

Implemented: steps 1-4 and the interim xdu-view approach from step 5.

Deviations from the plan above:
- Files directly in the crawl root still go to `INDEX/__root__/` (not `INDEX/*.parquet`).
  With the default `--split-depth 1`, the layout is therefore identical to before, apart from the new
  `_xdu.json`, so older xdu tools and external `*/*.parquet` queries keep working on flat indexes.
- Readers find partitions by scanning the index for directories containing `*.parquet`. The manifest
  supplies the crawl root and split spec, not the partition list. Leftover partitions are removed by the
  next full crawl, which deletes only `NNNNNN.parquet` chunk files.
- xdu-view always compares whole top-level subtrees in compare mode. xdu-diff compares partition by
  partition only when both manifests have the same split spec (an index without a manifest counts as
  depth 1, no patterns).

Not done: path-only navigation in xdu-view; `--split-from` auto-splitting.
