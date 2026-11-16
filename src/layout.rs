//! Nested partitions: which directories become partitions, the manifest that records the
//! choice, and the helpers readers use to map a chunk back to its partition.
//!
//! A partition is named by its directory path relative to the crawl root (`alice`,
//! `projects/big`), or `__root__` for what no split point claims. Its chunks live in
//! `<index>/<key>/NNNNNN.parquet`, so partition directories can nest: `projects/` holds the
//! chunks of `projects` and the directory of `projects/big`. A file belongs to the deepest
//! split point containing it, and every walker skips the split points below its own, so each
//! file is indexed exactly once.
//!
//! The default spec (`depth` 1, no patterns) makes every top-level directory a split point,
//! which is the flat layout `INDEX_FORMAT_VERSION` describes. Only an index with a split point
//! below the top level is written as `NESTED_INDEX_FORMAT_VERSION`, so a reader that globs
//! `*/*.parquet` refuses it instead of silently missing the nested chunks.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{IndexLocator, ROOT_PARTITION};

/// Index metadata written by `xdu` at the index root.
///
/// Not a dotfile, so `ls` shows it beside the partitions; it is in `RESERVED_INDEX_NAMES`
/// because a top-level source directory of this name would be written over it.
pub const MANIFEST_FILE: &str = "_xdu.json";

/// The newest manifest layout this xdu reads and the one it writes.
pub const MANIFEST_VERSION: u64 = 1;

/// The snapshot directory names `xdu` skips by default: GPFS's `.snapshots`, and the
/// `.snapshot` of NetApp, PowerScale and VAST. Each entry below one is a read-only copy of the
/// tree it sits in, so walking it indexes the same files again under other paths.
pub const DEFAULT_SNAPSHOT_DIRS: &[&str] = &[".snapshots", ".snapshot"];

/// The directory names a crawl skips as snapshots, sorted and without duplicates: the
/// defaults plus any `--snapshot-dir`, or none under `--include-snapshots`. One value is
/// consulted by the top-level listing, the walker and `resolve_split_points`, which must agree
/// or a snapshot could still become a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDirs(Vec<String>);

impl SnapshotDirs {
    pub fn new(include_snapshots: bool, extra: &[String]) -> Self {
        if include_snapshots {
            return SnapshotDirs(Vec::new());
        }
        let names = DEFAULT_SNAPSHOT_DIRS.iter().map(|s| s.to_string());
        Self::from_names(names.chain(extra.iter().cloned()).collect())
    }

    /// A list read back from a manifest, in the canonical order.
    pub fn from_names(mut names: Vec<String>) -> Self {
        names.sort();
        names.dedup();
        SnapshotDirs(names)
    }

    pub fn names(&self) -> &[String] {
        &self.0
    }

    /// Whether a directory with this name is skipped. Compared on the raw bytes, so a
    /// non-UTF-8 name never matches by lossy conversion.
    pub fn skips(&self, name: &OsStr) -> bool {
        self.0.iter().any(|n| OsStr::new(n) == name)
    }

    /// The first component of a `/`-separated relative path that is skipped, if any.
    pub fn first_in_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        path.split('/').find(|c| self.skips(OsStr::new(c)))
    }

    /// The list for messages: `.snapshot, .snapshots`, or `none` under `--include-snapshots`.
    pub fn describe(&self) -> String {
        if self.0.is_empty() {
            "none".to_string()
        } else {
            self.0.join(", ")
        }
    }
}

impl Default for SnapshotDirs {
    fn default() -> Self {
        SnapshotDirs::new(false, &[])
    }
}

/// A manifest's snapshot setting. Before the list existed the manifest held only
/// `include_snapshots`, and that xdu skipped `.snapshots` alone, so `false` reads as that
/// one-name list rather than today's defaults.
fn snapshot_dirs_field(v: &serde_json::Value) -> Option<SnapshotDirs> {
    if let Some(names) = v["snapshot_dirs"].as_array() {
        let names = names
            .iter()
            .filter_map(|n| n.as_str().map(String::from))
            .collect();
        return Some(SnapshotDirs::from_names(names));
    }
    match v["include_snapshots"].as_bool()? {
        true => Some(SnapshotDirs::new(true, &[])),
        false => Some(SnapshotDirs::from_names(vec![".snapshots".to_string()])),
    }
}

/// `--snapshot-dir`'s value parser: one literal directory name.
pub fn parse_snapshot_dir(name: &str) -> Result<String, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(format!(
            "'{name}' is not a directory name; give one name such as .snapshot, not a path"
        ));
    }
    if name.contains(['*', '?', '[']) {
        return Err(format!(
            "'{name}' holds a wildcard; snapshot directory names are matched literally"
        ));
    }
    Ok(name.to_string())
}

/// Which directories become partitions (split points).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitSpec {
    /// Every directory at depth `1..=depth` below the root is a split point.
    pub depth: usize,
    /// Further split points relative to the root. A component may use `*` and `?`.
    pub patterns: Vec<String>,
}

impl Default for SplitSpec {
    /// One partition per top-level directory: the flat layout.
    fn default() -> Self {
        Self {
            depth: 1,
            patterns: Vec::new(),
        }
    }
}

impl SplitSpec {
    /// Patterns trimmed, sorted and deduplicated, so two specs compare by meaning.
    pub fn normalized(&self) -> Self {
        let mut patterns: Vec<String> = self
            .patterns
            .iter()
            .map(|p| p.trim().trim_matches('/').to_string())
            .filter(|p| !p.is_empty())
            .collect();
        patterns.sort();
        patterns.dedup();
        Self {
            depth: self.depth,
            patterns,
        }
    }

    /// True when both specs assign every path to the same partition.
    pub fn same_layout(&self, other: &SplitSpec) -> bool {
        self.normalized() == other.normalized()
    }

    /// True for the flat layout, the only one an `s3://` destination accepts.
    pub fn is_default(&self) -> bool {
        self.same_layout(&SplitSpec::default())
    }
}

/// The contents of `<index>/_xdu.json`.
#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pub version: u64,
    /// The crawl root, without a trailing slash.
    pub root: String,
    pub split: SplitSpec,
    /// The size mode's label (`disk-usage`, `apparent-size`, `block-rounded(N)`), recorded so
    /// a `--partition` run that mixes modes can say so.
    pub size_mode: String,
    /// The snapshot directory names the crawl skipped. `None` for a manifest written before
    /// any snapshot setting existed; that xdu walked them, but whether the tree had any is
    /// unknown.
    pub snapshot_dirs: Option<SnapshotDirs>,
}

impl Manifest {
    /// Read an index's manifest. `None` for an index without one, which is read as the flat
    /// layout: every index written before nested partitions existed is one.
    pub fn load(index: &Path) -> Result<Option<Manifest>> {
        let path = index.join(MANIFEST_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("Reading {}", path.display())));
            }
        };
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Invalid manifest {}: {}", path.display(), e))?;
        let version = v["version"].as_u64().unwrap_or(0);
        if version > MANIFEST_VERSION {
            anyhow::bail!(
                "{} has version {}; this xdu supports up to {}",
                path.display(),
                version,
                MANIFEST_VERSION
            );
        }
        let root = v["root"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Manifest {} has no root", path.display()))?
            .trim_end_matches('/')
            .to_string();
        let depth = v["split"]["depth"].as_u64().unwrap_or(1) as usize;
        let patterns = v["split"]["patterns"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(Manifest {
            version,
            root,
            split: SplitSpec { depth, patterns },
            size_mode: v["size_mode"].as_str().unwrap_or("").to_string(),
            snapshot_dirs: snapshot_dirs_field(&v),
        }))
    }

    /// Write the manifest through a `.partial` and a rename, so a reader never sees half of it.
    pub fn save(&self, index: &Path) -> Result<()> {
        let split = self.split.normalized();
        let mut v = serde_json::json!({
            "version": self.version,
            "root": self.root,
            "split": { "depth": split.depth, "patterns": split.patterns },
            "size_mode": self.size_mode,
        });
        if let Some(ref dirs) = self.snapshot_dirs {
            v["snapshot_dirs"] = serde_json::json!(dirs.names());
        }
        let path = index.join(MANIFEST_FILE);
        let tmp = index.join(format!("{}.partial", MANIFEST_FILE));
        std::fs::write(&tmp, format!("{}\n", serde_json::to_string_pretty(&v)?))
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("Failed to rename {} into place", tmp.display()))?;
        Ok(())
    }
}

/// The split spec a local index was built with; the flat layout when it has no manifest.
pub fn index_split_spec(index: &Path) -> Result<SplitSpec> {
    Ok(Manifest::load(index)?.map(|m| m.split).unwrap_or_default())
}

/// Match one path component against a pattern with `*` and `?`.
///
/// Neither wildcard crosses `/`: split patterns are expanded a component at a time, so `a/*`
/// names the children of `a` and nothing deeper.
pub fn component_glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A directory that gets its own partition: the key it is stored under, and the real path
/// the crawl walks.
///
/// The key is lossy UTF-8, like every partition name; the path keeps the directory's real
/// bytes, so a non-UTF-8 name is still walked where it is rather than at its lossy spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitPoint {
    pub key: String,
    pub path: PathBuf,
}

/// Real (non-symlink) subdirectories of `dir` as (lossy name, real name), sorted. An
/// unreadable directory has none: the crawl reports it as an error when it gets there.
/// Snapshot directories are left out, since the walk will not enter them.
fn subdirs(dir: &Path, snapshots: &SnapshotDirs) -> Vec<(String, OsString)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<(String, OsString)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| !snapshots.skips(&e.file_name()))
        .map(|e| (e.file_name().to_string_lossy().to_string(), e.file_name()))
        .collect();
    names.sort();
    names
}

/// Why `rel` is not a real directory under `root`, naming the first component that is not.
fn explain_missing_dir(root: &Path, rel: &str) -> String {
    let mut path = root.to_path_buf();
    for comp in rel.split('/') {
        path.push(comp);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return format!("{} does not exist", path.display());
            }
            Err(e) => return format!("cannot access {}: {}", path.display(), e),
            Ok(m) if m.file_type().is_symlink() => {
                let target = std::fs::read_link(&path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_default();
                return format!(
                    "{} is a symlink (to {}); symlinks are not followed, so nothing below it \
                     is indexed",
                    path.display(),
                    target
                );
            }
            Ok(m) if !m.is_dir() => return format!("{} is not a directory", path.display()),
            Ok(_) => {}
        }
    }
    format!("{} is not a directory", path.display())
}

/// Resolve a split spec against the tree under `root`.
///
/// Returns the split points sorted by key (the root is implied, not listed), and a warning for
/// each wildcard pattern that matched nothing. A literal path that is not a real directory is
/// an error rather than a warning: a typo would otherwise leave a whole subtree in its
/// parent's partition without a word. Two directories whose names collapse onto one lossy key
/// are an error too, since both would write the same partition.
///
/// No split point lies in a skipped snapshot directory: depth and wildcards pass over it, and
/// a literal path through it is an error, because the walk skips it and the partition would
/// come out empty.
pub fn resolve_split_points(
    root: &Path,
    spec: &SplitSpec,
    snapshots: &SnapshotDirs,
) -> Result<(Vec<SplitPoint>, Vec<String>)> {
    let mut points: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut warnings = Vec::new();

    let insert = |points: &mut BTreeMap<String, PathBuf>, point: SplitPoint| -> Result<()> {
        match points.get(&point.key) {
            Some(existing) if *existing != point.path => anyhow::bail!(
                "two directories in {} map to the same partition name '{}' (a non-UTF-8 name \
                 is stored lossily); rename one before indexing",
                root.display(),
                point.key
            ),
            Some(_) => Ok(()),
            None => {
                points.insert(point.key, point.path);
                Ok(())
            }
        }
    };
    let child = |parent: &SplitPoint, name: &str, real: &OsString| SplitPoint {
        key: if parent.key.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", parent.key, name)
        },
        path: parent.path.join(real),
    };
    let top = SplitPoint {
        key: String::new(),
        path: root.to_path_buf(),
    };

    let mut level: Vec<SplitPoint> = vec![top.clone()];
    for _ in 0..spec.depth {
        let mut next = Vec::new();
        for parent in &level {
            for (name, real) in subdirs(&parent.path, snapshots) {
                let point = child(parent, &name, &real);
                insert(&mut points, point.clone())?;
                next.push(point);
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }

    for pattern in &spec.normalized().patterns {
        let comps: Vec<&str> = pattern.split('/').collect();
        if comps
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == "..")
        {
            anyhow::bail!(
                "Invalid split path '{}': use a relative path without '.' or '..'",
                pattern
            );
        }
        if pattern.contains("**") {
            anyhow::bail!(
                "Invalid split path '{}': '**' is not supported, because wildcards match a \
                 single path component. Use '*' for one level (e.g. 'a/*'), list deeper levels \
                 explicitly (e.g. 'a/*,a/*/*'), or use --split-depth",
                pattern
            );
        }
        if let Some(dir) = snapshots.first_in_path(pattern) {
            anyhow::bail!(
                "Split path '{}' is inside a {} directory, which is skipped as a snapshot; \
                 pass --include-snapshots to index snapshots",
                pattern,
                dir
            );
        }
        let mut matches: Vec<SplitPoint> = vec![top.clone()];
        for comp in comps {
            let mut next = Vec::new();
            for parent in &matches {
                if comp.contains(['*', '?']) {
                    next.extend(
                        subdirs(&parent.path, snapshots)
                            .iter()
                            .filter(|(name, _)| component_glob_match(comp, name))
                            .map(|(name, real)| child(parent, name, real)),
                    );
                } else if std::fs::symlink_metadata(parent.path.join(comp))
                    .is_ok_and(|m| m.is_dir())
                {
                    next.push(child(parent, comp, &OsString::from(comp)));
                }
            }
            matches = next;
        }
        if matches.is_empty() {
            if pattern.contains(['*', '?']) {
                warnings.push(format!("split path '{}' matched no directories", pattern));
            } else {
                anyhow::bail!(
                    "Split path '{}': {}",
                    pattern,
                    explain_missing_dir(root, pattern)
                );
            }
        }
        for point in matches {
            insert(&mut points, point)?;
        }
    }

    Ok((
        points
            .into_iter()
            .map(|(key, path)| SplitPoint { key, path })
            .collect(),
        warnings,
    ))
}

/// The keys of a set of split points.
pub fn split_keys(points: &[SplitPoint]) -> Vec<String> {
    points.iter().map(|p| p.key.clone()).collect()
}

/// True when some split point lies below the top level, which makes the index nested.
pub fn is_nested(split_points: &[String]) -> bool {
    split_points.iter().any(|p| p.contains('/'))
}

/// Depth of a partition key below the crawl root (`alice` is 1, `projects/big` is 2).
pub fn key_depth(key: &str) -> usize {
    key.split('/').count()
}

/// First component of a partition key (`projects/big` is `projects`).
pub fn top_level(key: &str) -> &str {
    key.split('/').next().unwrap_or(key)
}

/// Distinct top-level directories of a set of partition keys, sorted.
pub fn top_level_partitions(partitions: &[String]) -> Vec<String> {
    let set: BTreeSet<&str> = partitions.iter().map(|p| top_level(p)).collect();
    set.into_iter().map(String::from).collect()
}

/// The partitions of a local index: every directory holding a `.parquet` chunk, at any
/// depth, as sorted keys relative to the index root.
///
/// Every directory must be readable. The crawler lists with this, since a partition it
/// cannot see is one it cannot prune; the readers use `readable_partitions`.
pub fn list_partitions(index: &Path) -> Result<Vec<String>> {
    let mut found = Readable::default();
    if index.is_dir() {
        walk_partitions(index, "", false, &mut found)?;
    }
    found.partitions.sort();
    Ok(found.partitions)
}

/// What a reader can see of a local index: the partitions it can read, and the directories it
/// was refused, whose partitions it cannot even name.
#[derive(Debug, Default, PartialEq)]
pub struct Readable {
    pub partitions: Vec<String>,
    /// Keys of the directories that refused a listing, sorted.
    pub unreadable: Vec<String>,
}

impl Readable {
    /// The one stderr line a reader prints when partitions were left out, or `None`.
    ///
    /// DuckDB's glob skips a directory it cannot open without a word, so without this an
    /// index whose partitions carry their sources' permissions reads as a smaller tree, at
    /// exit 0, for anyone outside some of the groups.
    pub fn note(&self, index: &Path) -> Option<String> {
        let n = self.unreadable.len();
        (n > 0).then(|| {
            format!(
                "Note: {} director{} of index {} {} not readable by you; the partitions in {} \
                 are left out.",
                n,
                if n == 1 { "y" } else { "ies" },
                index.display(),
                if n == 1 { "is" } else { "are" },
                if n == 1 { "it" } else { "them" },
            )
        })
    }
}

/// The partitions of a local index this process can read, under `scope` when one is given.
///
/// A directory whose listing fails with `PermissionDenied` is recorded in `unreadable` and not
/// entered; any other error fails. A `scope` that is itself unreadable, or lies under a
/// directory that is, is an error naming it, since every answer for it would be empty.
pub fn readable_partitions(index: &Path, scope: Option<&str>) -> Result<Readable> {
    let mut found = Readable::default();
    match scope {
        None => {
            if index.is_dir() {
                walk_partitions(index, "", true, &mut found)?;
            }
        }
        Some(scope) => {
            let dir = index.join(scope);
            match std::fs::read_dir(&dir) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => anyhow::bail!(
                    "Partition '{}' of index {} is not readable by you",
                    scope,
                    index.display()
                ),
                // Absent: the query's own "No files found" names the glob it tried.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => walk_partitions(&dir, scope, true, &mut found)?,
            }
        }
    }
    found.partitions.sort();
    found.unreadable.sort();
    Ok(found)
}

fn walk_partitions(dir: &Path, rel: &str, tolerant: bool, out: &mut Readable) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Err(e) if tolerant && e.kind() == std::io::ErrorKind::PermissionDenied => {
            out.unreadable.push(rel.to_string());
            return Ok(());
        }
        r => r.with_context(|| format!("Reading index directory {}", dir.display()))?,
    };
    let mut has_parquet = false;
    for entry in entries {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            let child = if rel.is_empty() {
                name
            } else {
                format!("{}/{}", rel, name)
            };
            walk_partitions(&entry.path(), &child, tolerant, out)?;
        } else if !rel.is_empty() && entry.path().extension().is_some_and(|ext| ext == "parquet") {
            has_parquet = true;
        }
    }
    if has_parquet {
        out.partitions.push(rel.to_string());
    }
    Ok(())
}

/// The index root as the readers' globs spell it, so `filename` values start with it.
fn index_prefix(index: &IndexLocator) -> String {
    match index {
        IndexLocator::Local(path) => path.display().to_string(),
        IndexLocator::S3(locator) => locator.to_string(),
    }
}

/// SQL giving each row's partition key, over a `read_parquet(..., filename=true)` of `index`.
///
/// The key is the chunk's directory relative to the index root. Only the prefix length
/// reaches the SQL text, so an `s3://` prefix stays a bound value.
pub fn partition_key_sql(index: &IndexLocator) -> String {
    format!(
        r"regexp_extract(substr(filename, {}), '^(.*)/[^/]+\.parquet$', 1)",
        index_prefix(index).chars().count() + 2
    )
}

/// SQL giving each row's top-level partition (see `partition_key_sql`): the directory a
/// nested partition is listed under.
pub fn top_level_key_sql(index: &IndexLocator) -> String {
    format!("split_part({}, '/', 1)", partition_key_sql(index))
}

/// Normalize a reader's `-u` value: nested keys are written with `/`, and a trailing or
/// leading one is the same partition.
pub fn normalize_partition_arg(partition: &str) -> String {
    partition.trim_matches('/').to_string()
}

/// True when `key` is `scope` or nested below it.
pub fn key_in_subtree(key: &str, scope: &str) -> bool {
    key == scope
        || (scope != ROOT_PARTITION
            && key.len() > scope.len()
            && key.starts_with(scope)
            && key.as_bytes()[scope.len()] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_component_glob_match() {
        assert!(component_glob_match("*", "anything"));
        assert!(component_glob_match("a*", "alice"));
        assert!(component_glob_match("?ob", "bob"));
        assert!(component_glob_match("*ce", "alice"));
        assert!(!component_glob_match("a*", "bob"));
        assert!(!component_glob_match("?", "ab"));
        assert!(component_glob_match("a*b*c", "aXXbYYc"));
        assert!(!component_glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn test_split_spec_normalized_and_default() {
        let spec = SplitSpec {
            depth: 1,
            patterns: vec![" b/ ".into(), "/a".into(), "b".into(), "".into()],
        };
        assert_eq!(spec.normalized().patterns, vec!["a", "b"]);
        assert!(SplitSpec::default().is_default());
        assert!(!spec.is_default());
        assert!(
            SplitSpec {
                depth: 1,
                patterns: vec!["/".into()]
            }
            .is_default()
        );
    }

    fn tree() -> TempDir {
        let tmp = TempDir::new().unwrap();
        for d in [
            "alice",
            "projects/big/x",
            "projects/big/y",
            "projects/small",
        ] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        fs::write(tmp.path().join("loose.txt"), b"x").unwrap();
        tmp
    }

    #[test]
    fn test_resolve_split_points_depth_and_patterns() {
        let tmp = tree();
        let (points, warnings) =
            resolve_split_points(tmp.path(), &SplitSpec::default(), &SnapshotDirs::default())
                .unwrap();
        assert_eq!(split_keys(&points), vec!["alice", "projects"]);
        assert_eq!(points[1].path, tmp.path().join("projects"));
        assert!(warnings.is_empty());
        assert!(!is_nested(&split_keys(&points)));

        let spec = SplitSpec {
            depth: 1,
            patterns: vec![
                "projects/big".into(),
                "projects/big/*".into(),
                "nope*".into(),
            ],
        };
        let (points, warnings) =
            resolve_split_points(tmp.path(), &spec, &SnapshotDirs::default()).unwrap();
        let points = split_keys(&points);
        assert_eq!(
            points,
            vec![
                "alice",
                "projects",
                "projects/big",
                "projects/big/x",
                "projects/big/y"
            ]
        );
        assert_eq!(warnings.len(), 1);
        assert!(is_nested(&points));

        let (points, _) = resolve_split_points(
            tmp.path(),
            &SplitSpec {
                depth: 0,
                patterns: vec![],
            },
            &SnapshotDirs::default(),
        )
        .unwrap();
        assert!(points.is_empty());
    }

    #[test]
    fn test_resolve_split_points_skips_snapshots() {
        let tmp = TempDir::new().unwrap();
        for d in [
            ".snapshots/@GMT-1/alice",
            "alice/.snapshots/@GMT-1",
            "alice/.snapshot/hourly.0",
            "alice/sub",
        ] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        let spec = SplitSpec {
            depth: 2,
            patterns: vec!["*/*".into()],
        };
        let (points, _) =
            resolve_split_points(tmp.path(), &spec, &SnapshotDirs::default()).unwrap();
        assert_eq!(split_keys(&points), vec!["alice", "alice/sub"]);

        let (points, _) =
            resolve_split_points(tmp.path(), &spec, &SnapshotDirs::new(true, &[])).unwrap();
        assert_eq!(
            split_keys(&points),
            vec![
                ".snapshots",
                ".snapshots/@GMT-1",
                "alice",
                "alice/.snapshot",
                "alice/.snapshots",
                "alice/sub"
            ]
        );

        // A name added with --snapshot-dir is skipped like the defaults.
        let extra = SnapshotDirs::new(false, &["sub".to_string()]);
        let (points, _) = resolve_split_points(tmp.path(), &spec, &extra).unwrap();
        assert_eq!(split_keys(&points), vec!["alice"]);

        let literal = SplitSpec {
            depth: 1,
            patterns: vec!["alice/.snapshot".into()],
        };
        let msg = resolve_split_points(tmp.path(), &literal, &SnapshotDirs::default())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("inside a .snapshot directory"), "{msg}");
        assert!(msg.contains("--include-snapshots"), "{msg}");
        assert!(resolve_split_points(tmp.path(), &literal, &SnapshotDirs::new(true, &[])).is_ok());
    }

    #[test]
    fn test_resolve_split_points_rejects_missing_dotdot_and_double_star() {
        let tmp = tree();
        for (pattern, needle) in [
            ("ghost", "does not exist"),
            ("loose.txt", "is not a directory"),
            ("a/../b", "without '.' or '..'"),
            ("projects/**", "'**' is not supported"),
        ] {
            let spec = SplitSpec {
                depth: 1,
                patterns: vec![pattern.into()],
            };
            let err = resolve_split_points(tmp.path(), &spec, &SnapshotDirs::default())
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "{pattern}: {err}");
        }
    }

    #[test]
    fn test_resolve_split_points_names_a_symlink() {
        let tmp = tree();
        std::os::unix::fs::symlink(tmp.path().join("alice"), tmp.path().join("link")).unwrap();
        let spec = SplitSpec {
            depth: 0,
            patterns: vec!["link".into()],
        };
        let err = resolve_split_points(tmp.path(), &spec, &SnapshotDirs::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a symlink"), "{err}");
    }

    #[test]
    fn test_manifest_round_trip_and_absent() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(Manifest::load(tmp.path()).unwrap(), None);
        assert!(index_split_spec(tmp.path()).unwrap().is_default());
        let m = Manifest {
            version: MANIFEST_VERSION,
            root: "/data".into(),
            split: SplitSpec {
                depth: 2,
                patterns: vec!["b".into(), "a".into()],
            },
            size_mode: "disk-usage".into(),
            snapshot_dirs: Some(SnapshotDirs::new(false, &[".zfs".to_string()])),
        };
        m.save(tmp.path()).unwrap();
        let back = Manifest::load(tmp.path()).unwrap().unwrap();
        assert_eq!(back.root, "/data");
        assert_eq!(
            back.snapshot_dirs.unwrap().names(),
            [".snapshot", ".snapshots", ".zfs"]
        );
        assert_eq!(back.split.patterns, vec!["a", "b"]);
        assert_eq!(back.split.depth, 2);
        assert!(!tmp.path().join("_xdu.json.partial").exists());
    }

    /// A manifest from before the list existed records `include_snapshots` alone. That xdu
    /// skipped `.snapshots` and nothing else, so `false` must not read as today's defaults,
    /// or a `--partition` run would mix the two rules without a word.
    #[test]
    fn test_manifest_reads_the_older_snapshot_setting() {
        let tmp = TempDir::new().unwrap();
        let write = |extra: &str| {
            let text = format!(
                r#"{{"version": 1, "root": "/data", "split": {{"depth": 1, "patterns": []}},
                   "size_mode": "disk-usage"{extra}}}"#
            );
            fs::write(tmp.path().join(MANIFEST_FILE), text).unwrap();
            Manifest::load(tmp.path()).unwrap().unwrap().snapshot_dirs
        };
        assert_eq!(
            write(r#", "include_snapshots": false"#).unwrap().names(),
            [".snapshots"]
        );
        assert!(
            write(r#", "include_snapshots": true"#)
                .unwrap()
                .names()
                .is_empty()
        );
        assert_eq!(write(""), None);
    }

    #[test]
    fn test_snapshot_dirs() {
        let dirs = SnapshotDirs::default();
        assert_eq!(dirs.names(), [".snapshot", ".snapshots"]);
        assert!(dirs.skips(OsStr::new(".snapshot")));
        assert!(!dirs.skips(OsStr::new(".snapshotsx")));
        assert_eq!(dirs.first_in_path("a/.snapshot/b"), Some(".snapshot"));
        assert_eq!(dirs.first_in_path("a/b"), None);
        assert_eq!(dirs.describe(), ".snapshot, .snapshots");
        // Repeating a default changes nothing, so the recorded list stays comparable.
        assert_eq!(SnapshotDirs::new(false, &[".snapshots".to_string()]), dirs);
        let none = SnapshotDirs::new(true, &[]);
        assert!(!none.skips(OsStr::new(".snapshots")));
        assert_eq!(none.describe(), "none");

        assert_eq!(parse_snapshot_dir(".zfs"), Ok(".zfs".to_string()));
        for bad in ["", ".", "..", "a/b", ".snap*"] {
            assert!(parse_snapshot_dir(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_list_partitions_nested() {
        let tmp = TempDir::new().unwrap();
        for p in [
            "__root__",
            "alice",
            "projects",
            "projects/big",
            "projects/big/x",
        ] {
            fs::create_dir_all(tmp.path().join(p)).unwrap();
            fs::write(tmp.path().join(p).join("000000.parquet"), b"").unwrap();
        }
        fs::create_dir_all(tmp.path().join("empty/dir")).unwrap();
        assert_eq!(
            list_partitions(tmp.path()).unwrap(),
            vec![
                "__root__",
                "alice",
                "projects",
                "projects/big",
                "projects/big/x"
            ]
        );
        assert_eq!(
            top_level_partitions(&list_partitions(tmp.path()).unwrap()),
            vec!["__root__", "alice", "projects"]
        );
    }

    #[test]
    fn test_readable_partitions_records_refused_directories() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = TempDir::new().unwrap();
        for p in ["alice", "bob", "projects", "projects/big"] {
            fs::create_dir_all(tmp.path().join(p)).unwrap();
            fs::write(tmp.path().join(p).join("000000.parquet"), b"").unwrap();
        }
        let lock = |p: &str, mode| {
            fs::set_permissions(tmp.path().join(p), fs::Permissions::from_mode(mode)).unwrap()
        };
        lock("bob", 0o000);
        lock("projects/big", 0o000);
        let all = readable_partitions(tmp.path(), None);
        let scoped = readable_partitions(tmp.path(), Some("projects"));
        let refused = readable_partitions(tmp.path(), Some("bob"));
        let strict = list_partitions(tmp.path());
        lock("bob", 0o755);
        lock("projects/big", 0o755);

        let all = all.unwrap();
        assert_eq!(all.partitions, vec!["alice", "projects"]);
        assert_eq!(all.unreadable, vec!["bob", "projects/big"]);
        assert!(
            all.note(tmp.path())
                .unwrap()
                .contains("2 directories of index")
        );
        let scoped = scoped.unwrap();
        assert_eq!(scoped.partitions, vec!["projects"]);
        assert_eq!(scoped.unreadable, vec!["projects/big"]);
        assert!(refused.unwrap_err().to_string().contains("Partition 'bob'"));
        assert!(
            strict.is_err(),
            "the crawler's listing must not skip a directory"
        );
        assert_eq!(
            readable_partitions(tmp.path(), None)
                .unwrap()
                .note(tmp.path()),
            None
        );
    }

    #[test]
    fn test_key_helpers() {
        assert_eq!(top_level("projects/big"), "projects");
        assert_eq!(key_depth("projects/big"), 2);
        assert!(key_in_subtree("projects/big", "projects"));
        assert!(key_in_subtree("projects", "projects"));
        assert!(!key_in_subtree("projectsX", "projects"));
        assert!(!key_in_subtree("alice", ROOT_PARTITION));
        assert_eq!(normalize_partition_arg("/projects/big/"), "projects/big");
    }

    #[test]
    fn test_partition_key_sql_offsets_past_the_prefix() {
        let local = IndexLocator::Local("/idx".into());
        assert!(partition_key_sql(&local).contains("substr(filename, 6)"));
        assert!(top_level_key_sql(&local).starts_with("split_part("));
    }
}
