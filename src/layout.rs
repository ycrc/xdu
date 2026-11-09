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
use std::ffi::OsString;
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

/// The name of GPFS's snapshot directory. Each `@GMT-…` entry below it is a read-only copy
/// of the tree it sits in, so walking it indexes the same files again under other paths;
/// `xdu` skips directories of this name unless `--include-snapshots` is given.
pub const SNAPSHOT_DIR: &str = ".snapshots";

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
    /// Whether `.snapshots` directories were walked. `None` for a manifest written before
    /// the setting existed; that xdu walked them, but whether the tree had any is unknown.
    pub include_snapshots: Option<bool>,
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
            include_snapshots: v["include_snapshots"].as_bool(),
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
        if let Some(include) = self.include_snapshots {
            v["include_snapshots"] = serde_json::Value::Bool(include);
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
/// `.snapshots` is left out unless `include_snapshots`, since the walk will not enter it.
fn subdirs(dir: &Path, include_snapshots: bool) -> Vec<(String, OsString)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<(String, OsString)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| include_snapshots || e.file_name() != SNAPSHOT_DIR)
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
/// Without `include_snapshots`, no split point lies in a `.snapshots` directory: depth and
/// wildcards pass over it, and a literal path through it is an error, because the walk skips
/// it and the partition would come out empty.
pub fn resolve_split_points(
    root: &Path,
    spec: &SplitSpec,
    include_snapshots: bool,
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
            for (name, real) in subdirs(&parent.path, include_snapshots) {
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
        if !include_snapshots && comps.contains(&SNAPSHOT_DIR) {
            anyhow::bail!(
                "Split path '{}' is inside a {} directory, which is skipped; pass \
                 --include-snapshots to index snapshots",
                pattern,
                SNAPSHOT_DIR
            );
        }
        let mut matches: Vec<SplitPoint> = vec![top.clone()];
        for comp in comps {
            let mut next = Vec::new();
            for parent in &matches {
                if comp.contains(['*', '?']) {
                    next.extend(
                        subdirs(&parent.path, include_snapshots)
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
pub fn list_partitions(index: &Path) -> Result<Vec<String>> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) -> Result<()> {
        let mut has_parquet = false;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                let child = if rel.is_empty() {
                    name
                } else {
                    format!("{}/{}", rel, name)
                };
                walk(&entry.path(), &child, out)?;
            } else if !rel.is_empty()
                && entry.path().extension().is_some_and(|ext| ext == "parquet")
            {
                has_parquet = true;
            }
        }
        if has_parquet {
            out.push(rel.to_string());
        }
        Ok(())
    }
    let mut partitions = Vec::new();
    if index.is_dir() {
        walk(index, "", &mut partitions)?;
    }
    partitions.sort();
    Ok(partitions)
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
            resolve_split_points(tmp.path(), &SplitSpec::default(), false).unwrap();
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
        let (points, warnings) = resolve_split_points(tmp.path(), &spec, false).unwrap();
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
            false,
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
            "alice/sub",
        ] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        let spec = SplitSpec {
            depth: 2,
            patterns: vec!["*/*".into()],
        };
        let (points, _) = resolve_split_points(tmp.path(), &spec, false).unwrap();
        assert_eq!(split_keys(&points), vec!["alice", "alice/sub"]);

        let (points, _) = resolve_split_points(tmp.path(), &spec, true).unwrap();
        assert_eq!(
            split_keys(&points),
            vec![
                ".snapshots",
                ".snapshots/@GMT-1",
                "alice",
                "alice/.snapshots",
                "alice/sub"
            ]
        );

        let literal = SplitSpec {
            depth: 1,
            patterns: vec!["alice/.snapshots".into()],
        };
        let msg = resolve_split_points(tmp.path(), &literal, false)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("--include-snapshots"), "{msg}");
        assert!(resolve_split_points(tmp.path(), &literal, true).is_ok());
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
            let err = resolve_split_points(tmp.path(), &spec, false)
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
        let err = resolve_split_points(tmp.path(), &spec, false)
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
            include_snapshots: Some(true),
        };
        m.save(tmp.path()).unwrap();
        let back = Manifest::load(tmp.path()).unwrap().unwrap();
        assert_eq!(back.root, "/data");
        assert_eq!(back.include_snapshots, Some(true));
        assert_eq!(back.split.patterns, vec!["a", "b"]);
        assert_eq!(back.split.depth, 2);
        assert!(!tmp.path().join("_xdu.json.partial").exists());
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
