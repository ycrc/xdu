//! Readers over an index some of whose partition directories the reader cannot open, as when
//! each carries its source directory's group access.
//!
//! DuckDB's glob skips such a directory without a word, so every reader must say how much it
//! left out, a `-u` naming one must fail naming it, and a comparison must not read a directory
//! readable in only one index as every file in it added or removed. Each case locks a directory
//! with mode 000, which binds every user but root, so each skips itself under root.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use common::{build_index, create_test_file, find_count, run_find, run_with_stdin, run_xdu};

const NOTE: &str = "not readable by you; the partitions in";

fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// A directory set to mode 000 for the life of the guard, restored on drop so the temp dir
/// can be removed even when an assertion fails.
struct Locked(PathBuf);

impl Locked {
    fn new(dir: PathBuf) -> Self {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        Locked(dir)
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

/// `alice` with one 100-byte file, `bob` with two of 200 and 300, and one loose 50-byte file.
fn source_tree(root: &Path) {
    fs::create_dir_all(root.join("alice")).unwrap();
    fs::create_dir_all(root.join("bob")).unwrap();
    create_test_file(&root.join("alice/a.dat"), 100).unwrap();
    create_test_file(&root.join("bob/b1.dat"), 200).unwrap();
    create_test_file(&root.join("bob/b2.dat"), 300).unwrap();
    create_test_file(&root.join("loose.dat"), 50).unwrap();
}

fn indexed() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let source = tmp.path().join("source");
    let index = tmp.path().join("index");
    source_tree(&source);
    build_index(&source, &index);
    (tmp, source, index)
}

#[test]
fn test_find_leaves_out_an_unreadable_partition_and_says_so() {
    if is_root() {
        return;
    }
    let (_tmp, _source, index) = indexed();
    let i = index.to_str().unwrap();

    let (_, err, ok) = run_find(&["-i", i, "--count"]);
    assert!(ok, "{err}");
    assert!(!err.contains(NOTE), "a readable index needs no note: {err}");
    assert_eq!(find_count(&index, &[]), 4);

    let _lock = Locked::new(index.join("bob"));
    let (out, err, ok) = run_find(&["-i", i, "--count"]);
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "2", "alice's file and the loose one");
    assert!(err.contains("1 directory of index"), "{err}");
    assert!(err.contains(NOTE), "{err}");

    let (out, err, ok) = run_find(&["-i", i, "-u", "alice", "--count"]);
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "1");
    assert!(
        !err.contains(NOTE),
        "nothing under alice was left out: {err}"
    );
}

#[test]
fn test_partition_flag_naming_an_unreadable_partition_fails_naming_it() {
    if is_root() {
        return;
    }
    let (_tmp, _source, index) = indexed();
    let _lock = Locked::new(index.join("bob"));
    let (out, err, ok) = run_find(&["-i", index.to_str().unwrap(), "-u", "bob", "--count"]);
    assert!(!ok, "printed {out}");
    assert!(
        err.contains("Partition 'bob' of index") && err.contains("is not readable by you"),
        "{err}"
    );
}

#[test]
fn test_du_rm_and_cp_note_what_they_left_out() {
    if is_root() {
        return;
    }
    let (tmp, source, index) = indexed();
    let i = index.to_str().unwrap();
    let _lock = Locked::new(index.join("bob"));

    let (out, err, ok) = run_with_stdin("xdu-du", &["-i", i, "-s"], None);
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "150\t.", "100 + 50 bytes");
    assert!(err.contains(NOTE), "{err}");

    let (out, err, ok) = run_with_stdin("xdu-rm", &["-i", i, "--dry-run"], None);
    assert!(ok, "{err}");
    assert!(out.contains("2 file(s) would be deleted"), "{out}");
    assert!(err.contains(NOTE), "{err}");
    assert!(source.join("bob/b1.dat").exists());

    let into = tmp.path().join("into");
    fs::create_dir(&into).unwrap();
    let (out, err, ok) = run_with_stdin(
        "xdu-cp",
        &["-i", i, "--into", into.to_str().unwrap(), "--dry-run"],
        None,
    );
    assert!(ok, "{out}{err}");
    assert!(err.contains(NOTE), "{err}");
    assert!(!out.contains("b1.dat"), "{out}");
}

#[test]
fn test_diff_hides_a_directory_readable_in_only_one_index() {
    if is_root() {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let source = tmp.path().join("source");
    let old = tmp.path().join("old");
    let new = tmp.path().join("new");
    source_tree(&source);
    build_index(&source, &old);
    build_index(&source, &new);
    create_test_file(&source.join("alice/later.dat"), 10).unwrap();
    fs::remove_dir_all(&new).unwrap();
    build_index(&source, &new);

    let _lock = Locked::new(old.join("bob"));
    let (out, err, _) = run_with_stdin(
        "xdu-diff",
        &["-f", old.to_str().unwrap(), new.to_str().unwrap()],
        None,
    );
    assert!(err.contains(NOTE), "{err}");
    assert!(out.contains("alice/later.dat"), "{out}");
    assert!(
        !out.contains("b1.dat") && !out.contains("b2.dat"),
        "bob is unreadable in the old index, so it is not compared: {out}"
    );
}

#[test]
fn test_a_nested_partition_below_a_readable_one_is_left_out() {
    if is_root() {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let source = tmp.path().join("source");
    let index = tmp.path().join("index");
    source_tree(&source);
    fs::create_dir_all(source.join("bob/deep")).unwrap();
    create_test_file(&source.join("bob/deep/d.dat"), 400).unwrap();
    let (_, err, ok) = run_xdu(&[
        "--apparent-size",
        "--split",
        "bob/deep",
        "-o",
        index.to_str().unwrap(),
        source.to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    assert_eq!(find_count(&index, &[]), 5);

    let _lock = Locked::new(index.join("bob/deep"));
    let (out, err, ok) = run_find(&["-i", index.to_str().unwrap(), "-u", "bob", "--count"]);
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "2", "bob's own two files, not the deep one");
    assert!(err.contains(NOTE), "{err}");
}
