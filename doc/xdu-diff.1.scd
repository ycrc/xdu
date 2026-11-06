xdu-diff(1)

# NAME

xdu-diff - compare two file metadata indexes of the same tree

# SYNOPSIS

*xdu-diff* \[*-f*] \[*--status* _LIST_] \[*-u* _NAME_] \[*-p* _PATTERN_] \[*--regex*]
	\[*--min-delta* _SIZE_] \[*-s* _ORDER_] \[*-l* _N_] \[*-a*] \[*--absolute*] \[*-h*]
	\[*--csv*] \[*--old-root* _PATH_] \[*--new-root* _PATH_] _OLD_ _NEW_

# DESCRIPTION

*xdu-diff* compares two indexes built by *xdu*(1) from the same tree at
different times, such as indexes of two filesystem snapshots. Files are matched
by their path relative to each index's crawl root, so a file under
/fs/.snapshots/@GMT-2026.10.14/home and the same file under
/fs/.snapshots/@GMT-2026.10.16/home are one file.

Each file is classified as *added*, *removed*, *modified* (size or mtime
changed), *meta* (only ctime, uid, gid or mode changed), *accessed* (only
atime changed) or *unchanged*. By default *xdu-diff* prints one line per
partition with its old and new size and the count of each change; with
*--files* it lists the changed files.

Indexes built with the same split settings are compared partition by partition.
Otherwise a file can lie in different partitions on each side, and whole
top-level directories are compared instead. Both indexes must be local
directories.

# OPTIONS

_OLD_, _NEW_
	The earlier and the later index directory.

*-f*, *--files*
	List individual files instead of a per-partition summary. Each line shows
	a marker (+ added, - removed, ~ modified, m meta, . accessed), the size
	change, the current size (the old one for a removed file) and the path.

*--status* _LIST_
	Statuses to list with *--files*, comma-separated, or *all*. Default:
	added,removed,modified,meta.

*-u*, *--partition* _NAME_
	Restrict to one partition or subdirectory, such as alice or projects/big.

*-p*, *--pattern* _PATTERN_
	Glob pattern matched against paths relative to the crawl root. \* crosses
	directories.

*--regex*
	Interpret *-p* as a regular expression instead of a glob.

*--min-delta* _SIZE_
	With *--files*, list only files whose size changed by at least _SIZE_.

*-s*, *--sort* _ORDER_
	*name* (default), *delta* (largest growth first), *shrink* (largest shrink
	first) or *abs* (largest change either way first).

*-l*, *--limit* _N_
	Print at most _N_ rows.

*-a*, *--all*
	In the summary, include partitions with no changes.

*--absolute*
	With *--files*, print absolute paths: under the new root, or the old root
	for a removed file.

*-h*, *--human-readable*
	Print sizes with binary suffixes.

*--csv*
	Print CSV with a header row and raw values.

*--old-root* _PATH_, *--new-root* _PATH_
	Override the crawl root of either index. The root is read from the
	index's \_xdu.json manifest, or recovered from its paths for an index
	without one.

*--help*
	Print help information. *-h* means *--human-readable*.

*-V*, *--version*
	Print version information.

# EXIT STATUS

As for *diff*(1): *0* when nothing changed (atime-only changes do not count),
*1* when something did, and *2* on error.

# EXAMPLES

Per-partition growth between two snapshots:

	xdu-diff -h /index/snap-mon /index/snap-wed

The 20 files that grew most:

	xdu-diff -h --files --sort delta -l 20 /index/snap-mon /index/snap-wed

New files over 1 GiB in one partition, as absolute paths:

	xdu-diff --files --status added --min-delta 1G -u alice --absolute OLD NEW

# SEE ALSO

*xdu*(1), *xdu-view*(1), *xdu-du*(1)
