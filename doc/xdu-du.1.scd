xdu-du(1)

# NAME

xdu-du - summarize disk usage from a file metadata index

# SYNOPSIS

*xdu-du* *-i* _DIR_ \[*-s*] \[*-h*] \[*-c*] \[*-u* _NAME_] \[_PATH_...]

# DESCRIPTION

*xdu-du* answers the question *du*(1) answers, from a Parquet index built by
*xdu*(1) instead of the filesystem. With no _PATH_ it prints one line per
top-level directory of the indexed tree, nested partitions included in their
top-level directory, plus *\_\_root\_\_* for the files lying directly in it.
With _PATH_ arguments it prints the total of the files at or below each one.

Sizes are those the index recorded: disk usage, or apparent sizes when the
index was built with *--apparent-size*.

# OPTIONS

*-i*, *--index* _DIR_
	Path to the Parquet index directory, or s3://_BUCKET_/_PREFIX_ for an index
	built into an S3 bucket, read as *xdu-find*(1) reads one. Required. See
	also *XDU_INDEX* in _ENVIRONMENT_.

*-s*, *--summarize*
	With no _PATH_, print one grand total instead of a line per top-level
	directory.

*-h*, *--human-readable*
	Print sizes with binary suffixes, such as 1.50 GiB.

*-c*, *--total*
	Print a grand total after the other lines.

*-u*, *--partition* _NAME_
	Restrict to one partition: a top-level subdirectory name, or the path of a
	nested partition such as projects/big. The partitions nested below it are
	included.

_PATH_
	An absolute path prefix as stored in the index, such as
	/data/scratch/alice.

*--help*
	Print help information. *-h* means *--human-readable*, as in *du*(1).

*-V*, *--version*
	Print version information.

# ENVIRONMENT

*XDU_INDEX*
	Default index if *-i* is not specified.

# EXAMPLES

Usage of every top-level directory, with a total:

	xdu-du -i /index/scratch -h -c

Usage of two directories:

	xdu-du -i /index/scratch -h /data/scratch/alice /data/scratch/bob

# SEE ALSO

*xdu*(1), *xdu-find*(1), *xdu-view*(1), *xdu-diff*(1)
