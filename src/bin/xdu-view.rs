#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::io::{stdout, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use duckdb::Connection;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};

use xdu::{
    diff_as_index_sql, discover_index_root, format_bytes, format_bytes_signed, format_count, list_partitions,
    parse_size, sql_quote, DiffSide, QueryFilters, SortMode,
};

/// Detect file type from magic bytes, shebangs, text content, and extension.
///
/// Returns `(description, is_text)` where `description` is a human-readable
/// string like "ELF 64-bit LSB executable, x86-64" or "Python script, UTF-8 text"
/// and `is_text` indicates whether the file should be treated as scrollable text.
fn detect_file_type(sniff_buf: &[u8], file_path: &str) -> (String, bool) {
    // --- Layer 1: infer magic bytes (with enrichment) ---
    if let Some(kind) = infer::get(sniff_buf) {
        let mime = kind.mime_type();
        // ELF enrichment
        if mime == "application/x-executable"
            || mime == "application/x-sharedlib"
            || (sniff_buf.len() >= 4 && &sniff_buf[..4] == b"\x7FELF")
        {
            if let Some(desc) = describe_elf(sniff_buf) {
                return (desc, false);
            }
        }
        // For text/* MIME types (e.g. text/x-shellscript), fall through to
        // our shebang and text sub-type layers for richer descriptions and
        // correct is_text=true handling.
        if !mime.starts_with("text/") {
            return (format!("{} ({})", mime, kind.extension()), false);
        }
    }

    // ELF that infer missed (it should catch it, but just in case)
    if sniff_buf.len() >= 4 && &sniff_buf[..4] == b"\x7FELF" {
        if let Some(desc) = describe_elf(sniff_buf) {
            return (desc, false);
        }
        return ("ELF binary".to_string(), false);
    }

    // Mach-O enrichment (infer may not detect all variants)
    if sniff_buf.len() >= 8 {
        let magic = &sniff_buf[..4];
        if magic == b"\xCF\xFA\xED\xFE" || magic == b"\xFE\xED\xFA\xCF"
            || magic == b"\xCE\xFA\xED\xFE" || magic == b"\xFE\xED\xFA\xCE"
        {
            if let Some(desc) = describe_macho(sniff_buf) {
                return (desc, false);
            }
            return ("Mach-O binary".to_string(), false);
        }
        // Universal (fat) binary
        if magic == b"\xCA\xFE\xBA\xBE" || magic == b"\xBE\xBA\xFE\xCA" {
            return ("Mach-O universal binary".to_string(), false);
        }
    }

    // --- Layer 2: Shebang detection ---
    if sniff_buf.len() >= 2 && &sniff_buf[..2] == b"#!" {
        if let Some(desc) = describe_shebang(sniff_buf) {
            return (desc, true);
        }
    }

    // --- Layer 3: Text sub-type sniffing ---
    if let Ok(text) = std::str::from_utf8(sniff_buf) {
        // Content-based detection
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return ("JSON text, UTF-8".to_string(), true);
        }
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<!DOCTYPE") {
            return ("XML text, UTF-8".to_string(), true);
        }

        // Extension-based fallback for text files
        if let Some(desc) = describe_text_by_extension(file_path) {
            return (format!("{}, UTF-8", desc), true);
        }

        // --- Layer 4a: Generic UTF-8 text ---
        return ("text/plain; UTF-8".to_string(), true);
    }

    // --- Layer 4b: Binary fallback ---
    ("application/octet-stream (binary data)".to_string(), false)
}

/// Parse ELF header fields from the sniff buffer.
fn describe_elf(buf: &[u8]) -> Option<String> {
    if buf.len() < 20 {
        return None;
    }
    let class = match buf[4] {
        1 => "32-bit",
        2 => "64-bit",
        _ => "unknown-class",
    };
    let endian = match buf[5] {
        1 => "LSB",
        2 => "MSB",
        _ => "unknown-endian",
    };
    let e_type_val = if buf[5] == 1 {
        u16::from_le_bytes([buf[16], buf[17]])
    } else {
        u16::from_be_bytes([buf[16], buf[17]])
    };
    let etype = match e_type_val {
        1 => "relocatable",
        2 => "executable",
        3 => "shared object",
        4 => "core dump",
        _ => "object",
    };
    let e_machine_val = if buf[5] == 1 {
        u16::from_le_bytes([buf[18], buf[19]])
    } else {
        u16::from_be_bytes([buf[18], buf[19]])
    };
    let arch = match e_machine_val {
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC64",
        0x28 => "ARM",
        0x2A => "SuperH",
        0x32 => "IA-64",
        0x3E => "x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0xF7 => "BPF",
        _ => "unknown-arch",
    };
    Some(format!("ELF {} {} {}, {}", class, endian, etype, arch))
}

/// Parse Mach-O header fields from the sniff buffer.
fn describe_macho(buf: &[u8]) -> Option<String> {
    if buf.len() < 8 {
        return None;
    }
    let magic = &buf[..4];
    let (class, le) = match magic {
        b"\xCF\xFA\xED\xFE" => ("64-bit", true),   // MH_MAGIC_64 (LE)
        b"\xFE\xED\xFA\xCF" => ("64-bit", false),  // MH_MAGIC_64 (BE)
        b"\xCE\xFA\xED\xFE" => ("32-bit", true),   // MH_MAGIC (LE)
        b"\xFE\xED\xFA\xCE" => ("32-bit", false),  // MH_MAGIC (BE)
        _ => return None,
    };
    let cpu_type = if le {
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]])
    } else {
        u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])
    };
    let arch = match cpu_type {
        7 => "x86",                     // CPU_TYPE_X86
        0x0100_0007 => "x86-64",        // CPU_TYPE_X86_64
        12 => "ARM",                    // CPU_TYPE_ARM
        0x0100_000C => "ARM64",         // CPU_TYPE_ARM64
        18 => "PowerPC",                // CPU_TYPE_POWERPC
        0x0100_0012 => "PowerPC64",     // CPU_TYPE_POWERPC64
        _ => "unknown-arch",
    };
    // file_type at offset 12 (4 bytes)
    let ftype = if buf.len() >= 16 {
        let ft = if le {
            u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]])
        } else {
            u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]])
        };
        match ft {
            1 => "object",
            2 => "executable",
            3 => "fixed VM shared library",
            4 => "core dump",
            5 => "preloaded executable",
            6 => "dylib",
            7 => "dynamic linker",
            8 => "bundle",
            _ => "binary",
        }
    } else {
        "binary"
    };
    Some(format!("Mach-O {} {}, {}", class, ftype, arch))
}

/// Parse a shebang line to identify the script type.
fn describe_shebang(buf: &[u8]) -> Option<String> {
    // Find the end of the first line
    let end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len().min(256));
    let line = std::str::from_utf8(&buf[2..end]).ok()?.trim();
    if line.is_empty() {
        return None;
    }

    // Handle "env" indirection: "#!/usr/bin/env python3" -> "python3"
    let interpreter = if line.contains("env ") || line.contains("env\t") {
        line.split_whitespace().last()?
    } else {
        // "/usr/bin/perl" -> "perl", "/bin/bash" -> "bash"
        line.split_whitespace()
            .next()?
            .rsplit('/')
            .next()?
    };

    let desc = match interpreter {
        "bash" => "Bash script",
        "sh" => "POSIX shell script",
        "zsh" => "Zsh script",
        "fish" => "Fish script",
        "dash" => "Dash script",
        i if i.starts_with("python") => "Python script",
        "perl" => "Perl script",
        "ruby" => "Ruby script",
        "node" | "nodejs" => "Node.js script",
        "Rscript" => "R script",
        "lua" => "Lua script",
        "php" => "PHP script",
        "awk" | "gawk" | "mawk" => "AWK script",
        "sed" => "Sed script",
        "tclsh" | "wish" => "Tcl script",
        _ => return Some(format!("Script (#!{}), UTF-8 text", interpreter)),
    };
    Some(format!("{}, UTF-8 text", desc))
}

/// Map file extension to a human-readable text type description.
fn describe_text_by_extension(path: &str) -> Option<&'static str> {
    let ext = path.rsplit('.').next()?.to_ascii_lowercase();
    let desc = match ext.as_str() {
        "csv" => "CSV text",
        "tsv" => "TSV text",
        "json" => "JSON text",
        "jsonl" | "ndjson" => "JSON Lines text",
        "yaml" | "yml" => "YAML text",
        "toml" => "TOML text",
        "xml" => "XML text",
        "html" | "htm" => "HTML text",
        "css" => "CSS text",
        "md" | "markdown" => "Markdown text",
        "rst" => "reStructuredText",
        "tex" | "latex" => "LaTeX text",
        "py" => "Python source",
        "rs" => "Rust source",
        "c" => "C source",
        "h" => "C header",
        "cpp" | "cc" | "cxx" => "C++ source",
        "hpp" | "hh" | "hxx" => "C++ header",
        "java" => "Java source",
        "go" => "Go source",
        "js" | "mjs" | "cjs" => "JavaScript source",
        "ts" | "mts" | "cts" => "TypeScript source",
        "rb" => "Ruby source",
        "pl" | "pm" => "Perl source",
        "php" => "PHP source",
        "r" => "R source",
        "jl" => "Julia source",
        "lua" => "Lua source",
        "swift" => "Swift source",
        "kt" | "kts" => "Kotlin source",
        "scala" => "Scala source",
        "hs" => "Haskell source",
        "ml" | "mli" => "OCaml source",
        "ex" | "exs" => "Elixir source",
        "erl" | "hrl" => "Erlang source",
        "f" | "f90" | "f95" | "f03" | "f08" | "for" => "Fortran source",
        "sh" | "bash" => "Shell script",
        "zsh" => "Zsh script",
        "fish" => "Fish script",
        "ps1" => "PowerShell script",
        "sql" => "SQL text",
        "graphql" | "gql" => "GraphQL text",
        "proto" => "Protocol Buffers text",
        "ini" | "cfg" | "conf" => "Configuration text",
        "env" => "Environment file",
        "txt" | "text" | "log" => "Plain text",
        "makefile" => "Makefile",
        _ => return None,
    };
    Some(desc)
}

/// Resolve a uid to a username using getpwuid_r, with a process-lifetime cache.
fn resolve_username(uid: i32) -> String {
    static CACHE: OnceLock<Mutex<HashMap<i32, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(name) = map.get(&uid) {
        return name.clone();
    }
    let name = unsafe {
        let mut buf = vec![0i8; 4096];
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if !result.is_null() {
            std::ffi::CStr::from_ptr((*result).pw_name)
                .to_string_lossy()
                .into_owned()
        } else {
            uid.to_string()
        }
    };
    map.insert(uid, name.clone());
    name
}

/// Resolve a gid to a group name using getgrgid_r, with a process-lifetime cache.
fn resolve_groupname(gid: i32) -> String {
    static CACHE: OnceLock<Mutex<HashMap<i32, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(name) = map.get(&gid) {
        return name.clone();
    }
    let name = unsafe {
        let mut buf = vec![0i8; 4096];
        let mut grp: libc::group = std::mem::zeroed();
        let mut result: *mut libc::group = std::ptr::null_mut();
        libc::getgrgid_r(
            gid as libc::gid_t,
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if !result.is_null() {
            std::ffi::CStr::from_ptr((*result).gr_name)
                .to_string_lossy()
                .into_owned()
        } else {
            gid.to_string()
        }
    };
    map.insert(gid, name.clone());
    name
}

/// Format a uid as username ("-" for the parent entry sentinel).
fn format_uid(uid: i32, _is_dir: bool) -> String {
    if uid < 0 { "-".to_string() } else { resolve_username(uid) }
}

/// Format a gid as group name ("-" for the parent entry sentinel).
fn format_gid(gid: i32, _is_dir: bool) -> String {
    if gid < 0 { "-".to_string() } else { resolve_groupname(gid) }
}

/// Format a mode value in octal ("-" for directories/parent entry).
fn format_mode(mode: i32, is_dir: bool) -> String {
    if is_dir || mode < 0 { "-".to_string() } else { format!("{:o}", mode & 0o7777) }
}

/// Format file count with K/M/B suffixes
fn format_file_count(count: i64) -> String {
    if count >= 1_000_000_000 {
        format!("{:.1}B files", count as f64 / 1_000_000_000.0)
    } else if count >= 1_000_000 {
        format!("{:.1}M files", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K files", count as f64 / 1_000.0)
    } else if count == 1 {
        "1 file".to_string()
    } else {
        format!("{} files", count)
    }
}

/// Signed size change for display; blank for unchanged entries.
fn format_size_delta(entry: &DirEntry) -> String {
    if entry.changed == 0 && entry.size_delta() == 0 {
        String::new()
    } else {
        format_bytes_signed(entry.size_delta())
    }
}

/// Signed compact file-count change (e.g. "+6.5K", "-3"); blank when zero.
fn format_count_delta(delta: i64) -> String {
    match delta.signum() {
        1 => format!("+{}", format_count(delta as u64)),
        -1 => format!("-{}", format_count(delta.unsigned_abs())),
        _ => String::new(),
    }
}

/// Green for growth, red for shrinkage.
fn delta_style(delta: i64) -> Style {
    match delta.signum() {
        1 => Style::default().fg(Color::Green),
        -1 => Style::default().fg(Color::Red),
        _ => Style::default(),
    }
}

/// Name style in compare mode, by change marker.
fn marker_style(marker: char) -> Style {
    match marker {
        '+' => Style::default().fg(Color::Green),
        '-' => Style::default().fg(Color::Red),
        '~' => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "xdu-view",
    about = "Interactive TUI for exploring a file metadata index",
    after_help = "\
Examples:
  xdu-view -i /index/scratch
  xdu-view -i /index/scratch -u alice
  xdu-view -i /index/scratch --older-than 90 --sort size
  xdu-view -i /index/snap-wed --compare /index/snap-mon --sort delta"
)]
struct Args {
    /// Path to the Parquet index directory
    #[arg(short, long, value_name = "DIR", env = "XDU_INDEX")]
    index: PathBuf,

    /// Initial partition to view (optional, shows partition list if omitted)
    #[arg(short = 'u', long, value_name = "NAME")]
    partition: Option<String>,

    /// Regular expression pattern to match paths
    #[arg(short, long, value_name = "REGEX")]
    pattern: Option<String>,

    /// Minimum file size (e.g., 1K, 10M, 1G)
    #[arg(long, value_name = "SIZE")]
    min_size: Option<String>,

    /// Maximum file size (e.g., 1K, 10M, 1G)
    #[arg(long, value_name = "SIZE")]
    max_size: Option<String>,

    /// Files not accessed in N days
    #[arg(long, value_name = "DAYS")]
    older_than: Option<u64>,

    /// Files accessed within N days
    #[arg(long, value_name = "DAYS")]
    newer_than: Option<u64>,

    /// Sort order: name, size-asc, size-desc, count-asc, count-desc, age-asc, age-desc,
    /// delta-desc, delta-asc (delta sorts require --compare)
    #[arg(short, long, default_value = "name")]
    sort: String,

    /// Compare against an earlier index of the same tree (e.g. an older snapshot) and
    /// show size changes and added/removed files
    #[arg(long, value_name = "DIR")]
    compare: Option<PathBuf>,
}

/// Represents a directory entry in the view
#[derive(Clone, Debug)]
struct DirEntry {
    name: String,
    path: String,
    is_dir: bool,
    total_size: i64,
    file_count: i64,
    latest_atime: i64,
    latest_mtime: i64,
    latest_ctime: i64,
    uid: i32,
    gid: i32,
    mode: i32,
    /// Size in the comparison (old) index; equals `total_size` when not comparing
    size_old: i64,
    /// File count in the comparison (old) index; equals `file_count` when not comparing
    files_old: i64,
    /// Number of files added, removed, or modified relative to the old index
    changed: i64,
}

impl DirEntry {
    fn size_delta(&self) -> i64 { self.total_size - self.size_old }
    fn files_delta(&self) -> i64 { self.file_count - self.files_old }

    /// Change marker for compare mode: `+` new, `-` gone, `~` changed, blank if unchanged.
    fn change_marker(&self) -> char {
        if self.changed == 0 {
            ' '
        } else if self.files_old == 0 {
            '+'
        } else if self.file_count == 0 {
            '-'
        } else {
            '~'
        }
    }

    /// Entry for "..", which has no stats.
    fn parent() -> Self {
        DirEntry {
            name: "..".to_string(),
            path: "..".to_string(),
            is_dir: true,
            total_size: 0,
            file_count: 0,
            latest_atime: 0,
            latest_mtime: 0,
            latest_ctime: 0,
            uid: -1,
            gid: -1,
            mode: -1,
            size_old: 0,
            files_old: 0,
            changed: 0,
        }
    }
}

/// Which files to include when comparing two indices.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum StatusFilter {
    #[default]
    All,
    Changed,
    Added,
    Removed,
    Modified,
}

impl StatusFilter {
    fn next(self) -> Self {
        match self {
            StatusFilter::All => StatusFilter::Changed,
            StatusFilter::Changed => StatusFilter::Added,
            StatusFilter::Added => StatusFilter::Removed,
            StatusFilter::Removed => StatusFilter::Modified,
            StatusFilter::Modified => StatusFilter::All,
        }
    }
    fn label(self) -> &'static str {
        match self {
            StatusFilter::All => "all",
            StatusFilter::Changed => "changed",
            StatusFilter::Added => "added",
            StatusFilter::Removed => "removed",
            StatusFilter::Modified => "modified",
        }
    }
    /// SQL condition on the diff `status` column, if any.
    fn condition(self) -> Option<&'static str> {
        match self {
            StatusFilter::All => None,
            StatusFilter::Changed => Some("status IN ('added', 'removed', 'modified', 'meta')"),
            StatusFilter::Added => Some("status = 'added'"),
            StatusFilter::Removed => Some("status = 'removed'"),
            StatusFilter::Modified => Some("status IN ('modified', 'meta')"),
        }
    }
}

/// State for comparing the viewed index against an earlier one.
struct Compare {
    old: DiffSide,
    new: DiffSide,
    old_partitions: BTreeSet<String>,
    new_partitions: BTreeSet<String>,
    /// Partition name -> temp table holding its materialized diff
    tables: RefCell<HashMap<String, String>>,
}

impl Compare {
    fn partitions(&self) -> impl Iterator<Item = &String> {
        self.old_partitions.union(&self.new_partitions)
    }

    fn has_partition(&self, partition: &str) -> bool {
        self.old_partitions.contains(partition) || self.new_partitions.contains(partition)
    }

    /// Unmaterialized diff of one partition, shaped like an index.
    fn diff_sql(&self, partition: &str) -> String {
        diff_as_index_sql(
            &self.old,
            &self.new,
            partition,
            self.old_partitions.contains(partition),
            self.new_partitions.contains(partition),
        )
    }

    /// Name of a temp table holding the diff of `partition`, creating it on first use so
    /// navigating within a partition doesn't redo the join.
    fn table(&self, conn: &Connection, partition: &str) -> Result<String> {
        if let Some(name) = self.tables.borrow().get(partition) {
            return Ok(name.clone());
        }
        let name = format!("xdu_diff_{}", self.tables.borrow().len());
        conn.execute_batch(&format!(
            "CREATE TEMP TABLE {} AS {}",
            name,
            self.diff_sql(partition)
        ))
        .with_context(|| format!("Comparing partition '{}'", partition))?;
        self.tables.borrow_mut().insert(partition.to_string(), name.clone());
        Ok(name)
    }
}

/// Which timestamp column is currently displayed.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum TimestampCol {
    #[default]
    Atime,
    Mtime,
    Ctime,
}

impl TimestampCol {
    fn next(self) -> Self {
        match self {
            TimestampCol::Atime => TimestampCol::Mtime,
            TimestampCol::Mtime => TimestampCol::Ctime,
            TimestampCol::Ctime => TimestampCol::Atime,
        }
    }
    fn label(self) -> &'static str {
        match self {
            TimestampCol::Atime => "accessed",
            TimestampCol::Mtime => "modified",
            TimestampCol::Ctime => "changed",
        }
    }
}

/// Which extra metadata columns are currently visible.
#[derive(Clone, Debug, Default)]
struct VisibleExtras {
    uid: bool,
    gid: bool,
    mode: bool,
}

/// Input mode for interactive filter entry
#[derive(Clone, Debug, PartialEq)]
enum InputMode {
    /// Normal navigation mode
    Normal,
    /// Entering a pattern filter
    Pattern,
    /// Entering older-than days (with active timestamp field)
    OlderThan(TimestampCol),
    /// Entering newer-than days (with active timestamp field)
    NewerThan(TimestampCol),
    /// Entering min-size
    MinSize,
    /// Entering max-size
    MaxSize,
    /// Selecting sort mode
    SortSelect,
}

impl InputMode {
    fn prompt(&self) -> String {
        match self {
            InputMode::Normal => String::new(),
            InputMode::Pattern => "Pattern (regex): ".to_string(),
            InputMode::OlderThan(ts) => format!("Older than (days, {}): ", ts.label()),
            InputMode::NewerThan(ts) => format!("Newer than (days, {}): ", ts.label()),
            InputMode::MinSize => "Min size (e.g., 1M): ".to_string(),
            InputMode::MaxSize => "Max size (e.g., 1G): ".to_string(),
            InputMode::SortSelect => String::new(),
        }
    }
}

/// View mode for the TUI
#[derive(Clone, Copy, Debug, PartialEq)]
enum ViewMode {
    /// Traditional single-list view (default)
    List,
    /// Miller columns (tree) view — horizontal cascade of directory hierarchy
    Tree,
}

/// Strip ANSI escape sequences (CSI, OSC, and single-byte ESC sequences) from a string.
/// Raw escapes corrupt ratatui's cell-width accounting and can bleed into other panes.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1B' {
            match chars.peek() {
                // CSI sequence: ESC [ ... final_byte
                Some('[') => {
                    chars.next();
                    // Consume parameter bytes (0x30-0x3F), intermediate bytes (0x20-0x2F),
                    // then the final byte (0x40-0x7E)
                    while let Some(&ch) = chars.peek() {
                        if ('\x40'..='\x7E').contains(&ch) {
                            chars.next(); // consume final byte
                            break;
                        }
                        chars.next();
                    }
                }
                // OSC sequence: ESC ] ... ST (ST = ESC \ or BEL)
                Some(']') => {
                    chars.next();
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' { break; } // BEL terminator
                        if ch == '\x1B' {
                            if chars.peek() == Some(&'\\') {
                                chars.next(); // consume \
                            }
                            break;
                        }
                    }
                }
                // Two-byte ESC sequence: ESC + one character
                Some(_) => { chars.next(); }
                // Bare ESC at end of string
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Special partition name for files directly in the top-level directory.
const ROOT_PARTITION: &str = "__root__";

/// Maximum lines to keep in the sliding window buffer.
const MAX_BUFFER_LINES: usize = 100_000;
/// Chunk size for streaming reads (64KB).
const CHUNK_BYTES: usize = 65_536;

/// Cached file preview for the rightmost pane in tree view.
struct FilePreview {
    /// Full file path on disk
    path: String,
    /// File size from the index
    size: i64,
    /// Access time from the index
    atime: i64,
    /// Size in the comparison index, when comparing (None if the file is new)
    size_old: Option<i64>,
    /// Human-readable type description (e.g. "PNG image", "text/plain; UTF-8")
    type_description: String,
    /// Whether the file is detected as plain text
    is_text: bool,
    /// Content lines (sliding window for text files, empty for binary)
    lines: VecDeque<String>,
    /// Global line number of `lines[0]`
    first_line_number: usize,
    /// Total lines read from the file so far
    total_lines_loaded: usize,
    /// Byte position where the last read stopped
    file_offset: u64,
    /// Whether we've hit EOF
    eof_reached: bool,
    /// Current scroll offset — a global line number
    scroll_offset: usize,
}

/// A single column in the Miller columns (tree) view.
struct Column {
    /// Display title for the column header
    title: String,
    /// Partition name (None = partition list column)
    partition: Option<String>,
    /// Root path for the partition (empty for partition list)
    partition_root: String,
    /// Directory path this column represents
    path: String,
    /// Entries in this column
    entries: Vec<DirEntry>,
    /// Selection state
    list_state: ListState,
}

/// Application state
struct App {
    conn: Connection,
    index_path: PathBuf,

    /// Crawl root of the index (partition `p` lives at `<index_root>/p`)
    index_root: String,

    /// Comparison against an earlier index, if `--compare` was given
    compare: Option<Compare>,

    /// Which files to show when comparing
    status_filter: StatusFilter,
    
    /// Current absolute path prefix (the root path for the current partition)
    partition_root: String,
    
    /// Current directory path (absolute, empty = partition list)
    current_path: String,
    
    /// Current partition being viewed (None = viewing partition list)
    current_partition: Option<String>,
    
    /// Entries in the current view
    entries: Vec<DirEntry>,
    
    /// List selection state
    list_state: ListState,
    
    /// Whether we're currently loading
    loading: bool,
    
    /// Status message
    status: String,

    /// Query filters
    filters: QueryFilters,

    /// Sort mode
    sort_mode: SortMode,

    /// Current input mode
    input_mode: InputMode,

    /// Current input buffer
    input_buffer: String,

    /// Pending sort mode (for sort selection)
    pending_sort: SortMode,

    /// Current view mode (list or tree)
    view_mode: ViewMode,

    /// Columns for Miller columns (tree) view
    columns: Vec<Column>,

    /// Active column index in tree view
    active_column: usize,

    /// File preview for the rightmost pane in tree view
    file_preview: Option<FilePreview>,

    /// Whether the preview pane pager is focused (less-like scroll mode)
    preview_focused: bool,

    /// Which timestamp column is currently displayed
    timestamp_col: TimestampCol,

    /// Which extra metadata columns are visible
    visible_extras: VisibleExtras,

    /// Whether the help overlay is shown
    show_help: bool,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: Connection,
        index_path: PathBuf,
        index_root: String,
        compare: Option<Compare>,
        initial_partition: Option<String>,
        filters: QueryFilters,
        sort_mode: SortMode,
    ) -> Result<Self> {
        let mut app = App {
            conn,
            index_path,
            index_root,
            compare,
            status_filter: StatusFilter::default(),
            partition_root: String::new(),
            current_path: String::new(),
            current_partition: None,
            entries: Vec::new(),
            list_state: ListState::default(),
            loading: false,
            status: String::new(),
            filters,
            sort_mode,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            pending_sort: sort_mode,
            view_mode: ViewMode::List,
            columns: Vec::new(),
            active_column: 0,
            file_preview: None,
            preview_focused: false,
            timestamp_col: TimestampCol::Atime,
            visible_extras: VisibleExtras::default(),
            show_help: false,
        };
        
        if let Some(partition) = initial_partition {
            app.current_partition = Some(partition);
            app.load_directory()?;
        } else {
            app.load_partitions()?;
        }
        
        if !app.entries.is_empty() {
            app.list_state.select(Some(0));
        }
        
        Ok(app)
    }
    
    /// SQL relation with the files of one partition, or None if the partition doesn't exist.
    /// When comparing, this is the partition's diff (with `size_old` and `status` columns).
    fn partition_source(&self, partition: &str) -> Result<Option<String>> {
        match self.compare {
            Some(ref cmp) => {
                if !cmp.has_partition(partition) {
                    return Ok(None);
                }
                Ok(Some(cmp.table(&self.conn, partition)?))
            }
            None => {
                let dir = self.index_path.join(partition);
                if !dir.is_dir() {
                    return Ok(None);
                }
                let glob = format!("{}/*.parquet", dir.display());
                Ok(Some(format!("read_parquet({})", sql_quote(&glob))))
            }
        }
    }

    /// SQL relation with the files of all partitions plus a `partition` column.
    fn all_partitions_source(&self) -> String {
        match self.compare {
            Some(ref cmp) => {
                // Reuse partitions already materialized; join the rest on the fly.
                let tables = cmp.tables.borrow();
                let parts: Vec<String> = cmp.partitions()
                    .filter(|p| p.as_str() != ROOT_PARTITION)
                    .map(|p| {
                        let source = match tables.get(p) {
                            Some(table) => table.clone(),
                            None => format!("({})", cmp.diff_sql(p)),
                        };
                        format!("SELECT {} AS partition, * FROM {}", sql_quote(p), source)
                    })
                    .collect();
                if parts.is_empty() {
                    "(SELECT NULL::VARCHAR AS partition, NULL::BIGINT AS size WHERE false)".to_string()
                } else {
                    format!("({})", parts.join(" UNION ALL "))
                }
            }
            None => {
                let glob = format!("{}/*/*.parquet", self.index_path.display());
                format!(
                    "(SELECT *, regexp_extract(filename, '.*/([^/]+)/[^/]+\\.parquet$', 1) AS partition \
                     FROM read_parquet({}, filename=true))",
                    sql_quote(&glob)
                )
            }
        }
    }

    /// Active filter conditions, including the compare-mode status filter.
    fn conditions(&self) -> Vec<String> {
        let mut conditions = self.filters.to_conditions();
        if self.compare.is_some() {
            if let Some(cond) = self.status_filter.condition() {
                conditions.push(cond.to_string());
            }
        }
        conditions
    }

    /// Whether any filter (including the status filter) is narrowing the view.
    fn is_filtered(&self) -> bool {
        self.filters.is_active() || (self.compare.is_some() && self.status_filter != StatusFilter::All)
    }

    /// Aggregate columns shared by the partition and directory queries, read back by
    /// [`App::read_stats`]. Removed files (compare mode) count toward the old index only.
    fn aggregate_columns(&self) -> &'static str {
        if self.compare.is_some() {
            r#"
                SUM(size) as total_size,
                COUNT(*) FILTER (WHERE status <> 'removed') as file_count,
                MAX(atime) as latest_atime,
                MAX(mtime) as latest_mtime,
                MAX(ctime) as latest_ctime,
                CASE WHEN MIN(uid) = MAX(uid) THEN MIN(uid) ELSE -1 END as min_uid,
                CASE WHEN MIN(gid) = MAX(gid) THEN MIN(gid) ELSE -1 END as min_gid,
                MIN(mode) as min_mode,
                SUM(size_old) as total_size_old,
                COUNT(*) FILTER (WHERE status <> 'added') as files_old,
                COUNT(*) FILTER (WHERE status IN ('added', 'removed', 'modified', 'meta')) as changed,
                SUM(size) - SUM(size_old) as size_delta"#
        } else {
            r#"
                SUM(size) as total_size,
                COUNT(*) as file_count,
                MAX(atime) as latest_atime,
                MAX(mtime) as latest_mtime,
                MAX(ctime) as latest_ctime,
                CASE WHEN MIN(uid) = MAX(uid) THEN MIN(uid) ELSE -1 END as min_uid,
                CASE WHEN MIN(gid) = MAX(gid) THEN MIN(gid) ELSE -1 END as min_gid,
                MIN(mode) as min_mode,
                SUM(size) as total_size_old,
                COUNT(*) as files_old,
                0 as changed,
                0 as size_delta"#
        }
    }

    /// Build a DirEntry from the columns of [`App::aggregate_columns`], starting at `col`.
    fn read_stats(row: &duckdb::Row, col: usize, name: String, path: String, is_dir: bool) -> duckdb::Result<DirEntry> {
        Ok(DirEntry {
            name,
            path,
            is_dir,
            total_size: row.get(col)?,
            file_count: row.get(col + 1)?,
            latest_atime: row.get(col + 2)?,
            latest_mtime: row.get(col + 3)?,
            latest_ctime: row.get(col + 4)?,
            uid: row.get(col + 5)?,
            gid: row.get(col + 6)?,
            mode: row.get(col + 7)?,
            size_old: row.get(col + 8)?,
            files_old: row.get(col + 9)?,
            changed: row.get(col + 10)?,
        })
    }

    /// Query individual files from the __root__ partition.
    /// Returns DirEntry items with is_dir=false and file_count=1.
    fn query_root_files(&self) -> Result<Vec<DirEntry>> {
        let Some(source) = self.partition_source(ROOT_PARTITION)? else {
            return Ok(Vec::new());
        };
        let conditions = self.conditions();
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        // Per-file equivalents of the aggregate columns
        let stats = if self.compare.is_some() {
            "size, CASE WHEN status = 'removed' THEN 0 ELSE 1 END, atime, mtime, ctime, uid, gid, mode, \
             size_old, CASE WHEN status = 'added' THEN 0 ELSE 1 END, \
             CASE WHEN status IN ('added', 'removed', 'modified', 'meta') THEN 1 ELSE 0 END"
        } else {
            "size, 1, atime, mtime, ctime, uid, gid, mode, size, 1, 0"
        };

        let sql = format!("SELECT path, {stats} FROM {source} {where_clause}");

        let mut entries = Vec::new();
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            entries.push(Self::read_stats(row, 1, name, path, false)?);
        }

        Ok(entries)
    }

    /// Sort entries in-place according to the current SortMode.
    fn sort_entries(entries: &mut [DirEntry], sort_mode: SortMode) {
        match sort_mode {
            SortMode::Name => {
                // Directories first, then alphabetical by name
                entries.sort_by(|a, b| {
                    b.is_dir.cmp(&a.is_dir)
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
            SortMode::SizeDesc => entries.sort_by(|a, b| b.total_size.cmp(&a.total_size)),
            SortMode::SizeAsc => entries.sort_by(|a, b| a.total_size.cmp(&b.total_size)),
            SortMode::CountDesc => entries.sort_by(|a, b| b.file_count.cmp(&a.file_count)),
            SortMode::CountAsc => entries.sort_by(|a, b| a.file_count.cmp(&b.file_count)),
            SortMode::AgeDesc => entries.sort_by(|a, b| a.latest_atime.cmp(&b.latest_atime)), // oldest first
            SortMode::AgeAsc => entries.sort_by(|a, b| b.latest_atime.cmp(&a.latest_atime)),  // newest first
            SortMode::MtimeDesc => entries.sort_by(|a, b| a.latest_mtime.cmp(&b.latest_mtime)),
            SortMode::MtimeAsc  => entries.sort_by(|a, b| b.latest_mtime.cmp(&a.latest_mtime)),
            SortMode::CtimeDesc => entries.sort_by(|a, b| a.latest_ctime.cmp(&b.latest_ctime)),
            SortMode::CtimeAsc  => entries.sort_by(|a, b| b.latest_ctime.cmp(&a.latest_ctime)),
            SortMode::UidAsc    => entries.sort_by(|a, b| a.uid.cmp(&b.uid)),
            SortMode::GidAsc    => entries.sort_by(|a, b| a.gid.cmp(&b.gid)),
            SortMode::ModeAsc   => entries.sort_by(|a, b| a.mode.cmp(&b.mode)),
            SortMode::DeltaDesc => entries.sort_by(|a, b| b.size_delta().cmp(&a.size_delta())),
            SortMode::DeltaAsc  => entries.sort_by(|a, b| a.size_delta().cmp(&b.size_delta())),
        }
    }

    /// Query the partition list (with __root__ files merged in as individual entries).
    fn query_partition_entries(&self) -> Result<Vec<DirEntry>> {
        let mut conditions = self.conditions();
        // Exclude __root__ — its files are merged as individual entries
        conditions.push(format!("partition IS NOT NULL AND partition != '' AND partition != '{}'", ROOT_PARTITION));

        let sql = format!(
            r#"
            SELECT partition, {aggregates}
            FROM {source}
            WHERE {conditions}
            GROUP BY partition
            ORDER BY {order}
            "#,
            aggregates = self.aggregate_columns(),
            source = self.all_partitions_source(),
            conditions = conditions.join(" AND "),
            order = self.sort_mode.to_partition_order_by()
        );

        let mut entries = Vec::new();
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            entries.push(Self::read_stats(row, 1, name.clone(), name, true)?);
        }

        // Merge individual files from the __root__ partition
        let root_files = self.query_root_files()?;
        if !root_files.is_empty() {
            entries.extend(root_files);
            Self::sort_entries(&mut entries, self.sort_mode);
        }
        Ok(entries)
    }

    /// Query the entries (subdirectories and files) directly under `path` in a partition.
    fn query_directory_entries(&self, partition: &str, path: &str) -> Result<Vec<DirEntry>> {
        let Some(source) = self.partition_source(partition)? else {
            return Ok(Vec::new());
        };

        // Path prefix we're looking at (with trailing slash for LIKE).
        // We extract the next path component after it.
        let prefix = format!("{}/", path);
        let prefix_len = prefix.len();

        let mut conditions = vec![format!("starts_with(path, {})", sql_quote(&prefix))];
        conditions.extend(self.conditions());

        let order_by = self.sort_mode.to_order_by(self.sort_mode == SortMode::Name);

        let sql = format!(
            r#"
            WITH files AS (
                SELECT * FROM {source}
                WHERE {conditions}
            ),
            components AS (
                SELECT
                    *,
                    CASE
                        WHEN position('/' IN substr(path, {prefix_len} + 1)) > 0
                        THEN substr(path, {prefix_len} + 1, position('/' IN substr(path, {prefix_len} + 1)) - 1)
                        ELSE substr(path, {prefix_len} + 1)
                    END as component,
                    CASE
                        WHEN position('/' IN substr(path, {prefix_len} + 1)) > 0 THEN true
                        ELSE false
                    END as is_dir
                FROM files
            )
            SELECT
                component,
                bool_or(is_dir) as is_dir,
                {aggregates}
            FROM components
            WHERE component != '' AND component IS NOT NULL
            GROUP BY component
            ORDER BY {order_by}
            "#,
            conditions = conditions.join(" AND "),
            aggregates = self.aggregate_columns(),
        );

        let mut entries = Vec::new();
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let component: String = row.get(0)?;
            let is_dir: bool = row.get(1)?;
            let entry_path = format!("{}/{}", path, component);
            entries.push(Self::read_stats(row, 2, component, entry_path, is_dir)?);
        }
        Ok(entries)
    }

    /// Load the list of partitions
    fn load_partitions(&mut self) -> Result<()> {
        self.loading = true;
        let start = Instant::now();

        self.entries = self.query_partition_entries()?;

        self.status = format!("{} entries loaded in {:.2}s", self.entries.len(), start.elapsed().as_secs_f64());
        self.loading = false;
        Ok(())
    }

    /// Root directory of a partition (`<index_root>/<partition>`).
    fn partition_root_path(&self, partition: &str) -> String {
        format!("{}/{}", self.index_root, partition)
    }

    /// Load directory contents for the current path
    fn load_directory(&mut self) -> Result<()> {
        self.loading = true;
        let start = Instant::now();

        let partition = self.current_partition.clone().unwrap();

        // If we don't have a partition root yet, start there
        if self.partition_root.is_empty() {
            self.partition_root = self.partition_root_path(&partition);
            self.current_path = self.partition_root.clone();
        }

        // Always show ".." to go back
        let mut entries = vec![DirEntry::parent()];
        entries.extend(self.query_directory_entries(&partition, &self.current_path)?);
        self.entries = entries;

        let elapsed = start.elapsed().as_secs_f64();
        let filter_info = if self.is_filtered() { " (filtered)" } else { "" };
        self.status = format!("{} entries in {:.2}s{}", self.entries.len(), elapsed, filter_info);
        self.loading = false;
        Ok(())
    }

    /// Start sort selection mode
    fn start_sort_select(&mut self) {
        self.pending_sort = self.sort_mode;
        self.input_mode = InputMode::SortSelect;
    }

    /// Cycle pending sort to next mode
    fn sort_select_next(&mut self) {
        self.pending_sort = self.pending_sort.next();
        while self.pending_sort.is_compare_only() && self.compare.is_none() {
            self.pending_sort = self.pending_sort.next();
        }
    }

    /// Cycle pending sort to previous mode
    fn sort_select_prev(&mut self) {
        self.pending_sort = self.pending_sort.prev();
        while self.pending_sort.is_compare_only() && self.compare.is_none() {
            self.pending_sort = self.pending_sort.prev();
        }
    }

    /// Cycle which files are shown when comparing (all → changed → added → ...)
    fn cycle_status_filter(&mut self) -> Result<()> {
        if self.compare.is_none() {
            self.status = "Change filter requires --compare".to_string();
            return Ok(());
        }
        self.status_filter = self.status_filter.next();
        self.reload()
    }

    /// Confirm sort selection and reload
    fn confirm_sort(&mut self) -> Result<()> {
        self.sort_mode = self.pending_sort;
        self.input_mode = InputMode::Normal;
        self.reload()
    }

    /// Cancel sort selection
    fn cancel_sort(&mut self) {
        self.pending_sort = self.sort_mode;
        self.input_mode = InputMode::Normal;
    }

    /// Reload the current view
    fn reload(&mut self) -> Result<()> {
        match self.view_mode {
            ViewMode::List => {
                if self.current_partition.is_none() {
                    self.load_partitions()?;
                } else {
                    self.load_directory()?;
                }
                // Preserve selection if possible
                if let Some(idx) = self.list_state.selected() {
                    if idx >= self.entries.len() && !self.entries.is_empty() {
                        self.list_state.select(Some(self.entries.len() - 1));
                    }
                }
            }
            ViewMode::Tree => {
                self.init_tree()?;
            }
        }
        Ok(())
    }

    /// Start input mode for a filter
    fn start_input(&mut self, mode: InputMode) {
        self.input_mode = mode;
        self.input_buffer.clear();
    }

    /// Cancel input mode
    fn cancel_input(&mut self) {
        self.input_mode = InputMode::Normal;
        self.input_buffer.clear();
    }

    /// Confirm input and apply filter
    fn confirm_input(&mut self) -> Result<()> {
        let value = self.input_buffer.trim().to_string();
        
        match self.input_mode {
            InputMode::Pattern => {
                if value.is_empty() {
                    self.filters.pattern = None;
                } else {
                    self.filters.pattern = Some(value);
                }
            }
            InputMode::OlderThan(ts) => {
                if value.is_empty() {
                    match ts {
                        TimestampCol::Atime => self.filters.older_than = None,
                        TimestampCol::Mtime => self.filters.mtime_older_than = None,
                        TimestampCol::Ctime => self.filters.ctime_older_than = None,
                    }
                } else if let Ok(days) = value.parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let threshold = now - (days as i64 * 86400);
                    match ts {
                        TimestampCol::Atime => self.filters.older_than = Some(threshold),
                        TimestampCol::Mtime => self.filters.mtime_older_than = Some(threshold),
                        TimestampCol::Ctime => self.filters.ctime_older_than = Some(threshold),
                    }
                } else {
                    self.status = format!("Invalid number: {}", value);
                    self.input_mode = InputMode::Normal;
                    self.input_buffer.clear();
                    return Ok(());
                }
            }
            InputMode::NewerThan(ts) => {
                if value.is_empty() {
                    match ts {
                        TimestampCol::Atime => self.filters.newer_than = None,
                        TimestampCol::Mtime => self.filters.mtime_newer_than = None,
                        TimestampCol::Ctime => self.filters.ctime_newer_than = None,
                    }
                } else if let Ok(days) = value.parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let threshold = now - (days as i64 * 86400);
                    match ts {
                        TimestampCol::Atime => self.filters.newer_than = Some(threshold),
                        TimestampCol::Mtime => self.filters.mtime_newer_than = Some(threshold),
                        TimestampCol::Ctime => self.filters.ctime_newer_than = Some(threshold),
                    }
                } else {
                    self.status = format!("Invalid number: {}", value);
                    self.input_mode = InputMode::Normal;
                    self.input_buffer.clear();
                    return Ok(());
                }
            }
            InputMode::MinSize => {
                if value.is_empty() {
                    self.filters.min_size = None;
                } else {
                    match parse_size(&value) {
                        Ok(size) => self.filters.min_size = Some(size),
                        Err(e) => {
                            self.status = e;
                            self.input_mode = InputMode::Normal;
                            self.input_buffer.clear();
                            return Ok(());
                        }
                    }
                }
            }
            InputMode::MaxSize => {
                if value.is_empty() {
                    self.filters.max_size = None;
                } else {
                    match parse_size(&value) {
                        Ok(size) => self.filters.max_size = Some(size),
                        Err(e) => {
                            self.status = e;
                            self.input_mode = InputMode::Normal;
                            self.input_buffer.clear();
                            return Ok(());
                        }
                    }
                }
            }
            InputMode::Normal | InputMode::SortSelect => {}
        }
        
        self.input_mode = InputMode::Normal;
        self.input_buffer.clear();
        self.reload()
    }

    /// Clear all filters
    fn clear_filters(&mut self) -> Result<()> {
        self.filters.clear();
        self.reload()
    }
    
    fn select_next(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1).min(self.entries.len() - 1),
            None => 0,
        };
        self.list_state.select(Some(i));
    }
    
    fn select_prev(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn select_first(&mut self) {
        if !self.entries.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn select_last(&mut self) {
        if !self.entries.is_empty() {
            self.list_state.select(Some(self.entries.len() - 1));
        }
    }

    fn cycle_timestamp(&mut self) { self.timestamp_col = self.timestamp_col.next(); }
    fn toggle_uid(&mut self)      { self.visible_extras.uid  = !self.visible_extras.uid; }
    fn toggle_gid(&mut self)      { self.visible_extras.gid  = !self.visible_extras.gid; }
    fn toggle_mode(&mut self)     { self.visible_extras.mode = !self.visible_extras.mode; }
    fn toggle_help(&mut self)     { self.show_help = !self.show_help; }
    
    fn enter_selected(&mut self) -> Result<()> {
        let Some(idx) = self.list_state.selected() else {
            return Ok(());
        };
        
        let entry = &self.entries[idx];
        
        if !entry.is_dir {
            return Ok(());
        }
        
        if entry.name == ".." {
            return self.go_up();
        }
        
        // If we're at the partition list, enter the partition
        if self.current_partition.is_none() {
            self.current_partition = Some(entry.name.clone());
            self.partition_root.clear();
            self.current_path.clear();
            self.load_directory()?;
        } else {
            // Enter subdirectory - use the full path from the entry
            self.current_path = format!("{}/{}", self.current_path, entry.name);
            self.load_directory()?;
        }
        
        self.list_state.select(Some(0));
        Ok(())
    }
    
    fn go_up(&mut self) -> Result<()> {
        if self.current_partition.is_none() {
            // Already at root
            return Ok(());
        }
        
        if self.current_path == self.partition_root || self.current_path.is_empty() {
            // Go back to partition list
            self.current_partition = None;
            self.partition_root.clear();
            self.current_path.clear();
            self.load_partitions()?;
        } else {
            // Go up one directory
            if let Some(pos) = self.current_path.rfind('/') {
                self.current_path = self.current_path[..pos].to_string();
            } else {
                self.current_path.clear();
            }
            self.load_directory()?;
        }
        
        self.list_state.select(Some(0));
        Ok(())
    }
    
    // ---- Tree (Miller columns) mode ----

    /// Create a Column for the partition list.
    fn make_partition_column(&self) -> Result<Column> {
        let entries = self.query_partition_entries()?;

        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }

        Ok(Column {
            title: "Partitions".to_string(),
            partition: None,
            partition_root: String::new(),
            path: String::new(),
            entries,
            list_state,
        })
    }

    /// Create a Column for a partition's root directory.
    fn make_partition_root_column(&self, partition: &str) -> Result<Column> {
        let partition_root = self.partition_root_path(partition);
        self.make_directory_column_tree(partition, &partition_root, &partition_root)
    }

    /// Create a Column for a directory within a partition.
    fn make_directory_column_tree(
        &self,
        partition: &str,
        partition_root: &str,
        path: &str,
    ) -> Result<Column> {
        let entries = self.query_directory_entries(partition, path)?;

        let title = path.rsplit('/').next().unwrap_or(partition).to_string();

        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }

        Ok(Column {
            title,
            partition: Some(partition.to_string()),
            partition_root: partition_root.to_string(),
            path: path.to_string(),
            entries,
            list_state,
        })
    }

    /// Initialize tree mode columns from scratch.
    fn init_tree(&mut self) -> Result<()> {
        self.columns.clear();
        self.active_column = 0;

        let partition_col = self.make_partition_column()?;
        self.columns.push(partition_col);

        // Auto-expand preview for the selected partition
        self.tree_update_preview()?;
        Ok(())
    }

    /// Update the preview column (active_column + 1) based on the active column's selection.
    /// Truncates any columns beyond the preview. For files, populates `file_preview`.
    fn tree_update_preview(&mut self) -> Result<()> {
        // Remove everything after the active column
        self.columns.truncate(self.active_column + 1);
        self.file_preview = None;
        self.preview_focused = false;

        // Extract info from active column's selection (avoid borrow conflict)
        enum PreviewAction {
            Directory {
                is_partition_list: bool,
                name: String,
                partition: Option<String>,
                partition_root: String,
                path: String,
            },
            File {
                path: String,
                size: i64,
                atime: i64,
                size_old: Option<i64>,
            },
            None,
        }

        let action = {
            let col = &self.columns[self.active_column];
            if let Some(idx) = col.list_state.selected() {
                if idx < col.entries.len() {
                    let entry = &col.entries[idx];
                    if entry.is_dir {
                        PreviewAction::Directory {
                            is_partition_list: col.partition.is_none(),
                            name: entry.name.clone(),
                            partition: col.partition.clone(),
                            partition_root: col.partition_root.clone(),
                            path: col.path.clone(),
                        }
                    } else {
                        PreviewAction::File {
                            path: entry.path.clone(),
                            size: entry.total_size,
                            atime: entry.latest_atime,
                            size_old: (entry.files_old > 0).then_some(entry.size_old),
                        }
                    }
                } else {
                    PreviewAction::None
                }
            } else {
                PreviewAction::None
            }
        };

        match action {
            PreviewAction::Directory { is_partition_list, name, partition, partition_root, path } => {
                let new_col = if is_partition_list {
                    self.make_partition_root_column(&name)?
                } else {
                    let part = partition.as_ref().unwrap();
                    let new_path = format!("{}/{}", path, name);
                    self.make_directory_column_tree(part, &partition_root, &new_path)?
                };
                self.columns.push(new_col);
            }
            PreviewAction::File { path, size, atime, size_old } => {
                let mut preview = Self::load_file_preview(&path, size, atime);
                if self.compare.is_some() {
                    preview.size_old = size_old;
                }
                self.file_preview = Some(preview);
            }
            PreviewAction::None => {}
        }

        Ok(())
    }

    /// Load file type info and (optionally) text content for the preview pane.
    fn load_file_preview(path: &str, size: i64, atime: i64) -> FilePreview {
        const SNIFF_SIZE: usize = 8192;

        // Read the first SNIFF_SIZE bytes for type detection
        let sniff_buf = File::open(path)
            .and_then(|mut f| {
                let mut buf = vec![0u8; SNIFF_SIZE];
                let n = f.read(&mut buf)?;
                buf.truncate(n);
                Ok(buf)
            })
            .unwrap_or_default();

        if sniff_buf.is_empty() {
            return FilePreview {
                path: path.to_string(),
                size,
                atime,
                size_old: None,
                type_description: "(unreadable)".to_string(),
                is_text: false,
                lines: VecDeque::new(),
                first_line_number: 0,
                total_lines_loaded: 0,
                file_offset: 0,
                eof_reached: true,
                scroll_offset: 0,
            };
        }

        // Detect file type using multi-layer heuristics
        let (type_description, is_text) = detect_file_type(&sniff_buf, path);

        // Load initial text content if applicable
        let mut lines = VecDeque::new();
        let mut file_offset: u64 = 0;
        let mut eof_reached = !is_text;
        let mut total_lines_loaded: usize = 0;

        if is_text {
            if let Ok(mut f) = File::open(path) {
                let mut buf = vec![0u8; CHUNK_BYTES];
                match f.read(&mut buf) {
                    Ok(0) => {
                        eof_reached = true;
                    }
                    Ok(n) => {
                        file_offset = n as u64;
                        // Check if we hit EOF (read less than buffer)
                        if n < CHUNK_BYTES {
                            eof_reached = true;
                        }
                        // Parse lines from the chunk. If not EOF, the last
                        // "line" may be a partial line — we back up file_offset
                        // to re-read it on the next chunk.
                        let chunk = &buf[..n];
                        if let Ok(text) = std::str::from_utf8(chunk) {
                            let mut iter = text.split('\n').peekable();
                            while let Some(line) = iter.next() {
                                if iter.peek().is_none() && !eof_reached {
                                    // Last fragment before EOF unknown — back up
                                    file_offset -= line.len() as u64;
                                    break;
                                }
                                lines.push_back(strip_ansi(line));
                                total_lines_loaded += 1;
                            }
                        }
                    }
                    Err(_) => {
                        eof_reached = true;
                    }
                }
            }
        }

        FilePreview {
            path: path.to_string(),
            size,
            atime,
            size_old: None,
            type_description,
            is_text,
            lines,
            first_line_number: 0,
            total_lines_loaded,
            file_offset,
            eof_reached,
            scroll_offset: 0,
        }
    }

    /// Read the next chunk of lines from the file, appending to the deque.
    /// Trims the front if the buffer exceeds MAX_BUFFER_LINES.
    fn preview_load_more_lines(preview: &mut FilePreview) {
        if preview.eof_reached || !preview.is_text {
            return;
        }

        let Ok(mut f) = File::open(&preview.path) else {
            preview.eof_reached = true;
            return;
        };
        if f.seek(SeekFrom::Start(preview.file_offset)).is_err() {
            preview.eof_reached = true;
            return;
        }

        let mut reader = BufReader::with_capacity(CHUNK_BYTES, f);
        let mut bytes_read: u64 = 0;
        let mut line_buf = String::new();

        loop {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => {
                    // True EOF
                    preview.eof_reached = true;
                    break;
                }
                Ok(n) => {
                    bytes_read += n as u64;

                    // Strip trailing newline (and CR if present)
                    if line_buf.ends_with('\n') {
                        line_buf.pop();
                        if line_buf.ends_with('\r') {
                            line_buf.pop();
                        }
                    }

                    preview.lines.push_back(strip_ansi(&line_buf));
                    preview.total_lines_loaded += 1;

                    // Trim front if over budget
                    if preview.lines.len() > MAX_BUFFER_LINES {
                        preview.lines.pop_front();
                        preview.first_line_number += 1;
                    }

                    // Stop after reading ~CHUNK_BYTES
                    if bytes_read >= CHUNK_BYTES as u64 {
                        break;
                    }
                }
                Err(_) => {
                    preview.eof_reached = true;
                    break;
                }
            }
        }

        preview.file_offset += bytes_read;
    }

    /// Read forward in chunks until EOF, maintaining the sliding window.
    fn preview_load_to_eof(preview: &mut FilePreview) {
        while !preview.eof_reached {
            Self::preview_load_more_lines(preview);
        }
    }

    /// Reload the file preview from the beginning (for `g` after front eviction).
    fn preview_reload_from_start(preview: &mut FilePreview) {
        preview.lines.clear();
        preview.first_line_number = 0;
        preview.total_lines_loaded = 0;
        preview.file_offset = 0;
        preview.eof_reached = false;
        preview.scroll_offset = 0;
        Self::preview_load_more_lines(preview);
    }

    /// Move selection down in the active tree column and update preview.
    fn tree_select_next(&mut self) -> Result<()> {
        if self.columns.is_empty() {
            return Ok(());
        }
        let col = &mut self.columns[self.active_column];
        if col.entries.is_empty() {
            return Ok(());
        }
        let i = match col.list_state.selected() {
            Some(i) => (i + 1).min(col.entries.len() - 1),
            None => 0,
        };
        col.list_state.select(Some(i));
        self.tree_update_preview()
    }

    /// Move selection up in the active tree column and update preview.
    fn tree_select_prev(&mut self) -> Result<()> {
        if self.columns.is_empty() {
            return Ok(());
        }
        let col = &mut self.columns[self.active_column];
        if col.entries.is_empty() {
            return Ok(());
        }
        let i = match col.list_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        col.list_state.select(Some(i));
        self.tree_update_preview()
    }

    /// Jump to the first entry in the active tree column.
    fn tree_select_first(&mut self) -> Result<()> {
        if self.columns.is_empty() {
            return Ok(());
        }
        let col = &mut self.columns[self.active_column];
        if !col.entries.is_empty() {
            col.list_state.select(Some(0));
        }
        self.tree_update_preview()
    }

    /// Jump to the last entry in the active tree column.
    fn tree_select_last(&mut self) -> Result<()> {
        if self.columns.is_empty() {
            return Ok(());
        }
        let col = &mut self.columns[self.active_column];
        if !col.entries.is_empty() {
            col.list_state.select(Some(col.entries.len() - 1));
        }
        self.tree_update_preview()
    }

    /// Move focus right into the preview column.
    fn tree_right(&mut self) -> Result<()> {
        if self.active_column + 1 < self.columns.len() {
            self.active_column += 1;
            self.tree_update_preview()?;
        }
        Ok(())
    }

    /// Move focus left to the parent column.
    fn tree_left(&mut self) -> Result<()> {
        if self.active_column > 0 {
            self.active_column -= 1;
            // Keep active column + its preview, truncate the rest
            self.columns.truncate(self.active_column + 2);
        }
        Ok(())
    }

    /// Toggle between list and tree view modes, preserving navigation position.
    fn toggle_view_mode(&mut self) -> Result<()> {
        match self.view_mode {
            ViewMode::List => {
                self.view_mode = ViewMode::Tree;
                self.init_tree_from_list_position()?;
            }
            ViewMode::Tree => {
                self.view_mode = ViewMode::List;
                self.restore_list_from_tree_position()?;
            }
        }
        Ok(())
    }

    /// Initialize tree mode, expanding to match the current list-mode position.
    fn init_tree_from_list_position(&mut self) -> Result<()> {
        self.columns.clear();
        self.active_column = 0;

        let partition_col = self.make_partition_column()?;
        self.columns.push(partition_col);

        let Some(ref partition) = self.current_partition else {
            // At partition list — just show the preview for first partition
            self.tree_update_preview()?;
            return Ok(());
        };
        let partition = partition.clone();

        // Select the matching partition in column 0
        if let Some(idx) = self.columns[0].entries.iter().position(|e| e.name == partition) {
            self.columns[0].list_state.select(Some(idx));
        }

        // Expand into partition root
        self.tree_update_preview()?;
        self.active_column = 1;

        // Walk path components from partition_root to current_path
        if !self.current_path.is_empty() && self.current_path.len() > self.partition_root.len() {
            let relative = self.current_path[self.partition_root.len()..].to_string();
            let components: Vec<&str> = relative.split('/').filter(|c| !c.is_empty()).collect();

            for component in &components {
                // Select the matching entry in the current active column
                let col = &self.columns[self.active_column];
                if let Some(idx) = col.entries.iter().position(|e| e.name == *component) {
                    self.columns[self.active_column].list_state.select(Some(idx));
                    self.tree_update_preview()?;
                    // Move into the newly expanded column
                    if self.active_column + 1 < self.columns.len() {
                        self.active_column += 1;
                    }
                } else {
                    break;
                }
            }
        }

        // Active column is the deepest directory we reached; update its preview
        self.tree_update_preview()?;
        Ok(())
    }

    /// Restore list-mode state from the current tree-mode position.
    fn restore_list_from_tree_position(&mut self) -> Result<()> {
        if self.columns.is_empty() {
            // No tree state — fall back to partition list
            self.current_partition = None;
            self.partition_root.clear();
            self.current_path.clear();
            self.load_partitions()?;
            if !self.entries.is_empty() {
                self.list_state.select(Some(0));
            }
            return Ok(());
        }

        let col = &self.columns[self.active_column];
        let selected_name = col.list_state.selected()
            .and_then(|idx| col.entries.get(idx))
            .map(|e| e.name.clone());

        if col.partition.is_none() {
            // Active column is the partition list
            self.current_partition = None;
            self.partition_root.clear();
            self.current_path.clear();
            self.load_partitions()?;
            // Try to select the same partition
            if let Some(name) = selected_name {
                if let Some(idx) = self.entries.iter().position(|e| e.name == name) {
                    self.list_state.select(Some(idx));
                    return Ok(());
                }
            }
            if !self.entries.is_empty() {
                self.list_state.select(Some(0));
            }
        } else {
            // Active column is inside a partition
            self.current_partition = col.partition.clone();
            self.partition_root = col.partition_root.clone();
            self.current_path = col.path.clone();
            self.load_directory()?;
            // Try to select the same entry
            if let Some(name) = selected_name {
                if let Some(idx) = self.entries.iter().position(|e| e.name == name) {
                    self.list_state.select(Some(idx));
                    return Ok(());
                }
            }
            if !self.entries.is_empty() {
                self.list_state.select(Some(0));
            }
        }

        Ok(())
    }

    fn format_atime(&self, atime: i64) -> String {
        if atime == 0 {
            return String::new();
        }
        
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let time = UNIX_EPOCH + Duration::from_secs(atime as u64);
        let now = SystemTime::now();
        
        if let Ok(duration) = now.duration_since(time) {
            let days = duration.as_secs() / 86400;
            if days == 0 {
                "today".to_string()
            } else if days == 1 {
                "1 day ago".to_string()
            } else if days < 30 {
                format!("{} days ago", days)
            } else if days < 365 {
                let months = days / 30;
                if months == 1 {
                    "1 month ago".to_string()
                } else {
                    format!("{} months ago", months)
                }
            } else {
                let years = days / 365;
                if years == 1 {
                    "1 year ago".to_string()
                } else {
                    format!("{} years ago", years)
                }
            }
        } else {
            "future".to_string()
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Resolve index path
    let index_path = args.index.canonicalize()
        .with_context(|| format!("Index directory not found: {}", args.index.display()))?;
    
    // Parse sort mode
    let sort_mode: SortMode = args.sort.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    if sort_mode.is_compare_only() && args.compare.is_none() {
        anyhow::bail!("--sort {} requires --compare", sort_mode);
    }
    
    // Build filters from CLI args
    let filters = QueryFilters::new()
        .with_pattern(args.pattern)
        .with_older_than(args.older_than)
        .with_newer_than(args.newer_than)
        .with_min_size(args.min_size.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?
        .with_max_size(args.max_size.as_deref())
        .map_err(|e| anyhow::anyhow!(e))?;
    
    // Connect to DuckDB
    let conn = Connection::open_in_memory()?;

    let partitions = list_partitions(&index_path)?;
    let index_root = discover_index_root(&conn, &index_path, &partitions)?;

    let compare = match args.compare {
        Some(ref old_path) => {
            let old_index = old_path.canonicalize()
                .with_context(|| format!("Comparison index not found: {}", old_path.display()))?;
            let old_partitions = list_partitions(&old_index)?;
            let old_root = discover_index_root(&conn, &old_index, &old_partitions)?;
            Some(Compare {
                old: DiffSide { index: old_index, root: old_root },
                new: DiffSide { index: index_path.clone(), root: index_root.clone() },
                old_partitions: old_partitions.into_iter().collect(),
                new_partitions: partitions.into_iter().collect(),
                tables: RefCell::new(HashMap::new()),
            })
        }
        None => None,
    };

    // Initialize app
    let mut app = App::new(conn, index_path, index_root, compare, args.partition, filters, sort_mode)?;
    
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    
    // Main loop
    let result = run_app(&mut terminal, &mut app);
    
    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    
    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                
                // Handle sort selection mode
                if app.input_mode == InputMode::SortSelect {
                    match key.code {
                        KeyCode::Esc => app.cancel_sort(),
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            if let Err(e) = app.confirm_sort() {
                                app.status = format!("Error: {}", e);
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') | KeyCode::Left => {
                            app.sort_select_prev();
                        }
                        KeyCode::Down | KeyCode::Char('j') | KeyCode::Right | KeyCode::Char('s') => {
                            app.sort_select_next();
                        }
                        _ => {}
                    }
                    continue;
                }

                // Handle text input mode
                if app.input_mode != InputMode::Normal {
                    match key.code {
                        KeyCode::Esc => app.cancel_input(),
                        KeyCode::Enter => {
                            if let Err(e) = app.confirm_input() {
                                app.status = format!("Error: {}", e);
                            }
                        }
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buffer.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }
                
                // Handle preview pager focus mode (tree view file preview)
                if app.preview_focused {
                    match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            if let Some(ref mut preview) = app.file_preview {
                                preview.scroll_offset += 1;
                                // Load more if we're near the end of loaded content
                                let last_loaded = preview.first_line_number + preview.lines.len();
                                if preview.scroll_offset + 40 >= last_loaded {
                                    App::preview_load_more_lines(preview);
                                }
                                // Clamp to total loaded
                                let max_offset = preview.total_lines_loaded.saturating_sub(1);
                                preview.scroll_offset = preview.scroll_offset.min(max_offset);
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            if let Some(ref mut preview) = app.file_preview {
                                if preview.scroll_offset > 0 {
                                    preview.scroll_offset -= 1;
                                }
                                // If scrolled before the buffer start, clamp
                                if preview.scroll_offset < preview.first_line_number {
                                    preview.scroll_offset = preview.first_line_number;
                                }
                            }
                        }
                        KeyCode::Char('g') => {
                            if let Some(ref mut preview) = app.file_preview {
                                if preview.first_line_number > 0 {
                                    // Front was evicted, reload from start
                                    App::preview_reload_from_start(preview);
                                } else {
                                    preview.scroll_offset = 0;
                                }
                            }
                        }
                        KeyCode::Char('G') => {
                            if let Some(ref mut preview) = app.file_preview {
                                App::preview_load_to_eof(preview);
                                preview.scroll_offset = preview.total_lines_loaded.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('d') => {
                            // Half-page down
                            if let Some(ref mut preview) = app.file_preview {
                                preview.scroll_offset += 20;
                                // Load more if needed
                                let last_loaded = preview.first_line_number + preview.lines.len();
                                if preview.scroll_offset + 40 >= last_loaded && !preview.eof_reached {
                                    App::preview_load_more_lines(preview);
                                }
                                let max_offset = preview.total_lines_loaded.saturating_sub(1);
                                preview.scroll_offset = preview.scroll_offset.min(max_offset);
                            }
                        }
                        KeyCode::Char('u') => {
                            // Half-page up
                            if let Some(ref mut preview) = app.file_preview {
                                preview.scroll_offset = preview.scroll_offset.saturating_sub(20);
                                if preview.scroll_offset < preview.first_line_number {
                                    preview.scroll_offset = preview.first_line_number;
                                }
                            }
                        }
                        KeyCode::Esc | KeyCode::Left | KeyCode::Char('q') | KeyCode::Char(' ') => {
                            app.preview_focused = false;
                        }
                        _ => {}
                    }
                    continue;
                }

                // Dismiss help overlay on any keypress
                if app.show_help {
                    app.show_help = false;
                    continue;
                }

                // Normal mode — shared keys first, then mode-specific navigation
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    // Toggle list ↔ tree view
                    KeyCode::Char('m') => {
                        if let Err(e) = app.toggle_view_mode() {
                            app.status = format!("Error: {}", e);
                        }
                    }
                    // Help overlay
                    KeyCode::Char('?') => app.toggle_help(),
                    // Cycle timestamp column (both modes)
                    KeyCode::Char('t') => app.cycle_timestamp(),
                    // Extra column toggles (both modes)
                    KeyCode::Char('u') => app.toggle_uid(),
                    KeyCode::Char('g') => app.toggle_gid(),
                    KeyCode::Char('x') => app.toggle_mode(),
                    // Sort mode selection (both modes)
                    KeyCode::Char('s') => app.start_sort_select(),
                    // Cycle change filter (compare mode)
                    KeyCode::Char('d') => {
                        if let Err(e) = app.cycle_status_filter() {
                            app.status = format!("Error: {}", e);
                        }
                    }
                    // Filter inputs (both modes)
                    KeyCode::Char('/') => app.start_input(InputMode::Pattern),
                    KeyCode::Char('o') => app.start_input(InputMode::OlderThan(app.timestamp_col)),
                    KeyCode::Char('n') => app.start_input(InputMode::NewerThan(app.timestamp_col)),
                    KeyCode::Char('>') => app.start_input(InputMode::MinSize),
                    KeyCode::Char('<') => app.start_input(InputMode::MaxSize),
                    // Clear filters (both modes)
                    KeyCode::Char('c') => {
                        if let Err(e) = app.clear_filters() {
                            app.status = format!("Error: {}", e);
                        }
                    }
                    // Go to first/last (both modes)
                    KeyCode::PageUp => match app.view_mode {
                        ViewMode::List => app.select_first(),
                        ViewMode::Tree => {
                            if let Err(e) = app.tree_select_first() {
                                app.status = format!("Error: {}", e);
                            }
                        }
                    },
                    KeyCode::PageDown => match app.view_mode {
                        ViewMode::List => app.select_last(),
                        ViewMode::Tree => {
                            if let Err(e) = app.tree_select_last() {
                                app.status = format!("Error: {}", e);
                            }
                        }
                    },
                    // Mode-specific navigation
                    _ => match app.view_mode {
                        ViewMode::List => match key.code {
                            KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                            KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                            KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
                                if let Err(e) = app.enter_selected() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            KeyCode::Left | KeyCode::Backspace => {
                                if let Err(e) = app.go_up() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            _ => {}
                        },
                        ViewMode::Tree => match key.code {
                            KeyCode::Down | KeyCode::Char('j') => {
                                if let Err(e) = app.tree_select_next() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if let Err(e) = app.tree_select_prev() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') => {
                                // If a file is selected, activate pager mode
                                if app.file_preview.is_some() {
                                    app.preview_focused = true;
                                } else if let Err(e) = app.tree_right() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            KeyCode::Left | KeyCode::Backspace => {
                                if let Err(e) = app.tree_left() {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                            _ => {}
                        },
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),     // Content
            Constraint::Length(1),  // Status bar
        ])
        .split(f.area());

    // Render content based on view mode
    match app.view_mode {
        ViewMode::List => render_list_content(f, app, chunks[0]),
        ViewMode::Tree => render_tree_content(f, app, chunks[0]),
    }

    // Shared status bar
    render_status_bar(f, app, chunks[1]);

    // Help overlay
    if app.show_help {
        render_help_overlay(f);
    }
}

fn render_help_overlay(f: &mut Frame) {
    let area = f.area();
    let popup_w = 62u16.min(area.width.saturating_sub(4));
    let popup_h = 20u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect { x, y, width: popup_w, height: popup_h };

    f.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(vec![
            Span::styled("Navigation", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
            Span::raw("              "),
            Span::styled("Display / Filter", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
        ]),
        Line::from("──────────────────────  ──────────────────────────"),
        Line::from(vec![Span::raw("j/↓  next               "), Span::styled("t", Style::default().fg(Color::Cyan)), Span::raw("   cycle timestamp (accessed/modified/changed)")]),
        Line::from(vec![Span::raw("k/↑  prev               "), Span::styled("u", Style::default().fg(Color::Cyan)), Span::raw("   toggle user column")]),
        Line::from(vec![Span::raw("PgUp first              "), Span::styled("g", Style::default().fg(Color::Cyan)), Span::raw("   toggle group column")]),
        Line::from(vec![Span::raw("PgDn last               "), Span::styled("x", Style::default().fg(Color::Cyan)), Span::raw("   toggle mode column")]),
        Line::from(vec![Span::raw("←/BS up / collapse      "), Span::styled("s", Style::default().fg(Color::Cyan)), Span::raw("   sort selector")]),
        Line::from(vec![Span::raw("→/Enter enter/expand    "), Span::styled("/", Style::default().fg(Color::Cyan)), Span::raw("   filter by pattern")]),
        Line::from(vec![Span::raw("m    list ↔ tree         "), Span::styled("o", Style::default().fg(Color::Cyan)), Span::raw("   older than N days (active timestamp)")]),
        Line::from(vec![Span::raw("q    quit                "), Span::styled("n", Style::default().fg(Color::Cyan)), Span::raw("   newer than N days (active timestamp)")]),
        Line::from(vec![Span::raw("?    this help           "), Span::styled(">", Style::default().fg(Color::Cyan)), Span::raw("   min size")]),
        Line::from(vec![Span::raw("                         "), Span::styled("<", Style::default().fg(Color::Cyan)), Span::raw("   max size")]),
        Line::from(vec![Span::raw("                         "), Span::styled("c", Style::default().fg(Color::Cyan)), Span::raw("   clear filters")]),
        Line::from(vec![Span::raw("                         "), Span::styled("d", Style::default().fg(Color::Cyan)), Span::raw("   cycle changes shown (--compare)")]),
        Line::from(""),
        Line::from(Span::styled("  Press any key to close", Style::default().fg(Color::DarkGray))),
    ];

    let paragraph = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .title(Span::styled(" Keyboard Shortcuts ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)))
        );
    f.render_widget(paragraph, popup_area);
}

/// Render the traditional single-list view.
fn render_list_content(f: &mut Frame, app: &App, area: Rect) {
    // Build filter display string
    let filter_display = app.filters.format_display();
    let filter_suffix = if filter_display.is_empty() {
        String::new()
    } else {
        format!(" {}", filter_display)
    };

    // Title with current path
    let title = if let Some(ref partition) = app.current_partition {
        let display_path = if app.current_path.len() > app.partition_root.len() {
            &app.current_path[app.partition_root.len()..]
        } else {
            ""
        };
        if app.loading {
            format!(" {}{} (loading...){} ", partition, display_path, filter_suffix)
        } else {
            format!(" {}{}{} ", partition, display_path, filter_suffix)
        }
    } else {
        if app.loading {
            format!(" Partitions (loading...){} ", filter_suffix)
        } else {
            format!(" Partitions{} ", filter_suffix)
        }
    };

    // Pre-compute formatted strings and find max widths dynamically
    let comparing = app.compare.is_some();
    struct EntryFmt {
        name: String,
        name_style: Style,
        size: String,
        delta: String,
        delta_style: Style,
        count: String,
        dfiles: String,
        dfiles_style: Style,
        ts: String,
        uid: String,
        gid: String,
        mode_s: String,
    }
    let formatted: Vec<EntryFmt> = app.entries.iter().map(|entry| {
        let prefix = if entry.is_dir && entry.name != ".." {
            "▸ "
        } else if entry.name == ".." {
            "◂ "
        } else {
            "  "
        };
        let is_blank = entry.name == "..";
        let marker = if comparing && !is_blank { entry.change_marker() } else { ' ' };
        let name = if comparing {
            format!("{} {}{}", marker, prefix, entry.name)
        } else {
            format!("{}{}", prefix, entry.name)
        };
        let name_style = marker_style(marker);
        let (delta, dfiles) = if comparing && !is_blank {
            (format_size_delta(entry), format_count_delta(entry.files_delta()))
        } else {
            (String::new(), String::new())
        };
        let delta_style = delta_style(entry.size_delta());
        let dfiles_style = self::delta_style(entry.files_delta());

        let size = if is_blank { String::new() } else { format_bytes(entry.total_size as u64) };
        let count = if is_blank { String::new() } else { format_file_count(entry.file_count) };
        let ts = if is_blank { String::new() } else {
            match app.timestamp_col {
                TimestampCol::Atime => app.format_atime(entry.latest_atime),
                TimestampCol::Mtime => app.format_atime(entry.latest_mtime),
                TimestampCol::Ctime => app.format_atime(entry.latest_ctime),
            }
        };
        let uid = if is_blank || !app.visible_extras.uid { String::new() } else { format_uid(entry.uid, entry.is_dir) };
        let gid = if is_blank || !app.visible_extras.gid { String::new() } else { format_gid(entry.gid, entry.is_dir) };
        let mode_s = if is_blank || !app.visible_extras.mode { String::new() } else { format_mode(entry.mode, entry.is_dir) };
        EntryFmt { name, name_style, size, delta, delta_style, count, dfiles, dfiles_style, ts, uid, gid, mode_s }
    }).collect();

    // Calculate dynamic column widths based on content (with minimum widths)
    let size_width  = formatted.iter().map(|f| f.size.len()).max().unwrap_or(0).max(10);
    let delta_width = if comparing { formatted.iter().map(|f| f.delta.len()).max().unwrap_or(0).max(10) } else { 0 };
    let count_width = formatted.iter().map(|f| f.count.len()).max().unwrap_or(0).max(8);
    let dfiles_width = if comparing { formatted.iter().map(|f| f.dfiles.len()).max().unwrap_or(0).max(6) } else { 0 };
    let ts_width    = formatted.iter().map(|f| f.ts.len()).max().unwrap_or(0).max(12);
    let uid_width   = if app.visible_extras.uid  { formatted.iter().map(|f| f.uid.len()).max().unwrap_or(0).max(4).max("user".len()) } else { 0 };
    let gid_width   = if app.visible_extras.gid  { formatted.iter().map(|f| f.gid.len()).max().unwrap_or(0).max(5).max("group".len()) } else { 0 };
    let mode_width  = if app.visible_extras.mode { formatted.iter().map(|f| f.mode_s.len()).max().unwrap_or(0).max(6) } else { 0 };

    let extra_cols = [uid_width, gid_width, mode_width, delta_width, dfiles_width]
        .iter().filter(|&&w| w > 0).map(|&w| w + 2).sum::<usize>();

    // Calculate available width for names
    let area_width = area.width.saturating_sub(2) as usize;
    let fixed_cols = size_width + count_width + ts_width + extra_cols + 8;
    let name_width = area_width.saturating_sub(fixed_cols);

    // Entry list
    let items: Vec<ListItem> = formatted.iter().map(|f| {
        let name_display = if f.name.len() > name_width {
            format!("{}…", &f.name[..name_width.saturating_sub(1)])
        } else {
            f.name.clone()
        };

        let mut spans = vec![
            Span::styled(format!("{:<name_width$}", name_display), f.name_style),
            Span::raw(format!("  {:>size_width$}", f.size)),
        ];
        if comparing {
            spans.push(Span::styled(format!("  {:>delta_width$}", f.delta), f.delta_style));
        }
        spans.push(Span::raw(format!("  {:>count_width$}", f.count)));
        if comparing {
            spans.push(Span::styled(format!("  {:>dfiles_width$}", f.dfiles), f.dfiles_style));
        }
        let mut rest = format!("  {:>ts_width$}", f.ts);
        if app.visible_extras.uid  { rest += &format!("  {:>uid_width$}",  f.uid,    uid_width  = uid_width);  }
        if app.visible_extras.gid  { rest += &format!("  {:>gid_width$}",  f.gid,    gid_width  = gid_width);  }
        if app.visible_extras.mode { rest += &format!("  {:>mode_width$}", f.mode_s, mode_width = mode_width); }
        spans.push(Span::raw(rest));

        ListItem::new(Line::from(spans))
    }).collect();

    // Build header string using same widths as data rows
    let mut header = format!("{:<name_width$}  {:>size_width$}", "name", "size");
    if comparing { header += &format!("  {:>delta_width$}", "Δsize"); }
    header += &format!("  {:>count_width$}", "files");
    if comparing { header += &format!("  {:>dfiles_width$}", "Δfiles"); }
    header += &format!("  {:>ts_width$}", app.timestamp_col.label());
    if app.visible_extras.uid  { header += &format!("  {:>uid_width$}",  "user",  uid_width  = uid_width);  }
    if app.visible_extras.gid  { header += &format!("  {:>gid_width$}",  "group", gid_width  = gid_width);  }
    if app.visible_extras.mode { header += &format!("  {:>mode_width$}", "mode",  mode_width = mode_width); }

    // Render block separately so we can split the inner area
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    f.render_widget(
        Paragraph::new(header)
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        inner_chunks[0],
    );

    let list = List::new(items)
        .highlight_symbol("▶ ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, inner_chunks[1], &mut app.list_state.clone());
}

/// Minimum column width for Miller columns view.
const MIN_COLUMN_WIDTH: u16 = 20;
/// Maximum number of visible columns.
const MAX_VISIBLE_COLUMNS: usize = 5;

/// Render the Miller columns (tree) view.
fn render_tree_content(f: &mut Frame, app: &App, area: Rect) {
    if app.columns.is_empty() {
        return;
    }

    // Determine whether the rightmost slot is a file preview or a directory column.
    // The preview pane occupies one slot regardless.
    let has_preview_pane = app.file_preview.is_some()
        || app.columns.len() > app.active_column + 1; // dir preview column exists
    let need_extra_slot = app.file_preview.is_some(); // file preview needs its own slot

    // Total pane count: directory columns + (1 extra if file preview occupies a separate slot)
    let total_panes = app.columns.len() + if need_extra_slot { 1 } else { 0 };

    let available_width = area.width;
    let num_visible = total_panes
        .min(MAX_VISIBLE_COLUMNS)
        .min((available_width / MIN_COLUMN_WIDTH) as usize)
        .max(1);

    // Ensure the active column + its preview are visible
    let slots_after_active = if has_preview_pane { 2 } else { 1 };
    let start_idx = if app.active_column + slots_after_active > num_visible {
        (app.active_column + slots_after_active).saturating_sub(num_visible)
            .min(total_panes.saturating_sub(num_visible))
    } else {
        0
    };
    let end_idx = (start_idx + num_visible).min(total_panes);
    let actual_visible = end_idx - start_idx;

    // Create horizontal layout with equal widths
    let constraints: Vec<Constraint> = (0..actual_visible)
        .map(|_| Constraint::Ratio(1, actual_visible as u32))
        .collect();

    let col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

    for slot in 0..actual_visible {
        let global_idx = start_idx + slot;

        // Is this slot the file-preview pane?
        let is_file_preview_slot = need_extra_slot && global_idx == app.columns.len();

        if is_file_preview_slot {
            render_file_preview_pane(f, app, col_chunks[slot]);
            continue;
        }

        // Otherwise render a directory column
        if global_idx >= app.columns.len() {
            continue;
        }
        let col = &app.columns[global_idx];
        let is_active = global_idx == app.active_column;
        let is_dir_preview = global_idx == app.active_column + 1;

        let border_style = if is_active {
            Style::default().fg(Color::Blue)
        } else if is_dir_preview {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let col_inner_width = col_chunks[slot].width.saturating_sub(2) as usize;
        let highlight_width = 2;
        let content_width = col_inner_width.saturating_sub(highlight_width);

        let comparing = app.compare.is_some();
        struct TFmt {
            name: String,
            name_style: Style,
            size: String,
            delta: String,
            delta_style: Style,
            count: String,
            ts: String,
            uid: String,
            gid: String,
            mode_s: String,
        }
        let formatted: Vec<TFmt> = col.entries.iter().map(|entry| {
            let prefix = if entry.is_dir { "▸ " } else { "  " };
            let marker = if comparing { entry.change_marker() } else { ' ' };
            let name = if comparing {
                format!("{}{}{}", marker, prefix, entry.name)
            } else {
                format!("{}{}", prefix, entry.name)
            };
            let name_style = marker_style(marker);
            let delta = if comparing { format_size_delta(entry) } else { String::new() };
            let delta_style = delta_style(entry.size_delta());
            let size = format_bytes(entry.total_size as u64);
            let count = format_file_count(entry.file_count);
            let ts = match app.timestamp_col {
                TimestampCol::Atime => app.format_atime(entry.latest_atime),
                TimestampCol::Mtime => app.format_atime(entry.latest_mtime),
                TimestampCol::Ctime => app.format_atime(entry.latest_ctime),
            };
            let uid = if app.visible_extras.uid  { format_uid(entry.uid, entry.is_dir) }  else { String::new() };
            let gid = if app.visible_extras.gid  { format_gid(entry.gid, entry.is_dir) }  else { String::new() };
            let mode_s = if app.visible_extras.mode { format_mode(entry.mode, entry.is_dir) } else { String::new() };
            TFmt { name, name_style, size, delta, delta_style, count, ts, uid, gid, mode_s }
        }).collect();

        let size_w  = formatted.iter().map(|f| f.size.len()).max().unwrap_or(0).max(6);
        let delta_w = if comparing { formatted.iter().map(|f| f.delta.len()).max().unwrap_or(0).max(6) } else { 0 };
        // Columns are narrow: when comparing, Δsize takes the place of the file count
        let count_w = if comparing { 0 } else { formatted.iter().map(|f| f.count.len()).max().unwrap_or(0).max(6) };
        let ts_w    = formatted.iter().map(|f| f.ts.len()).max().unwrap_or(0).max(6);
        let uid_w   = if app.visible_extras.uid  { formatted.iter().map(|f| f.uid.len()).max().unwrap_or(0).max("user".len()) } else { 0 };
        let gid_w   = if app.visible_extras.gid  { formatted.iter().map(|f| f.gid.len()).max().unwrap_or(0).max("group".len()) } else { 0 };
        let mode_w  = if app.visible_extras.mode { formatted.iter().map(|f| f.mode_s.len()).max().unwrap_or(0).max(5) } else { 0 };
        let extra_w = [uid_w, gid_w, mode_w, delta_w].iter().filter(|&&w| w > 0).map(|&w| w + 2).sum::<usize>();
        let stat_cols = size_w + count_w + ts_w + extra_w + if comparing { 4 } else { 6 };
        let name_max = content_width.saturating_sub(stat_cols);

        let items: Vec<ListItem> = formatted.iter().map(|f| {
            let name_display = if f.name.len() > name_max && name_max > 1 {
                format!("{}…", &f.name[..name_max.saturating_sub(1)])
            } else if name_max == 0 {
                String::new()
            } else {
                f.name.clone()
            };

            let mut spans = vec![
                Span::styled(format!("{:<name_w$}", name_display, name_w = name_max), f.name_style),
                Span::raw(format!("  {:>size_w$}", f.size)),
            ];
            if comparing {
                spans.push(Span::styled(format!("  {:>delta_w$}", f.delta), f.delta_style));
            }
            let mut rest = if comparing {
                format!("  {:>ts_w$}", f.ts)
            } else {
                format!("  {:>count_w$}  {:>ts_w$}", f.count, f.ts)
            };
            if app.visible_extras.uid  { rest += &format!("  {:>uid_w$}",  f.uid,    uid_w  = uid_w);  }
            if app.visible_extras.gid  { rest += &format!("  {:>gid_w$}",  f.gid,    gid_w  = gid_w);  }
            if app.visible_extras.mode { rest += &format!("  {:>mode_w$}", f.mode_s, mode_w = mode_w); }
            spans.push(Span::raw(rest));

            ListItem::new(Line::from(spans))
        }).collect();

        let title_style = if is_active {
            Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        // Build header string using same widths as data rows
        let mut col_header = format!("{:<name_w$}  {:>size_w$}", "name", "size", name_w = name_max);
        if comparing { col_header += &format!("  {:>delta_w$}", "Δsize"); }
        if !comparing { col_header += &format!("  {:>count_w$}", "files"); }
        col_header += &format!("  {:>ts_w$}", app.timestamp_col.label());
        if app.visible_extras.uid  { col_header += &format!("  {:>uid_w$}",  "user",  uid_w  = uid_w);  }
        if app.visible_extras.gid  { col_header += &format!("  {:>gid_w$}",  "group", gid_w  = gid_w);  }
        if app.visible_extras.mode { col_header += &format!("  {:>mode_w$}", "mode",  mode_w = mode_w); }

        // Render block separately so we can split the inner area
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(Span::styled(format!(" {} ", col.title), title_style));
        let inner = block.inner(col_chunks[slot]);
        f.render_widget(block, col_chunks[slot]);

        let col_inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(inner);

        f.render_widget(
            Paragraph::new(col_header)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            col_inner_chunks[0],
        );

        let list = List::new(items)
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        f.render_stateful_widget(list, col_inner_chunks[1], &mut col.list_state.clone());
    }
}

/// Render the file preview pane (rightmost slot when a file is selected).
fn render_file_preview_pane(f: &mut Frame, app: &App, area: Rect) {
    // Clear stale content from previous preview before rendering new content.
    // Without this, rows below the last text line can retain old characters
    // because Paragraph only writes cells for its actual lines.
    f.render_widget(Clear, area);

    let Some(ref preview) = app.file_preview else {
        // Empty placeholder pane
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(" Preview ", Style::default().fg(Color::DarkGray)));
        f.render_widget(block, area);
        return;
    };

    let border_style = if app.preview_focused {
        Style::default().fg(Color::Blue)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let title_style = if app.preview_focused {
        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };

    let file_name = preview.path.rsplit('/').next().unwrap_or(&preview.path);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(format!(" {} ", file_name), title_style));

    let inner_height = area.height.saturating_sub(2) as usize; // borders top+bottom

    // Build content lines: header info + optional text content
    let mut text_lines: Vec<Line> = Vec::new();

    // File metadata header
    text_lines.push(Line::from(Span::styled(
        format!("  Type: {}", preview.type_description),
        Style::default().fg(Color::Yellow),
    )));
    text_lines.push(Line::from(Span::styled(
        format!("  Size: {}", format_bytes(preview.size as u64)),
        Style::default().fg(Color::Green),
    )));
    if app.compare.is_some() {
        let was = match preview.size_old {
            Some(old) => format!("{} ({})", format_bytes(old as u64), format_bytes_signed(preview.size - old)),
            None => "(new file)".to_string(),
        };
        text_lines.push(Line::from(Span::styled(
            format!("  Was:  {}", was),
            Style::default().fg(Color::Magenta),
        )));
    }
    text_lines.push(Line::from(Span::styled(
        format!("  Atime: {}", app.format_atime(preview.atime)),
        Style::default().fg(Color::Cyan),
    )));
    text_lines.push(Line::from(""));

    if preview.is_text && !preview.lines.is_empty() {
        // Translate global scroll_offset to deque index
        let content_height = inner_height.saturating_sub(text_lines.len());
        let global_start = preview.scroll_offset.max(preview.first_line_number);
        let deque_start = global_start - preview.first_line_number;
        let deque_end = (deque_start + content_height).min(preview.lines.len());

        for i in deque_start..deque_end {
            text_lines.push(Line::from(Span::raw(format!("  {}", &preview.lines[i]))));
        }

        // Scroll indicator with global position and EOF status
        let eof_indicator = if preview.eof_reached { "EOF" } else { "..." };
        let total = preview.total_lines_loaded;
        if total > content_height {
            let max_scroll = total.saturating_sub(content_height);
            let pct = if max_scroll == 0 { 100 } else {
                (global_start * 100) / max_scroll
            };
            text_lines.push(Line::from(Span::styled(
                format!("  ── {}% ({}/{} lines) ({}) ──", pct.min(100), global_start + 1, total, eof_indicator),
                Style::default().fg(Color::DarkGray),
            )));
        }
    } else if !preview.is_text {
        text_lines.push(Line::from(Span::styled(
            "  (binary file — no preview)",
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
        )));
    }

    let paragraph = Paragraph::new(text_lines).block(block);
    f.render_widget(paragraph, area);
}

/// Render the shared status bar.
fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status_text = if app.input_mode == InputMode::SortSelect {
        // Build sort selector display with short names
        let options: Vec<String> = SortMode::ALL
            .iter()
            .filter(|m| app.compare.is_some() || !m.is_compare_only())
            .map(|m| {
                if *m == app.pending_sort {
                    format!("▶ {} ◀", m)
                } else {
                    format!("  {}  ", m)
                }
            })
            .collect();
        format!(" Sort: {}  (s/→:next  ←:prev  Enter:apply  Esc:cancel)", options.join(""))
    } else if app.input_mode != InputMode::Normal {
        format!(" {}{}", app.input_mode.prompt(), app.input_buffer)
    } else if app.preview_focused {
        // Pager mode status
        if let Some(ref preview) = app.file_preview {
            let file_name = preview.path.rsplit('/').next().unwrap_or(&preview.path);
            format!(
                " ▶ {} │ {} │ jk↑↓:scroll d/u:page g/G:top/bottom Esc/←/q/␣:back",
                file_name,
                preview.type_description
            )
        } else {
            " Esc:back".to_string()
        }
    } else {
        // Build mode-specific status
        let mode_indicator = match app.view_mode {
            ViewMode::List => "list",
            ViewMode::Tree => "tree",
        };

        // In tree mode, show breadcrumb and selected entry info
        let context_info = if app.view_mode == ViewMode::Tree && !app.columns.is_empty() {
            // Build breadcrumb from column titles
            let breadcrumb: Vec<&str> = app.columns.iter()
                .take(app.active_column + 1)
                .map(|c| c.title.as_str())
                .collect();
            let path_str = breadcrumb.join(" > ");

            // Selected entry details
            let col = &app.columns[app.active_column];
            if let Some(idx) = col.list_state.selected() {
                if idx < col.entries.len() {
                    let entry = &col.entries[idx];
                    let ts_str = match app.timestamp_col {
                        TimestampCol::Atime => app.format_atime(entry.latest_atime),
                        TimestampCol::Mtime => app.format_atime(entry.latest_mtime),
                        TimestampCol::Ctime => app.format_atime(entry.latest_ctime),
                    };
                    let delta_str = if app.compare.is_some() {
                        format!(" ({})", format_bytes_signed(entry.size_delta()))
                    } else {
                        String::new()
                    };
                    format!(
                        "{} │ {}{} │ {} │ {}",
                        path_str,
                        format_bytes(entry.total_size as u64),
                        delta_str,
                        format_file_count(entry.file_count),
                        ts_str
                    )
                } else {
                    path_str
                }
            } else {
                path_str
            }
        } else {
            app.status.clone()
        };

        let filter_display = app.filters.format_display();
        let filter_str = if filter_display.is_empty() {
            String::new()
        } else {
            format!(" {}", filter_display)
        };

        // Build extras indicator
        let extras: Vec<&str> = [
            if app.visible_extras.uid  { Some("user")  } else { None },
            if app.visible_extras.gid  { Some("group") } else { None },
            if app.visible_extras.mode { Some("mode")  } else { None },
        ].iter().filter_map(|x| *x).collect();
        let extras_str = if extras.is_empty() {
            String::new()
        } else {
            format!(" [{}]", extras.join(","))
        };

        let compare_str = match app.compare {
            Some(ref cmp) => format!(
                " │ vs {} show:{}",
                cmp.old.index.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                app.status_filter.label(),
            ),
            None => String::new(),
        };
        let compare_keys = if app.compare.is_some() { " d:changes" } else { "" };

        format!(
            " {}{}{} │ sort:{} {} {} {} │ q:quit jk:nav ←→:cd /:pat s:sort m:view t:{}{} ?:help c:clear",
            context_info,
            filter_str,
            compare_str,
            app.sort_mode,
            mode_indicator,
            app.timestamp_col.label(),
            extras_str,
            app.timestamp_col.label(),
            compare_keys,
        )
    };

    let status_style = if app.input_mode == InputMode::SortSelect {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else if app.input_mode != InputMode::Normal {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    };

    let status = Paragraph::new(status_text).style(status_style);
    f.render_widget(status, area);
}
