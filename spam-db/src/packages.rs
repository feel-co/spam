use std::path::Path;

use crate::{
    Error, Result,
    format::{DbFile, DbKind},
};

/// The type of a file entry in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

impl Default for FileKind {
    fn default() -> Self {
        FileKind::Regular
    }
}

/// A file-to-package mapping from a packages database or autonomous index.
///
/// Extended databases (produced by `spam index`) include full metadata;
/// legacy databases (from `spam db build`) only populate `path` and `packages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Relative path within a Nix store output, e.g. `"/bin/hello"`.
    pub path: String,
    /// Package names that ship this file.
    pub packages: Vec<String>,
    /// File size in bytes (0 for directories and symlinks, and for legacy records).
    pub size: u64,
    /// File type.
    pub kind: FileKind,
    /// Whether the file has the executable bit set (meaningful for [`FileKind::Regular`] only).
    pub executable: bool,
    /// Symlink target; empty unless `kind == FileKind::Symlink`.
    pub target: String,
}

/// Handle to an open spam packages database or autonomous index.
///
/// Only the fixed-size bucket index is loaded into memory on construction.
#[derive(Debug)]
pub struct PackagesDb {
    db: DbFile,
}

impl PackagesDb {
    pub(crate) fn from_file(db: DbFile) -> Self {
        Self { db }
    }

    /// Open the packages database or autonomous index at `path`.
    ///
    /// Returns [`Error::InvalidDatabase`] if the file is not queryable by `spam pkg`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = DbFile::open(path)?;
        if db.kind != DbKind::Packages && db.kind != DbKind::Index {
            return Err(Error::InvalidDatabase(
                "expected a packages or index database".into(),
            ));
        }
        Ok(Self { db })
    }

    /// Return all records whose path contains `query` as a substring.
    pub fn query(&self, query: &str) -> Result<Vec<FileRecord>> {
        match self.db.kind {
            DbKind::Packages => self.query_bucketed(query),
            DbKind::Index => self.query_stream(query),
            DbKind::Options => Err(Error::InvalidDatabase(
                "expected a packages or index database".into(),
            )),
        }
    }

    fn query_bucketed(&self, query: &str) -> Result<Vec<FileRecord>> {
        let bucket = DbFile::query_bucket(query);
        let lines = self.db.bucket_lines(bucket)?;

        let mut records = Vec::new();
        for line in &lines {
            let parts: Vec<&str> = line.splitn(7, '\t').collect();
            if parts.is_empty() {
                continue;
            }
            let path = parts[0];
            if !path.contains(query) {
                continue;
            }

            let record = if parts.len() >= 6 {
                // Extended format: path\tkind\tsize\texec\ttarget\tpkg1,pkg2,...
                let kind = match parts[1] {
                    "d" => FileKind::Directory,
                    "s" => FileKind::Symlink,
                    _ => FileKind::Regular,
                };
                let size: u64 = parts[2].parse().unwrap_or(0);
                let executable = parts[3] == "1";
                let target = parts[4].to_owned();
                let packages = parts[5]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                FileRecord {
                    path: path.to_owned(),
                    packages,
                    size,
                    kind,
                    executable,
                    target,
                }
            } else if parts.len() >= 2 {
                // Legacy format: path\tpkg1,pkg2,...
                let packages = parts[1]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                FileRecord {
                    path: path.to_owned(),
                    packages,
                    size: 0,
                    kind: FileKind::Regular,
                    executable: false,
                    target: String::new(),
                }
            } else {
                continue;
            };

            records.push(record);
        }
        Ok(records)
    }

    fn query_stream(&self, query: &str) -> Result<Vec<FileRecord>> {
        let lines = self.db.stream_lines()?;

        let mut records = Vec::new();
        let mut package = String::new();
        let mut previous_path = String::new();
        for line in &lines {
            if let Some(package_name) = line.strip_prefix("P\t") {
                package = package_name.to_owned();
                previous_path.clear();
                continue;
            }

            let Some(record) = parse_stream_record(line, &package, &mut previous_path) else {
                continue;
            };
            if record.path.contains(query) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

fn parse_stream_record(
    line: &str,
    package: &str,
    previous_path: &mut String,
) -> Option<FileRecord> {
    let parts: Vec<&str> = line.splitn(7, '\t').collect();
    if parts.len() < 7 || parts[0] != "F" {
        return None;
    }

    let shared = parts[5].parse::<usize>().ok()?;
    if shared > previous_path.len() {
        return None;
    }
    let path = format!("{}{}", &previous_path[..shared], parts[6]);
    previous_path.clear();
    previous_path.push_str(&path);

    let kind = match parts[1] {
        "d" => FileKind::Directory,
        "s" => FileKind::Symlink,
        _ => FileKind::Regular,
    };

    Some(FileRecord {
        path,
        packages: vec![package.to_owned()],
        size: parts[2].parse().unwrap_or(0),
        kind,
        executable: parts[3] == "1",
        target: parts[4].to_owned(),
    })
}
