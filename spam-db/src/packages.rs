use std::path::Path;

use crate::{
    Error, Result, indexv1,
    format::{DbFile, Scope, Section, SectionEncoding},
};

/// The type of a file entry in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileKind {
    /// A regular file.
    #[default]
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

/// A file-to-package mapping from the `pkg` scope of a database.
///
/// Sections written from a nixpkgs index carry full metadata; sections built
/// from a local manifest only populate `path` and `packages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Relative path within a Nix store output, e.g. `"/bin/hello"`.
    pub path: String,
    /// Package names that ship this file.
    pub packages: Vec<String>,
    /// File size in bytes (0 for directories and symlinks, and for manifest records).
    pub size: u64,
    /// File type.
    pub kind: FileKind,
    /// Whether the file has the executable bit set (meaningful for [`FileKind::Regular`] only).
    pub executable: bool,
    /// Symlink target; empty unless `kind == FileKind::Symlink`.
    pub target: String,
}

/// Handle to the `pkg` scope of an open database.
#[derive(Debug)]
pub struct PackagesDb {
    db: DbFile,
    section: Section,
}

impl PackagesDb {
    /// Open the database at `path` and select its `pkg` scope.
    ///
    /// Returns [`Error::InvalidDatabase`] if the database has no `pkg` section.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = DbFile::open(path)?;
        let section = db
            .section(Scope::Pkg)
            .ok_or_else(|| Error::InvalidDatabase("database has no pkg section".into()))?;
        Ok(Self { db, section })
    }

    /// Return all records whose path contains `query` as a substring.
    pub fn query(&self, query: &str) -> Result<Vec<FileRecord>> {
        match self.section.encoding {
            SectionEncoding::Buckets => self.query_bucketed(query),
            SectionEncoding::IndexV1 => indexv1::query(&self.db, self.section, query),
        }
    }

    fn query_bucketed(&self, query: &str) -> Result<Vec<FileRecord>> {
        let bucket = DbFile::query_bucket(query);
        let lines = self.db.bucket_lines(self.section, bucket)?;

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
                FileRecord {
                    path: path.to_owned(),
                    packages: split_packages(parts[5]),
                    size: parts[2].parse().unwrap_or(0),
                    kind,
                    executable: parts[3] == "1",
                    target: parts[4].to_owned(),
                }
            } else if parts.len() >= 2 {
                // Manifest format: path\tpkg1,pkg2,...
                FileRecord {
                    path: path.to_owned(),
                    packages: split_packages(parts[1]),
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
}

fn split_packages(field: &str) -> Vec<String> {
    field
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
