use std::path::Path;

use crate::{
  Error, Result,
  format::{DbFile, DbKind},
};

/// A file-to-package mapping from a packages database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
  /// Relative path within a Nix store output, e.g. `"/bin/hello"`.
  pub path: String,
  /// Package names that ship this file.
  pub packages: Vec<String>,
}

/// Handle to an open spam packages database.
///
/// The file is fully loaded into memory on construction.
#[derive(Debug)]
pub struct PackagesDb {
  db: DbFile,
}

impl PackagesDb {
  pub(crate) fn from_file(db: DbFile) -> Self {
    Self { db }
  }

  /// Open the packages database at `path`.
  ///
  /// Returns [`Error::InvalidDatabase`] if the file is not a packages database.
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    let db = DbFile::open(path)?;
    if db.kind != DbKind::Packages {
      return Err(Error::InvalidDatabase(
        "expected a packages database (kind = packages)".into(),
      ));
    }
    Ok(Self { db })
  }

  /// Return all records whose path contains `query` as a substring.
  ///
  /// Decompresses only the bucket for `query[0]`. An empty query reads bucket 0.
  pub fn query(&self, query: &str) -> Result<Vec<FileRecord>> {
    let bucket = DbFile::query_bucket(query);
    let lines = self.db.bucket_lines(bucket)?;

    let mut records = Vec::new();
    for line in &lines {
      if let Some(tab) = line.find('\t') {
        let path = &line[..tab];
        if path.contains(query) {
          let packages = line[tab + 1..]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
          records.push(FileRecord {
            path: path.to_owned(),
            packages,
          });
        }
      }
    }
    Ok(records)
  }
}
