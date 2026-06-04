use std::path::Path;

use crate::{
  Error, Result,
  format::{DbFile, DbKind},
};

/// A single NixOS module option from an options database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionRecord {
  /// Fully-qualified option name, e.g. `"services.nginx.enable"`.
  pub name: String,
  /// Summary text (description, type, or default), if present in the database.
  pub summary: Option<String>,
}

/// Handle to an open spam options database.
///
/// Only the fixed-size bucket index is loaded into memory on construction.
#[derive(Debug)]
pub struct OptionsDb {
  db: DbFile,
}

impl OptionsDb {
  pub(crate) fn from_file(db: DbFile) -> Self {
    Self { db }
  }

  /// Open the options database at `path`.
  ///
  /// Returns [`Error::InvalidDatabase`] if the file is not an options database.
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    let db = DbFile::open(path)?;
    if db.kind != DbKind::Options {
      return Err(Error::InvalidDatabase(
        "expected an options database (kind = options)".into(),
      ));
    }
    Ok(Self { db })
  }

  /// Return all records whose name contains `query` as a substring.
  ///
  /// Decompresses only the bucket for `query[0]`. An empty query reads bucket 0.
  pub fn query(&self, query: &str) -> Result<Vec<OptionRecord>> {
    let bucket = DbFile::query_bucket(query);
    let lines = self.db.bucket_lines(bucket)?;

    let mut records = Vec::new();
    for line in &lines {
      let (name, summary) = split_tab(line);
      if name.contains(query) {
        records.push(OptionRecord {
          name: name.to_owned(),
          summary: summary.filter(|s| !s.is_empty()).map(str::to_owned),
        });
      }
    }
    Ok(records)
  }
}

/// Split a database line on the first tab, returning `(key, Some(value))` or
/// `(whole_line, None)` when no tab is present.
fn split_tab(line: &str) -> (&str, Option<&str>) {
  match line.find('\t') {
    Some(tab) => (&line[..tab], Some(&line[tab + 1..])),
    None => (line, None),
  }
}
