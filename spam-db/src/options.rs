use std::path::Path;

use crate::{
  Error, Result,
  format::{DbFile, Scope, Section},
};

/// A single NixOS module option from the `opt` scope of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionRecord {
  /// Fully-qualified option name, e.g. `"services.nginx.enable"`.
  pub name: String,
  /// Summary text (description, type, or default), if present in the database.
  pub summary: Option<String>,
}

/// Handle to the `opt` scope of an open database.
#[derive(Debug)]
pub struct OptionsDb {
  db: DbFile,
  section: Section,
}

impl OptionsDb {
  /// Open the database at `path` and select its `opt` scope.
  ///
  /// Returns [`Error::InvalidDatabase`] if the database has no `opt` section.
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    let db = DbFile::open(path)?;
    let section = db
      .section(Scope::Opt)
      .ok_or_else(|| Error::InvalidDatabase("database has no opt section".into()))?;
    Ok(Self { db, section })
  }

  /// Return all records whose name contains `query` as a substring.
  ///
  /// Decompresses only the bucket for `query[0]`. An empty query reads bucket 0.
  pub fn query(&self, query: &str) -> Result<Vec<OptionRecord>> {
    let bucket = DbFile::query_bucket(query);
    let lines = self.db.bucket_lines(self.section, bucket)?;

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
