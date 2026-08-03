use std::path::Path;

use crate::{
    Error, Result,
    format::{DbFile, Scope, Section},
};

/// A documented Nix library function from the `lib` scope of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRecord {
    /// Attribute name, e.g. `"lib.strings.concatStrings"`.
    pub name: String,
    /// One-line gloss taken from the doc comment, if it had one.
    pub summary: Option<String>,
    /// Type signature from the comment's `# Type` section, if it had one.
    pub type_signature: Option<String>,
    /// Source location as `file:line`.
    pub location: String,
    /// Whether the doc comment marks the function deprecated.
    pub deprecated: bool,
}

/// Handle to the `lib` scope of an open database.
#[derive(Debug)]
pub struct FunctionsDb {
    db: DbFile,
    section: Section,
}

impl FunctionsDb {
    /// Open the database at `path` and select its `lib` scope.
    ///
    /// Returns [`Error::InvalidDatabase`] if the database has no `lib` section.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = DbFile::open(path)?;
        let section = db
            .section(Scope::Lib)
            .ok_or_else(|| Error::InvalidDatabase("database has no lib section".into()))?;
        Ok(Self { db, section })
    }

    /// Return all records whose name contains `query` as a substring.
    ///
    /// Decompresses only the bucket for `query[0]`. An empty query reads bucket 0.
    pub fn query(&self, query: &str) -> Result<Vec<FunctionRecord>> {
        let bucket = DbFile::query_bucket(query);
        let lines = self.db.bucket_lines(self.section, bucket)?;

        let mut records = Vec::new();
        for line in &lines {
            // name\tsummary\ttype\tlocation\tdeprecated
            let parts: Vec<&str> = line.splitn(5, '\t').collect();
            if parts.len() < 5 || !parts[0].contains(query) {
                continue;
            }
            records.push(FunctionRecord {
                name: parts[0].to_owned(),
                summary: non_empty(parts[1]),
                type_signature: non_empty(parts[2]),
                location: parts[3].to_owned(),
                deprecated: parts[4] == "1",
            });
        }
        Ok(records)
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
