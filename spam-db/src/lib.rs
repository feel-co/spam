//! Parser and query library for [spam](https://github.com/feel-co/spam) databases.
//!
//! spam indexes Nix package closures and `nixosOptionsDoc` output into
//! compressed, bucket-indexed databases. Use this crate to open those
//! databases and run substring queries against them.
//!
//! ## Database kinds
//!
//! - [`OptionsDb`]: NixOS module options, keyed by option name.
//! - [`PackagesDb`]: Nix store file paths, keyed by path.
//!
//! ## File format
//!
//! ```text
//! # spam-db-v1\t{options|packages}\n
//! [256 x 8-byte index entries: (offset: u32le, length: u32le)]
//! [concatenated zstd-compressed bucket blobs]
//! ```
//!
//! Each line is placed in every bucket for each unique byte in its search key.
//! Queries decompress only the bucket for `query[0]`.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use spam_db::SpamDb;
//!
//! match SpamDb::open("files.db").unwrap() {
//!     SpamDb::Options(db) => {
//!         for rec in db.query("services.nginx").unwrap() {
//!             println!("{}: {:?}", rec.name, rec.summary);
//!         }
//!     }
//!     SpamDb::Packages(db) => {
//!         for rec in db.query("/bin/").unwrap() {
//!             println!("{} -> {}", rec.path, rec.packages.join(", "));
//!         }
//!     }
//! }
//! ```
//!
//! ```rust,no_run
//! use spam_db::OptionsDb;
//!
//! let db = OptionsDb::open("options.db").unwrap();
//! let results = db.query("networking.firewall").unwrap();
//! ```

mod format;

pub mod error;
pub mod options;
pub mod packages;

pub use error::Error;
pub use format::DbKind;
pub use options::{OptionRecord, OptionsDb};
pub use packages::{FileRecord, PackagesDb};

/// Convenience alias for `Result<T, spam_db::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// A spam database of either kind, returned by [`SpamDb::open`] when the kind
/// is not known at compile time.
#[derive(Debug)]
pub enum SpamDb {
  /// An options database (NixOS module options).
  Options(OptionsDb),
  /// A packages database (file path to package name mappings).
  Packages(PackagesDb),
}

impl SpamDb {
  /// Open a spam database, detecting the kind from the file header.
  pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
    let db = format::DbFile::open(path)?;
    match db.kind {
      DbKind::Options => Ok(SpamDb::Options(OptionsDb::from_file(db))),
      DbKind::Packages => Ok(SpamDb::Packages(PackagesDb::from_file(db))),
    }
  }

  /// The kind of this database.
  pub fn kind(&self) -> DbKind {
    match self {
      SpamDb::Options(_) => DbKind::Options,
      SpamDb::Packages(_) => DbKind::Packages,
    }
  }
}
