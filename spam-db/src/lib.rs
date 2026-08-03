//! Parser and query library for [spam](https://github.com/feel-co/spam) databases.
//!
//! spam indexes Nix package closures, `nixosOptionsDoc` output and documented
//! Nix library functions into compact compressed databases. Use this crate to
//! open those databases and run substring queries against them.
//!
//! ## Scopes
//!
//! A database holds up to three independent sections, one per scope:
//!
//! - [`Scope::Pkg`]: Nix store file paths, keyed by path. See [`PackagesDb`].
//! - [`Scope::Opt`]: NixOS module options, keyed by option name. See [`OptionsDb`].
//! - [`Scope::Lib`]: documented library functions, keyed by attribute name. See
//!   [`FunctionsDb`].
//!
//! ## File format
//!
//! ```text
//! "# spam-db-v2\n"
//! [u32le section count]
//! [count x 20-byte entries: (scope: u16le, encoding: u16le, offset: u64le, length: u64le)]
//! [section payloads, in table order]
//! ```
//!
//! Sections use one of two encodings. `Buckets` is 256 zstd blobs indexed by
//! every distinct byte of the record key. `IndexV1` is a blocked, prefix-delta
//! encoded record format with a trigram index, used for the package section of
//! a nixpkgs index.
//!
//! Single-kind `# spam-db-v1` databases from earlier releases are read as one
//! synthesised section.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use spam_db::SpamDb;
//!
//! let db = SpamDb::open("spam.db").unwrap();
//!
//! if let Some(pkg) = db.packages().unwrap() {
//!     for rec in pkg.query("/bin/").unwrap() {
//!         println!("{} -> {}", rec.path, rec.packages.join(", "));
//!     }
//! }
//!
//! if let Some(opt) = db.options().unwrap() {
//!     for rec in opt.query("services.nginx").unwrap() {
//!         println!("{}: {:?}", rec.name, rec.summary);
//!     }
//! }
//! ```
//!
//! A single scope can also be opened directly:
//!
//! ```rust,no_run
//! use spam_db::OptionsDb;
//!
//! let db = OptionsDb::open("options.db").unwrap();
//! let results = db.query("networking.firewall").unwrap();
//! ```

mod format;
mod indexv1;

pub mod error;
pub mod functions;
pub mod options;
pub mod packages;

pub use error::Error;
pub use format::{Scope, SectionEncoding};
pub use functions::{FunctionRecord, FunctionsDb};
pub use options::{OptionRecord, OptionsDb};
pub use packages::{FileKind, FileRecord, PackagesDb};

use std::path::Path;

/// Convenience alias for `Result<T, spam_db::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// An open spam database, from which each scope present can be queried.
#[derive(Debug)]
pub struct SpamDb {
    path: std::path::PathBuf,
    scopes: Vec<(Scope, SectionEncoding)>,
}

impl SpamDb {
    /// Open a spam database and read its section table.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let db = format::DbFile::open(&path)?;
        let scopes = db.sections().iter().map(|s| (s.scope, s.encoding)).collect();
        Ok(Self { path, scopes })
    }

    /// The scopes this database carries, with the encoding of each.
    pub fn scopes(&self) -> &[(Scope, SectionEncoding)] {
        &self.scopes
    }

    /// Whether this database carries `scope`.
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.iter().any(|(s, _)| *s == scope)
    }

    /// Open the `pkg` scope, or `None` if this database has no package section.
    pub fn packages(&self) -> Result<Option<PackagesDb>> {
        if !self.has(Scope::Pkg) {
            return Ok(None);
        }
        PackagesDb::open(&self.path).map(Some)
    }

    /// Open the `opt` scope, or `None` if this database has no option section.
    pub fn options(&self) -> Result<Option<OptionsDb>> {
        if !self.has(Scope::Opt) {
            return Ok(None);
        }
        OptionsDb::open(&self.path).map(Some)
    }

    /// Open the `lib` scope, or `None` if this database has no function section.
    pub fn functions(&self) -> Result<Option<FunctionsDb>> {
        if !self.has(Scope::Lib) {
            return Ok(None);
        }
        FunctionsDb::open(&self.path).map(Some)
    }
}
