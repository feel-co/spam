use std::fmt;

/// Errors that can occur when opening or querying a spam database.
#[derive(Debug)]
pub enum Error {
  /// An I/O error reading the database file.
  Io(std::io::Error),
  /// The file does not match the expected spam-db format.
  InvalidDatabase(String),
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Error::Io(e) => write!(f, "I/O error: {e}"),
      Error::InvalidDatabase(msg) => write!(f, "invalid database: {msg}"),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Error::Io(e) => Some(e),
      Error::InvalidDatabase(_) => None,
    }
  }
}

impl From<std::io::Error> for Error {
  fn from(e: std::io::Error) -> Self {
    Error::Io(e)
  }
}
