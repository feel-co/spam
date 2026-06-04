/// The magic prefix that identifies all spam databases.
pub(crate) const DB_MAGIC: &str = "# spam-db-v2";

/// Number of index buckets.
pub(crate) const INDEX_BUCKETS: usize = 256;

/// Bytes per index entry: 8-byte little-endian offset, 8-byte little-endian length.
pub(crate) const INDEX_ENTRY_SIZE: usize = 16;

/// Total index size in bytes.
pub(crate) const INDEX_SIZE: usize = INDEX_BUCKETS * INDEX_ENTRY_SIZE;

use std::{
  io::{Read, Seek, SeekFrom},
  path::{Path, PathBuf},
};

use crate::{Error, Result};

/// Whether a spam database stores NixOS module options or package file paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
  /// Options database produced from `nixosOptionsDoc`.
  Options,
  /// Package-file database built from a local manifest via `spam db build`.
  Packages,
  /// Autonomous package index produced by `spam index`.
  Index,
}

/// An open spam database file.
///
/// Only the fixed-size bucket index is loaded into memory. Bucket lookups read
/// and decompress the relevant payload slice on demand.
///
/// Layout:
/// ```text
/// [header line]\n
/// [256 x 16-byte index entries]
/// [concatenated zstd-compressed bucket blobs]
/// ```
#[derive(Debug)]
pub(crate) struct DbFile {
  pub(crate) kind: DbKind,
  index: [u8; INDEX_SIZE],
  path: PathBuf,
  data_start: u64,
}

impl DbFile {
  /// Load a spam database from `path`.
  pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref().to_owned();
    let mut file = std::fs::File::open(&path)?;

    let mut header_bytes = Vec::new();
    loop {
      let mut byte = [0u8; 1];
      if file.read(&mut byte)? == 0 {
        return Err(Error::InvalidDatabase("missing header newline".into()));
      }
      if byte[0] == b'\n' {
        break;
      }
      header_bytes.push(byte[0]);
    }

    let header = std::str::from_utf8(&header_bytes)
      .map_err(|_| Error::InvalidDatabase("non-UTF-8 header".into()))?;

    let kind = parse_kind(header)?;

    let data_start = u64::try_from(header_bytes.len() + 1 + INDEX_SIZE)
      .map_err(|_| Error::InvalidDatabase("database header is too large".into()))?;

    if file.metadata()?.len() < data_start {
      return Err(Error::InvalidDatabase(
        "file is too short to contain index".into(),
      ));
    }

    let mut index = [0u8; INDEX_SIZE];
    file.read_exact(&mut index)?;

    Ok(Self {
      kind,
      index,
      path,
      data_start,
    })
  }

  /// Decompress and return all non-empty lines in `bucket`.
  pub(crate) fn bucket_lines(&self, bucket: usize) -> Result<Vec<String>> {
    let entry = bucket * INDEX_ENTRY_SIZE;
    let offset = read_u64le(&self.index, entry).try_into().map_err(|_| {
      Error::InvalidDatabase("bucket offset is too large for this platform".into())
    })?;
    let length = read_u64le(&self.index, entry + 8).try_into().map_err(|_| {
      Error::InvalidDatabase("bucket length is too large for this platform".into())
    })?;

    if length == 0 {
      return Ok(Vec::new());
    }

    let start = self
      .data_start
      .checked_add(offset)
      .ok_or_else(|| Error::InvalidDatabase("bucket offset overflow".into()))?;
    let end = start
      .checked_add(length)
      .ok_or_else(|| Error::InvalidDatabase("bucket length overflow".into()))?;

    let mut file = std::fs::File::open(&self.path)?;
    let file_len = file.metadata()?.len();
    if end > file_len {
      return Err(Error::InvalidDatabase(
        "bucket slice out of bounds".into(),
      ));
    }

    let length_usize = length.try_into().map_err(|_| {
      Error::InvalidDatabase("bucket length is too large for this platform".into())
    })?;
    let mut compressed = vec![0u8; length_usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut compressed)?;

    let decompressed = zstd::decode_all(compressed.as_slice())
      .map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))?;

    let text = String::from_utf8(decompressed).map_err(|_| {
      Error::InvalidDatabase("non-UTF-8 database content".into())
    })?;

    Ok(
      text
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect(),
    )
  }

  /// The bucket index for `query`: the first byte value, or 0 for empty input.
  pub(crate) fn query_bucket(query: &str) -> usize {
    query.bytes().next().map(|b| b as usize).unwrap_or(0)
  }
}

/// Parse the DB kind from the header line, e.g. `"# spam-db-v2\toptions"`.
fn parse_kind(header: &str) -> Result<DbKind> {
  let rest = header.strip_prefix(DB_MAGIC).ok_or_else(|| {
    Error::InvalidDatabase("missing spam-db magic header".into())
  })?;

  let kind_str = rest.strip_prefix('\t').unwrap_or(rest);

  match kind_str {
    "options" => Ok(DbKind::Options),
    "packages" => Ok(DbKind::Packages),
    "index" => Ok(DbKind::Index),
    other => Err(Error::InvalidDatabase(format!(
      "unknown database kind: {other}"
    ))),
  }
}

/// Read a little-endian `u64` from `data` at `offset`.
fn read_u64le(data: &[u8], offset: usize) -> u64 {
  u64::from_le_bytes(
    data[offset..offset + 8]
      .try_into()
      .expect("slice length guaranteed by caller"),
  )
}
