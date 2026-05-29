/// The magic prefix that identifies all spam databases.
pub(crate) const DB_MAGIC: &str = "# spam-db-v1";

/// Number of index buckets.
pub(crate) const INDEX_BUCKETS: usize = 256;

/// Bytes per index entry: 4-byte little-endian offset, 4-byte little-endian length.
pub(crate) const INDEX_ENTRY_SIZE: usize = 8;

/// Total index size in bytes.
pub(crate) const INDEX_SIZE: usize = INDEX_BUCKETS * INDEX_ENTRY_SIZE;

use crate::{Error, Result};

/// Whether a spam database stores NixOS module options or package file paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
  /// Options database produced from `nixosOptionsDoc`.
  Options,
  /// Package-file database mapping file paths to package names.
  Packages,
}

/// The parsed contents of a spam database file.
///
/// The entire file is loaded into memory on construction. Bucket lookups
/// decompress only the relevant slice on demand.
///
/// Layout:
/// ```text
/// [header line]\n
/// [256 x 8-byte index entries]
/// [concatenated zstd-compressed bucket blobs]
/// ```
#[derive(Debug)]
pub(crate) struct DbFile {
  pub(crate) kind: DbKind,
  index: [u8; INDEX_SIZE],
  data: Vec<u8>,
}

impl DbFile {
  /// Load a spam database from `path`.
  pub(crate) fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
    let bytes = std::fs::read(path)?;

    let nl = bytes
      .iter()
      .position(|&b| b == b'\n')
      .ok_or_else(|| Error::InvalidDatabase("missing header newline".into()))?;

    let header = std::str::from_utf8(&bytes[..nl])
      .map_err(|_| Error::InvalidDatabase("non-UTF-8 header".into()))?;

    let kind = parse_kind(header)?;

    let index_start = nl + 1;
    let data_start = index_start + INDEX_SIZE;

    if bytes.len() < data_start {
      return Err(Error::InvalidDatabase(
        "file is too short to contain index".into(),
      ));
    }

    let mut index = [0u8; INDEX_SIZE];
    index.copy_from_slice(&bytes[index_start..index_start + INDEX_SIZE]);

    let data = bytes[data_start..].to_vec();

    Ok(Self { kind, index, data })
  }

  /// Decompress and return all non-empty lines in `bucket`.
  pub(crate) fn bucket_lines(&self, bucket: usize) -> Result<Vec<String>> {
    let entry = bucket * INDEX_ENTRY_SIZE;
    let offset = read_u32le(&self.index, entry) as usize;
    let length = read_u32le(&self.index, entry + 4) as usize;

    if length == 0 {
      return Ok(Vec::new());
    }

    let end = offset
      .checked_add(length)
      .filter(|&e| e <= self.data.len())
      .ok_or_else(|| {
        Error::InvalidDatabase("bucket slice out of bounds".into())
      })?;

    let compressed = &self.data[offset..end];
    let decompressed = zstd::decode_all(compressed)
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

/// Parse the DB kind from the header line, e.g. `"# spam-db-v1\toptions"`.
fn parse_kind(header: &str) -> Result<DbKind> {
  let rest = header.strip_prefix(DB_MAGIC).ok_or_else(|| {
    Error::InvalidDatabase("missing spam-db magic header".into())
  })?;

  let kind_str = rest.strip_prefix('\t').unwrap_or(rest);

  match kind_str {
    "options" => Ok(DbKind::Options),
    "packages" => Ok(DbKind::Packages),
    other => Err(Error::InvalidDatabase(format!(
      "unknown database kind: {other}"
    ))),
  }
}

/// Read a little-endian `u32` from `data` at `offset`.
fn read_u32le(data: &[u8], offset: usize) -> u32 {
  u32::from_le_bytes(
    data[offset..offset + 4]
      .try_into()
      .expect("slice length guaranteed by caller"),
  )
}
