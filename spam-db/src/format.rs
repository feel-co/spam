/// The magic header of a multi-scope database.
pub(crate) const DB_MAGIC_V2: &str = "# spam-db-v2";

/// The magic header prefix of a single-kind database from an earlier release.
pub(crate) const DB_MAGIC_V1: &str = "# spam-db-v1";

/// Number of index buckets in a bucketed section.
pub(crate) const INDEX_BUCKETS: usize = 256;

/// Bytes per index entry: 8-byte little-endian offset, 8-byte little-endian length.
pub(crate) const INDEX_ENTRY_SIZE: usize = 16;

/// Total bucket index size in bytes.
pub(crate) const INDEX_SIZE: usize = INDEX_BUCKETS * INDEX_ENTRY_SIZE;

/// Bytes per section table entry.
const SECTION_ENTRY_SIZE: usize = 20;

/// Upper bound on the section count, to reject a corrupt header before allocating.
const MAX_SECTIONS: usize = 64;

use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::{Error, Result};

/// A search scope. A database holds at most one section per scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Package file paths.
    Pkg,
    /// NixOS module options.
    Opt,
    /// Documented Nix library functions.
    Lib,
}

impl Scope {
    fn from_code(code: u16) -> Result<Self> {
        match code {
            0 => Ok(Scope::Pkg),
            1 => Ok(Scope::Opt),
            2 => Ok(Scope::Lib),
            other => Err(Error::InvalidDatabase(format!("unknown scope code {other}"))),
        }
    }

    /// The scope's name as spelled on the `spam` command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Pkg => "pkg",
            Scope::Opt => "opt",
            Scope::Lib => "lib",
        }
    }
}

/// How a section's records are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionEncoding {
    /// 256 zstd blobs, bucketed by every distinct byte of the record key.
    Buckets,
    /// Blocked, prefix-delta encoded records with a trigram index.
    IndexV1,
    /// Column-major row groups with a trigram index.
    IndexV2,
}

impl SectionEncoding {
    fn from_code(code: u16) -> Result<Self> {
        match code {
            1 => Ok(SectionEncoding::Buckets),
            2 => Ok(SectionEncoding::IndexV1),
            3 => Ok(SectionEncoding::IndexV2),
            other => Err(Error::InvalidDatabase(format!(
                "unknown section encoding {other}"
            ))),
        }
    }
}

/// One scope's slice of a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// The scope this section holds.
    pub scope: Scope,
    /// How its records are encoded.
    pub encoding: SectionEncoding,
    /// Offset from the first payload byte.
    pub(crate) offset: u64,
    /// Section length in bytes.
    pub(crate) length: u64,
}

/// An open spam database file.
///
/// Only the header and section table are read on open. Section payloads are
/// read and decompressed on demand, so a scoped query touches only the bytes
/// belonging to that scope.
///
/// Layout:
/// ```text
/// "# spam-db-v2\n"
/// [u32le section count]
/// [count x 20-byte section entries: (scope: u16le, encoding: u16le, offset: u64le, length: u64le)]
/// [section payloads, in table order]
/// ```
#[derive(Debug)]
pub(crate) struct DbFile {
    path: PathBuf,
    payload_start: u64,
    sections: Vec<Section>,
}

impl DbFile {
    /// Load a spam database from `path`.
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let mut file = std::fs::File::open(&path)?;
        let file_len = file.metadata()?.len();

        let mut header_bytes = Vec::new();
        {
            let mut reader = BufReader::new(&mut file);
            if reader.read_until(b'\n', &mut header_bytes)? == 0
                || header_bytes.last() != Some(&b'\n')
            {
                return Err(Error::InvalidDatabase("missing header newline".into()));
            }
            header_bytes.pop();
        }

        let header = std::str::from_utf8(&header_bytes)
            .map_err(|_| Error::InvalidDatabase("non-UTF-8 header".into()))?;
        let header_len = u64::try_from(header_bytes.len() + 1)
            .map_err(|_| Error::InvalidDatabase("database header is too large".into()))?;

        if let Some(rest) = header.strip_prefix(DB_MAGIC_V1) {
            let kind = rest.strip_prefix('\t').unwrap_or(rest);
            let length = file_len
                .checked_sub(header_len)
                .ok_or_else(|| Error::InvalidDatabase("file is too short".into()))?;
            return Ok(Self {
                path,
                payload_start: header_len,
                sections: vec![legacy_section(kind, length)?],
            });
        }

        if header != DB_MAGIC_V2 {
            return Err(Error::InvalidDatabase("missing spam-db magic header".into()));
        }

        file.seek(SeekFrom::Start(header_len))?;
        let mut count_bytes = [0u8; 4];
        file.read_exact(&mut count_bytes)?;
        let count = u32::from_le_bytes(count_bytes) as usize;
        if count > MAX_SECTIONS {
            return Err(Error::InvalidDatabase(format!(
                "implausible section count {count}"
            )));
        }

        let mut table = vec![0u8; count * SECTION_ENTRY_SIZE];
        file.read_exact(&mut table)?;

        let payload_start = header_len + 4 + table.len() as u64;
        let payload_len = file_len
            .checked_sub(payload_start)
            .ok_or_else(|| Error::InvalidDatabase("truncated section table".into()))?;

        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let base = i * SECTION_ENTRY_SIZE;
            let section = Section {
                scope: Scope::from_code(read_u16le(&table, base))?,
                encoding: SectionEncoding::from_code(read_u16le(&table, base + 2))?,
                offset: read_u64le(&table, base + 4),
                length: read_u64le(&table, base + 12),
            };
            if sections.iter().any(|s: &Section| s.scope == section.scope) {
                return Err(Error::InvalidDatabase(format!(
                    "duplicate {} section",
                    section.scope.as_str()
                )));
            }
            let end = section
                .offset
                .checked_add(section.length)
                .ok_or_else(|| Error::InvalidDatabase("section length overflow".into()))?;
            if end > payload_len {
                return Err(Error::InvalidDatabase("section slice out of bounds".into()));
            }
            sections.push(section);
        }

        Ok(Self {
            path,
            payload_start,
            sections,
        })
    }

    /// The sections this database carries.
    pub(crate) fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The section for `scope`, if present.
    pub(crate) fn section(&self, scope: Scope) -> Option<Section> {
        self.sections.iter().copied().find(|s| s.scope == scope)
    }

    /// Absolute file offset of `section`.
    fn start(&self, section: Section) -> Result<u64> {
        self.payload_start
            .checked_add(section.offset)
            .ok_or_else(|| Error::InvalidDatabase("section offset overflow".into()))
    }

    /// Read `length` bytes at `offset` within `section`.
    pub(crate) fn read_at(&self, section: Section, offset: u64, length: u64) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::InvalidDatabase("section slice overflow".into()))?;
        if end > section.length {
            return Err(Error::InvalidDatabase("read past end of section".into()));
        }

        let length = usize::try_from(length).map_err(|_| {
            Error::InvalidDatabase("slice is too large for this platform".into())
        })?;
        if length == 0 {
            return Ok(Vec::new());
        }

        let start = self
            .start(section)?
            .checked_add(offset)
            .ok_or_else(|| Error::InvalidDatabase("section offset overflow".into()))?;

        let mut file = std::fs::File::open(&self.path)?;
        let mut buffer = vec![0u8; length];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    /// Decompress and return all non-empty lines in `bucket` of a bucketed section.
    pub(crate) fn bucket_lines(&self, section: Section, bucket: usize) -> Result<Vec<String>> {
        if section.encoding != SectionEncoding::Buckets {
            return Err(Error::InvalidDatabase(
                "section is not bucket-indexed".into(),
            ));
        }

        let index = self.read_at(section, 0, INDEX_SIZE as u64)?;
        let entry = bucket * INDEX_ENTRY_SIZE;
        let offset = read_u64le(&index, entry);
        let length = read_u64le(&index, entry + 8);
        if length == 0 {
            return Ok(Vec::new());
        }

        let data_start = INDEX_SIZE as u64 + offset;
        let compressed = self.read_at(section, data_start, length)?;
        let decompressed = zstd::decode_all(compressed.as_slice())
            .map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))?;
        let text = String::from_utf8(decompressed)
            .map_err(|_| Error::InvalidDatabase("non-UTF-8 database content".into()))?;

        Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    /// The bucket index for `query`: the first byte value, or 0 for empty input.
    pub(crate) fn query_bucket(query: &str) -> usize {
        query.bytes().next().map(|b| b as usize).unwrap_or(0)
    }
}

/// Map a `# spam-db-v1` kind onto the scope and encoding it implied.
fn legacy_section(kind: &str, length: u64) -> Result<Section> {
    let (scope, encoding) = match kind {
        "options" => (Scope::Opt, SectionEncoding::Buckets),
        "packages" => (Scope::Pkg, SectionEncoding::Buckets),
        "lib" => (Scope::Lib, SectionEncoding::Buckets),
        "index" => (Scope::Pkg, SectionEncoding::IndexV1),
        other => {
            return Err(Error::InvalidDatabase(format!(
                "unknown database kind: {other}"
            )));
        }
    };
    Ok(Section {
        scope,
        encoding,
        offset: 0,
        length,
    })
}

/// Read a little-endian `u16` from `data` at `offset`.
fn read_u16le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        data[offset..offset + 2]
            .try_into()
            .expect("slice length guaranteed by caller"),
    )
}

/// Read a little-endian `u64` from `data` at `offset`.
fn read_u64le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .expect("slice length guaranteed by caller"),
    )
}
