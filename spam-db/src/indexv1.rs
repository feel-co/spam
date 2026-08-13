//! Reader for the `index-v1` section encoding.
//!
//! Records are prefix-delta encoded into zstd-compressed blocks of roughly
//! 128 KiB. A trigram index maps each three-byte sequence to the blocks that
//! contain it, so a substring query only decompresses blocks that can possibly
//! match. Trigrams appearing in too many blocks are marked skipped and carry no
//! postings, since intersecting them would cost more than it saves.

use std::collections::HashMap;

use crate::{
    Error, Result,
    format::{DbFile, Section},
    packages::{FileKind, FileRecord},
};

/// Bytes in the fixed header preceding the section table.
const FIXED_HEADER_SIZE: u64 = 28;

/// Bytes per section table entry.
const SECTION_ENTRY_SIZE: u64 = 20;

/// Bytes per block table entry.
const BLOCK_ENTRY_SIZE: usize = 28;

/// Bytes per trigram table entry.
const TRIGRAM_ENTRY_SIZE: usize = 20;

const SECTION_PACKAGES: u16 = 1;
const SECTION_BLOCK_TABLE: u16 = 2;
const SECTION_BLOCKS: u16 = 3;
const SECTION_TRIGRAMS: u16 = 4;
const SECTION_POSTINGS: u16 = 5;

/// A trigram present in too many blocks to be worth intersecting.
const TRIGRAM_SKIPPED: u8 = 1;

#[derive(Debug, Clone, Copy)]
struct SubSection {
    kind: u16,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone, Copy)]
struct Block {
    first_record_id: u64,
    record_count: u32,
    compressed_offset: u64,
    compressed_length: u32,
    uncompressed_length: u32,
}

#[derive(Debug, Clone, Copy)]
struct Trigram {
    flags: u8,
    doc_freq: u32,
    postings_offset: u64,
    postings_length: u32,
}

/// Return every record whose path contains `query`.
pub(crate) fn query(db: &DbFile, section: Section, query: &str) -> Result<Vec<FileRecord>> {
    let fixed = db.read_at(section, 0, FIXED_HEADER_SIZE)?;
    let record_count = read_u64le(&fixed, 0)?;
    let package_count = read_u32le(&fixed, 8)? as usize;
    let block_count = read_u32le(&fixed, 12)? as usize;
    let trigram_count = read_u32le(&fixed, 16)? as usize;
    let sub_count = read_u32le(&fixed, 24)? as u64;

    let table = db.read_at(
        section,
        FIXED_HEADER_SIZE,
        sub_count
            .checked_mul(SECTION_ENTRY_SIZE)
            .ok_or_else(|| invalid("section table is too large"))?,
    )?;

    let mut subs = Vec::with_capacity(sub_count as usize);
    for i in 0..sub_count as usize {
        let base = i * SECTION_ENTRY_SIZE as usize;
        subs.push(SubSection {
            kind: read_u16le(&table, base)?,
            offset: read_u64le(&table, base + 4)?,
            length: read_u64le(&table, base + 12)?,
        });
    }

    let packages_sub = find(&subs, SECTION_PACKAGES)?;
    let block_table_sub = find(&subs, SECTION_BLOCK_TABLE)?;
    let blocks_sub = find(&subs, SECTION_BLOCKS)?;
    let trigrams_sub = find(&subs, SECTION_TRIGRAMS)?;
    let postings_sub = find(&subs, SECTION_POSTINGS)?;

    let packages = parse_packages(&decompress(&read(db, section, packages_sub)?)?, package_count)?;
    let blocks = parse_blocks(
        &read(db, section, block_table_sub)?,
        block_count,
        record_count,
        blocks_sub.length,
    )?;
    let postings = decompress(&read(db, section, postings_sub)?)?;
    let trigrams = parse_trigrams(
        &decompress(&read(db, section, trigrams_sub)?)?,
        trigram_count,
        postings.len(),
    )?;

    let candidates = candidate_blocks(query, &trigrams, &postings, block_count)?;

    let mut records = Vec::new();
    for block_id in candidates {
        let block = blocks
            .get(block_id)
            .ok_or_else(|| invalid("candidate block id out of bounds"))?;
        let raw = decompress(&db.read_at(
            section,
            blocks_sub.offset + block.compressed_offset,
            u64::from(block.compressed_length),
        )?)?;
        if raw.len() != block.uncompressed_length as usize {
            return Err(invalid("record block length mismatch"));
        }
        decode_block(&raw, block.record_count, &packages, query, &mut records)?;
    }

    Ok(records)
}

fn candidate_blocks(
    query: &str,
    trigrams: &HashMap<u32, Trigram>,
    postings: &[u8],
    block_count: usize,
) -> Result<Vec<usize>> {
    let bytes = query.as_bytes();
    if bytes.len() < 3 {
        return Ok((0..block_count).collect());
    }

    let mut lists: Vec<Vec<u64>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for window in bytes.windows(3) {
        let trigram =
            (u32::from(window[0]) << 16) | (u32::from(window[1]) << 8) | u32::from(window[2]);
        if !seen.insert(trigram) {
            continue;
        }
        // A trigram the index has never seen means no block can match.
        let Some(entry) = trigrams.get(&trigram) else {
            return Ok(Vec::new());
        };
        if entry.flags & TRIGRAM_SKIPPED == 0 {
            lists.push(decode_postings(entry, postings, block_count)?);
        }
    }

    if lists.is_empty() {
        return Ok((0..block_count).collect());
    }

    lists.sort_by_key(Vec::len);
    let mut candidates = lists.remove(0);
    for list in &lists {
        candidates = intersect(&candidates, list);
        if candidates.is_empty() {
            break;
        }
    }
    Ok(candidates.into_iter().map(|id| id as usize).collect())
}

fn intersect(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                result.push(a[i]);
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    result
}

fn decode_postings(entry: &Trigram, postings: &[u8], block_count: usize) -> Result<Vec<u64>> {
    let start = usize::try_from(entry.postings_offset)
        .map_err(|_| invalid("postings offset is too large for this platform"))?;
    let end = start
        .checked_add(entry.postings_length as usize)
        .ok_or_else(|| invalid("postings slice overflow"))?;
    if end > postings.len() {
        return Err(invalid("postings slice out of bounds"));
    }

    let mut result = Vec::with_capacity(entry.doc_freq as usize);
    let mut pos = start;
    let mut current = 0u64;
    for i in 0..entry.doc_freq {
        let value = read_varint(postings, &mut pos)?;
        current = if i == 0 {
            value
        } else {
            current
                .checked_add(value)
                .ok_or_else(|| invalid("posting id overflow"))?
        };
        if current >= block_count as u64 {
            return Err(invalid("posting id out of bounds"));
        }
        if result.last().is_some_and(|last| *last >= current) {
            return Err(invalid("non-monotonic postings"));
        }
        result.push(current);
    }
    if pos != end {
        return Err(invalid("trailing bytes in postings"));
    }
    Ok(result)
}

fn decode_block(
    raw: &[u8],
    expected_count: u32,
    packages: &[String],
    query: &str,
    out: &mut Vec<FileRecord>,
) -> Result<()> {
    let mut pos = 0usize;
    let count = read_varint(raw, &mut pos)?;
    if count != u64::from(expected_count) {
        return Err(invalid("record block count mismatch"));
    }

    let mut previous_path = String::new();
    for _ in 0..count {
        let shared = read_varint(raw, &mut pos)? as usize;
        let suffix_length = read_varint(raw, &mut pos)? as usize;
        if shared > previous_path.len() || !previous_path.is_char_boundary(shared) {
            return Err(invalid("invalid path prefix boundary"));
        }
        let suffix = read_str(raw, &mut pos, suffix_length)?;
        let path = format!("{}{}", &previous_path[..shared], suffix);
        previous_path = path.clone();

        let package_count = read_varint(raw, &mut pos)? as usize;
        let mut record_packages = Vec::with_capacity(package_count);
        for _ in 0..package_count {
            let id = read_varint(raw, &mut pos)? as usize;
            let name = packages.get(id).ok_or_else(|| invalid("invalid package id"))?;
            record_packages.push(name.clone());
        }

        let kind = match read_varint(raw, &mut pos)? {
            1 => FileKind::Directory,
            2 => FileKind::Symlink,
            _ => FileKind::Regular,
        };
        let size = read_varint(raw, &mut pos)?;
        let executable = read_varint(raw, &mut pos)? != 0;
        let target_length = read_varint(raw, &mut pos)? as usize;
        let target = read_str(raw, &mut pos, target_length)?.to_owned();

        if path.contains(query) {
            out.push(FileRecord {
                path,
                packages: record_packages,
                size,
                kind,
                executable,
                target,
            });
        }
    }

    if pos != raw.len() {
        return Err(invalid("trailing bytes in record block"));
    }
    Ok(())
}

fn parse_packages(data: &[u8], expected: usize) -> Result<Vec<String>> {
    let count = read_u32le(data, 0)? as usize;
    if count != expected {
        return Err(invalid("package count mismatch"));
    }
    let names_start = 4 + (count + 1) * 4;
    if names_start > data.len() {
        return Err(invalid("truncated package offset table"));
    }
    let names = &data[names_start..];

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let start = read_u32le(data, 4 + i * 4)? as usize;
        let end = read_u32le(data, 4 + (i + 1) * 4)? as usize;
        if start > end || end > names.len() {
            return Err(invalid("invalid package string offset"));
        }
        result.push(
            std::str::from_utf8(&names[start..end])
                .map_err(|_| invalid("non-UTF-8 package string"))?
                .to_owned(),
        );
    }
    Ok(result)
}

fn parse_blocks(
    data: &[u8],
    expected: usize,
    record_count: u64,
    blocks_length: u64,
) -> Result<Vec<Block>> {
    let count = read_u32le(data, 0)? as usize;
    if count != expected || data.len() != 4 + count * BLOCK_ENTRY_SIZE {
        return Err(invalid("block table length mismatch"));
    }

    let mut result = Vec::with_capacity(count);
    let (mut expected_id, mut expected_offset) = (0u64, 0u64);
    for i in 0..count {
        let base = 4 + i * BLOCK_ENTRY_SIZE;
        let block = Block {
            first_record_id: read_u64le(data, base)?,
            record_count: read_u32le(data, base + 8)?,
            compressed_offset: read_u64le(data, base + 12)?,
            compressed_length: read_u32le(data, base + 20)?,
            uncompressed_length: read_u32le(data, base + 24)?,
        };
        if block.first_record_id != expected_id || block.compressed_offset != expected_offset {
            return Err(invalid("non-contiguous record blocks"));
        }
        expected_id += u64::from(block.record_count);
        expected_offset += u64::from(block.compressed_length);
        result.push(block);
    }

    // The blocks must account for every record and every byte of the payload,
    // or the header and the table disagree about what the index contains.
    if expected_id != record_count || expected_offset != blocks_length {
        return Err(invalid("record block table does not cover index"));
    }
    Ok(result)
}

fn parse_trigrams(
    data: &[u8],
    expected: usize,
    postings_length: usize,
) -> Result<HashMap<u32, Trigram>> {
    let count = read_u32le(data, 0)? as usize;
    if count != expected || data.len() != 4 + count * TRIGRAM_ENTRY_SIZE {
        return Err(invalid("trigram table length mismatch"));
    }

    let mut result = HashMap::with_capacity(count);
    for i in 0..count {
        let base = 4 + i * TRIGRAM_ENTRY_SIZE;
        let trigram = (u32::from(data[base]) << 16)
            | (u32::from(data[base + 1]) << 8)
            | u32::from(data[base + 2]);
        let entry = Trigram {
            flags: data[base + 3],
            doc_freq: read_u32le(data, base + 4)?,
            postings_offset: read_u64le(data, base + 8)?,
            postings_length: read_u32le(data, base + 16)?,
        };
        let end = entry
            .postings_offset
            .checked_add(u64::from(entry.postings_length))
            .ok_or_else(|| invalid("postings slice overflow"))?;
        if end > postings_length as u64 {
            return Err(invalid("postings slice out of bounds"));
        }
        result.insert(trigram, entry);
    }
    Ok(result)
}

fn find(subs: &[SubSection], kind: u16) -> Result<SubSection> {
    let mut found = None;
    for sub in subs {
        if sub.kind == kind {
            if found.is_some() {
                return Err(invalid("duplicate index section"));
            }
            found = Some(*sub);
        }
    }
    found.ok_or_else(|| invalid("missing index section"))
}

fn read(db: &DbFile, section: Section, sub: SubSection) -> Result<Vec<u8>> {
    db.read_at(section, sub.offset, sub.length)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data).map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *data.get(*pos).ok_or_else(|| invalid("truncated varint"))?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(invalid("malformed varint"))
}

fn read_str<'a>(data: &'a [u8], pos: &mut usize, length: usize) -> Result<&'a str> {
    let end = pos
        .checked_add(length)
        .ok_or_else(|| invalid("byte slice overflow"))?;
    if end > data.len() {
        return Err(invalid("truncated byte slice"));
    }
    let slice = &data[*pos..end];
    *pos = end;
    std::str::from_utf8(slice).map_err(|_| invalid("non-UTF-8 string"))
}

fn read_u16le(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| invalid("truncated index"))
}

fn read_u32le(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| invalid("truncated index"))
}

fn read_u64le(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| invalid("truncated index"))
}

fn invalid(message: &str) -> Error {
    Error::InvalidDatabase(message.to_owned())
}
