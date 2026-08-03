//! Reader for the `index-v2` section encoding.
//!
//! Records are grouped into row groups of a fixed record count, and each group
//! stores every column in its own zstd frame. A substring match only needs the
//! three path columns, so the size, package and target columns of a group are
//! decompressed solely when that group contains a hit. A trigram index over the
//! groups narrows the candidate set first; trigrams appearing in too many
//! groups are marked skipped and carry no postings.

use std::collections::HashMap;

use crate::{
    Error, Result,
    format::{DbFile, Section},
    packages::{FileKind, FileRecord},
};

/// Bytes in the fixed header preceding the section table.
const FIXED_HEADER_SIZE: u64 = 32;

/// Bytes per section table entry.
const SECTION_ENTRY_SIZE: u64 = 20;

/// Bytes per trigram table entry: 3 trigram, 1 flags, 5 postings offset.
const TRIGRAM_ENTRY_SIZE: usize = 9;

/// Byte planes per file size.
const SIZE_PLANES: usize = 5;

/// Number of columns in a row group; also their order on disk.
const COLUMN_COUNT: usize = 11;

const COL_DIFF: usize = 0;
const COL_SUFFIX_LEN: usize = 1;
const COL_SUFFIX: usize = 2;
const COL_FLAGS: usize = 3;
const COL_SIZE0: usize = 4;
const COL_PKGSET: usize = 9;
const COL_TARGET: usize = 10;

const SECTION_PACKAGE_NAMES: u16 = 1;
const SECTION_PACKAGE_SETS: u16 = 2;
const SECTION_DIRECTORY: u16 = 3;
const SECTION_COLUMNS: u16 = 4;
const SECTION_TRIGRAMS: u16 = 5;
const SECTION_POSTINGS: u16 = 6;

/// A trigram present in too many groups to be worth intersecting.
const TRIGRAM_SKIPPED: u8 = 1;

/// Escape marking a prefix delta that did not fit in one signed byte.
const LARGE_DIFF: u8 = 0x80;

#[derive(Debug, Clone, Copy)]
struct SubSection {
    kind: u16,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone)]
struct Group {
    data_offset: u64,
    record_count: u32,
    lengths: [u32; COLUMN_COUNT],
}

impl Group {
    /// Offset of `column` within the column data section.
    fn column_offset(&self, column: usize) -> u64 {
        self.data_offset + self.lengths[..column].iter().map(|l| u64::from(*l)).sum::<u64>()
    }
}

#[derive(Debug, Clone, Copy)]
struct Trigram {
    flags: u8,
    postings_offset: u64,
    postings_length: u64,
}

/// Return every record whose path contains `query`.
pub(crate) fn query(db: &DbFile, section: Section, query: &str) -> Result<Vec<FileRecord>> {
    let fixed = db.read_at(section, 0, FIXED_HEADER_SIZE)?;
    let record_count = read_u64le(&fixed, 0)?;
    let name_count = read_u32le(&fixed, 8)? as usize;
    let set_count = read_u32le(&fixed, 12)? as usize;
    let group_count = read_u32le(&fixed, 16)? as usize;
    let trigram_count = read_u32le(&fixed, 20)? as usize;
    let column_count = read_u32le(&fixed, 24)? as usize;
    let sub_count = read_u32le(&fixed, 28)? as u64;

    if column_count != COLUMN_COUNT {
        return Err(invalid("unexpected v2 column count"));
    }
    if sub_count != 6 {
        return Err(invalid("unexpected v2 section count"));
    }

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

    let columns_sub = find(&subs, SECTION_COLUMNS)?;
    let names = parse_names(
        &decompress(&read(db, section, find(&subs, SECTION_PACKAGE_NAMES)?)?)?,
        name_count,
    )?;
    let sets = parse_sets(
        &decompress(&read(db, section, find(&subs, SECTION_PACKAGE_SETS)?)?)?,
        set_count,
        name_count,
    )?;
    let groups = parse_directory(
        &decompress(&read(db, section, find(&subs, SECTION_DIRECTORY)?)?)?,
        group_count,
        record_count,
        columns_sub.length,
    )?;
    let postings = decompress(&read(db, section, find(&subs, SECTION_POSTINGS)?)?)?;
    let trigrams = parse_trigrams(
        &decompress(&read(db, section, find(&subs, SECTION_TRIGRAMS)?)?)?,
        trigram_count,
        postings.len(),
    )?;

    let candidates = candidate_groups(query, &trigrams, &postings, group_count)?;

    let mut records = Vec::new();
    for group_id in candidates {
        let group = groups
            .get(group_id)
            .ok_or_else(|| invalid("candidate group out of bounds"))?;

        let column = |index: usize| -> Result<Vec<u8>> {
            decompress(&db.read_at(
                section,
                columns_sub.offset + group.column_offset(index),
                u64::from(group.lengths[index]),
            )?)
        };

        // Rebuild this group's paths from the path columns alone; everything
        // else stays compressed unless something matches.
        let diffs = column(COL_DIFF)?;
        let suffix_lens = column(COL_SUFFIX_LEN)?;
        let suffixes = column(COL_SUFFIX)?;

        let rows = group.record_count as usize;
        let mut paths: Vec<String> = Vec::with_capacity(rows);
        let mut hits: Vec<usize> = Vec::new();
        let mut diff_pos = 0usize;
        let mut len_pos = 0usize;
        let mut suffix_pos = 0usize;
        let mut shared: i64 = 0;
        let mut previous = String::new();

        for row in 0..rows {
            shared += read_diff(&diffs, &mut diff_pos)?;
            if shared < 0 || shared as usize > previous.len() {
                return Err(invalid("invalid v2 path prefix boundary"));
            }
            let shared_len = shared as usize;
            if !previous.is_char_boundary(shared_len) {
                return Err(invalid("invalid v2 path prefix boundary"));
            }
            let suffix_len = read_varint(&suffix_lens, &mut len_pos)? as usize;
            let end = suffix_pos
                .checked_add(suffix_len)
                .ok_or_else(|| invalid("v2 suffix slice overflow"))?;
            if end > suffixes.len() {
                return Err(invalid("truncated v2 path suffix"));
            }
            let suffix = std::str::from_utf8(&suffixes[suffix_pos..end])
                .map_err(|_| invalid("non-UTF-8 path suffix"))?;
            suffix_pos = end;

            let path = format!("{}{}", &previous[..shared_len], suffix);
            if path.contains(query) {
                hits.push(row);
            }
            previous = path.clone();
            paths.push(path);
        }

        if hits.is_empty() {
            continue;
        }

        let flags = column(COL_FLAGS)?;
        let pkg_sets = column(COL_PKGSET)?;
        let targets = column(COL_TARGET)?;
        let mut planes = Vec::with_capacity(SIZE_PLANES);
        for plane in 0..SIZE_PLANES {
            planes.push(column(COL_SIZE0 + plane)?);
        }

        if flags.len() != rows {
            return Err(invalid("v2 flag column length mismatch"));
        }

        // The variable-width columns only hold entries for the rows carrying
        // them, so every row has to be walked to keep the cursors aligned.
        let mut set_pos = 0usize;
        let mut target_pos = 0usize;
        let mut regular_index = 0usize;
        let mut hit_index = 0usize;

        for row in 0..rows {
            let flag_byte = flags[row];
            let kind = match flag_byte & 0x3 {
                1 => FileKind::Directory,
                2 => FileKind::Symlink,
                _ => FileKind::Regular,
            };
            let set_id = read_varint(&pkg_sets, &mut set_pos)? as usize;

            let mut size = 0u64;
            if kind == FileKind::Regular {
                if regular_index >= planes[0].len() {
                    return Err(invalid("v2 size column is short"));
                }
                for (plane, bytes) in planes.iter().enumerate() {
                    size |= u64::from(bytes[regular_index]) << (8 * plane);
                }
                regular_index += 1;
            }

            let mut target = String::new();
            if kind == FileKind::Symlink {
                let length = read_varint(&targets, &mut target_pos)? as usize;
                let end = target_pos
                    .checked_add(length)
                    .ok_or_else(|| invalid("v2 target slice overflow"))?;
                if end > targets.len() {
                    return Err(invalid("truncated v2 symlink target"));
                }
                target = std::str::from_utf8(&targets[target_pos..end])
                    .map_err(|_| invalid("non-UTF-8 symlink target"))?
                    .to_owned();
                target_pos = end;
            }

            if hit_index < hits.len() && hits[hit_index] == row {
                hit_index += 1;
                let ids = sets
                    .get(set_id)
                    .ok_or_else(|| invalid("invalid v2 package set id"))?;
                let packages = ids.iter().map(|id| names[*id].clone()).collect();
                records.push(FileRecord {
                    path: std::mem::take(&mut paths[row]),
                    packages,
                    size,
                    kind,
                    executable: flag_byte & 4 != 0,
                    target,
                });
            }
        }
    }

    Ok(records)
}

fn candidate_groups(
    query: &str,
    trigrams: &HashMap<u32, Trigram>,
    postings: &[u8],
    group_count: usize,
) -> Result<Vec<usize>> {
    let bytes = query.as_bytes();
    if bytes.len() < 3 {
        return Ok((0..group_count).collect());
    }

    let mut lists: Vec<Vec<u64>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for window in bytes.windows(3) {
        let trigram =
            (u32::from(window[0]) << 16) | (u32::from(window[1]) << 8) | u32::from(window[2]);
        if !seen.insert(trigram) {
            continue;
        }
        // A trigram the index has never seen means no group can match.
        let Some(entry) = trigrams.get(&trigram) else {
            return Ok(Vec::new());
        };
        if entry.flags & TRIGRAM_SKIPPED == 0 {
            lists.push(decode_postings(entry, postings, group_count)?);
        }
    }

    if lists.is_empty() {
        return Ok((0..group_count).collect());
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

fn decode_postings(entry: &Trigram, postings: &[u8], group_count: usize) -> Result<Vec<u64>> {
    let start = usize::try_from(entry.postings_offset)
        .map_err(|_| invalid("postings offset is too large for this platform"))?;
    let end = start
        .checked_add(entry.postings_length as usize)
        .ok_or_else(|| invalid("postings slice overflow"))?;
    if end > postings.len() {
        return Err(invalid("postings slice out of bounds"));
    }

    let mut result = Vec::new();
    let mut pos = start;
    let mut current = 0u64;
    let mut first = true;
    while pos < end {
        let value = read_varint(postings, &mut pos)?;
        current = if first {
            value
        } else {
            current
                .checked_add(value)
                .ok_or_else(|| invalid("posting group id overflow"))?
        };
        first = false;
        if current >= group_count as u64 {
            return Err(invalid("posting group id out of bounds"));
        }
        if result.last().is_some_and(|last| *last >= current) {
            return Err(invalid("non-monotonic postings"));
        }
        result.push(current);
    }
    Ok(result)
}

fn parse_directory(
    data: &[u8],
    group_count: usize,
    record_count: u64,
    columns_length: u64,
) -> Result<Vec<Group>> {
    let entry_size = 16 + COLUMN_COUNT * 4;
    if data.len() != group_count * entry_size {
        return Err(invalid("v2 group directory length mismatch"));
    }

    let mut groups = Vec::with_capacity(group_count);
    let mut expected_record = 0u32;
    let mut expected_offset = 0u64;
    for i in 0..group_count {
        let base = i * entry_size;
        let data_offset = read_u64le(data, base)?;
        let first_record = read_u32le(data, base + 8)?;
        let record_count_here = read_u32le(data, base + 12)?;

        let mut lengths = [0u32; COLUMN_COUNT];
        let mut total = 0u64;
        for (column, length) in lengths.iter_mut().enumerate() {
            *length = read_u32le(data, base + 16 + column * 4)?;
            total += u64::from(*length);
        }

        if first_record != expected_record || data_offset != expected_offset {
            return Err(invalid("non-contiguous v2 row groups"));
        }
        expected_record += record_count_here;
        expected_offset += total;

        groups.push(Group {
            data_offset,
            record_count: record_count_here,
            lengths,
        });
    }

    if u64::from(expected_record) != record_count || expected_offset != columns_length {
        return Err(invalid("v2 group directory does not cover the index"));
    }
    Ok(groups)
}

fn parse_names(data: &[u8], expected: usize) -> Result<Vec<String>> {
    if expected == 0 {
        if !data.is_empty() {
            return Err(invalid("v2 package name table is not empty"));
        }
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(data).map_err(|_| invalid("non-UTF-8 package name"))?;
    let names: Vec<String> = text.split('\n').map(str::to_owned).collect();
    if names.len() != expected {
        return Err(invalid("v2 package name count mismatch"));
    }
    Ok(names)
}

fn parse_sets(data: &[u8], expected: usize, name_count: usize) -> Result<Vec<Vec<usize>>> {
    let mut sets = Vec::with_capacity(expected);
    let mut pos = 0usize;
    for _ in 0..expected {
        let count = read_varint(data, &mut pos)? as usize;
        let mut ids = Vec::with_capacity(count);
        let mut previous = 0usize;
        for _ in 0..count {
            let id = previous
                .checked_add(read_varint(data, &mut pos)? as usize)
                .ok_or_else(|| invalid("v2 package id overflow"))?;
            if id >= name_count {
                return Err(invalid("invalid v2 package id"));
            }
            ids.push(id);
            previous = id;
        }
        sets.push(ids);
    }
    if pos != data.len() {
        return Err(invalid("trailing bytes in v2 package set table"));
    }
    Ok(sets)
}

fn parse_trigrams(
    data: &[u8],
    expected: usize,
    postings_length: usize,
) -> Result<HashMap<u32, Trigram>> {
    if data.len() != 4 + expected * TRIGRAM_ENTRY_SIZE {
        return Err(invalid("v2 trigram table length mismatch"));
    }
    if read_u32le(data, 0)? as usize != expected {
        return Err(invalid("v2 trigram count mismatch"));
    }

    let mut result = HashMap::with_capacity(expected);
    let mut previous_trigram = 0u32;
    for i in 0..expected {
        let base = 4 + i * TRIGRAM_ENTRY_SIZE;
        let trigram = (u32::from(data[base]) << 16)
            | (u32::from(data[base + 1]) << 8)
            | u32::from(data[base + 2]);
        if i > 0 && trigram <= previous_trigram {
            return Err(invalid("v2 trigram table is not sorted"));
        }
        previous_trigram = trigram;

        let offset = read_u40le(data, base + 4)?;
        // A list runs until the next one starts; the last runs to the end.
        let next = if i == expected - 1 {
            postings_length as u64
        } else {
            read_u40le(data, base + TRIGRAM_ENTRY_SIZE + 4)?
        };
        if next < offset || next > postings_length as u64 {
            return Err(invalid("v2 postings slice out of bounds"));
        }

        result.insert(
            trigram,
            Trigram {
                flags: data[base + 3],
                postings_offset: offset,
                postings_length: next - offset,
            },
        );
    }
    Ok(result)
}

fn find(subs: &[SubSection], kind: u16) -> Result<SubSection> {
    let mut found = None;
    for sub in subs {
        if sub.kind == kind {
            if found.is_some() {
                return Err(invalid("duplicate v2 section"));
            }
            found = Some(*sub);
        }
    }
    found.ok_or_else(|| invalid("missing v2 section"))
}

fn read(db: &DbFile, section: Section, sub: SubSection) -> Result<Vec<u8>> {
    db.read_at(section, sub.offset, sub.length)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    zstd::decode_all(data).map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))
}

fn read_diff(data: &[u8], pos: &mut usize) -> Result<i64> {
    let head = *data
        .get(*pos)
        .ok_or_else(|| invalid("truncated prefix delta"))?;
    *pos += 1;
    if head == LARGE_DIFF {
        if *pos + 2 > data.len() {
            return Err(invalid("truncated wide prefix delta"));
        }
        let value = (i32::from(data[*pos]) << 8) | i32::from(data[*pos + 1]);
        *pos += 2;
        return Ok(i64::from(value as i16));
    }
    Ok(i64::from(head as i8))
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

fn read_u40le(data: &[u8], offset: usize) -> Result<u64> {
    let slice = data
        .get(offset..offset + 5)
        .ok_or_else(|| invalid("truncated index"))?;
    let mut value = 0u64;
    for (i, byte) in slice.iter().enumerate() {
        value |= u64::from(*byte) << (8 * i);
    }
    Ok(value)
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
