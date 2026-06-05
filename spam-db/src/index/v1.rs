use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::{
    Error, Result,
    format::DbFile,
    packages::{FileKind, FileRecord},
};

const FIXED_HEADER_SIZE: usize = 28;
const SECTION_ENTRY_SIZE: usize = 20;
const BLOCK_ENTRY_SIZE: usize = 28;
const TRIGRAM_ENTRY_SIZE: usize = 20;
const TRIGRAM_SKIPPED: u8 = 1;

pub(crate) fn query(db: &DbFile, query: &str) -> Result<Vec<FileRecord>> {
    Index::open(db)?.query(query)
}

struct Index {
    container: Container,
    packages: Vec<String>,
    records: RecordStore,
    trigrams: TrigramIndex,
}

impl Index {
    fn open(db: &DbFile) -> Result<Self> {
        let container = Container::open(db)?;
        let counts = container.counts;

        let packages = parse_packages(
            &container.read_compressed_section(SectionKind::Packages)?,
            counts.package_count,
        )?;
        let records = RecordStore::open(
            &container,
            &container.read_section(SectionKind::BlockTable)?,
            counts.record_count,
            counts.block_count,
        )?;
        let trigrams = TrigramIndex::open(
            &container.read_compressed_section(SectionKind::Trigrams)?,
            &container.read_compressed_section(SectionKind::Postings)?,
            counts.block_count as u64,
            counts.trigram_count,
        )?;

        Ok(Self {
            container,
            packages,
            records,
            trigrams,
        })
    }

    fn query(&self, query: &str) -> Result<Vec<FileRecord>> {
        match self.trigrams.candidates(query)? {
            CandidatePlan::Empty => Ok(Vec::new()),
            CandidatePlan::Scan => self.records.scan(&self.container, &self.packages, query),
            CandidatePlan::Blocks(block_ids) => {
                self.records
                    .decode_blocks(&self.container, &self.packages, &block_ids, query)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Counts {
    record_count: u64,
    package_count: usize,
    block_count: usize,
    trigram_count: usize,
}

#[derive(Clone, Copy)]
struct Section {
    offset: u64,
    length: u64,
}

#[derive(Clone, Copy)]
struct SectionEntry {
    kind: u16,
    section: Section,
}

#[derive(Clone, Copy)]
struct Sections {
    packages: Section,
    block_table: Section,
    blocks: Section,
    trigrams: Section,
    postings: Section,
}

#[derive(Clone, Copy)]
enum SectionKind {
    Packages,
    BlockTable,
    Trigrams,
    Postings,
}

struct Container {
    path: PathBuf,
    data_start: u64,
    counts: Counts,
    sections: Sections,
}

impl Container {
    fn open(db: &DbFile) -> Result<Self> {
        let file_len = std::fs::metadata(&db.path)?.len();
        if db.data_start > file_len {
            return Err(Error::InvalidDatabase(
                "v1 payload starts past end of file".into(),
            ));
        }

        let fixed = read_at(&db.path, db.data_start, FIXED_HEADER_SIZE)?;
        let counts = Counts {
            record_count: read_u64le(&fixed, 0)?,
            package_count: read_u32le(&fixed, 8)? as usize,
            block_count: read_u32le(&fixed, 12)? as usize,
            trigram_count: read_u32le(&fixed, 16)? as usize,
        };
        let flags = read_u32le(&fixed, 20)?;
        if flags != 0 {
            return Err(Error::InvalidDatabase("unsupported v1 index flags".into()));
        }
        let section_count = read_u32le(&fixed, 24)? as usize;

        let section_table_len = section_count
            .checked_mul(SECTION_ENTRY_SIZE)
            .ok_or_else(|| Error::InvalidDatabase("v1 section table too large".into()))?;
        let table_len = FIXED_HEADER_SIZE
            .checked_add(section_table_len)
            .ok_or_else(|| Error::InvalidDatabase("v1 section table too large".into()))?;
        let section_table = read_at(
            &db.path,
            db.data_start + FIXED_HEADER_SIZE as u64,
            section_table_len,
        )?;

        let mut table_data = fixed;
        table_data.extend_from_slice(&section_table);
        let entries = parse_section_entries(&table_data, section_count)?;
        validate_section_ranges(&entries, table_len as u64, file_len - db.data_start)?;
        let sections = Sections::from_entries(&entries)?;

        Ok(Self {
            path: db.path.clone(),
            data_start: db.data_start,
            counts,
            sections,
        })
    }

    fn read_section(&self, kind: SectionKind) -> Result<Vec<u8>> {
        let section = self.section(kind);
        let offset = self
            .data_start
            .checked_add(section.offset)
            .ok_or_else(|| Error::InvalidDatabase("section file offset overflow".into()))?;
        let length = usize::try_from(section.length)
            .map_err(|_| Error::InvalidDatabase("section length too large".into()))?;
        read_at(&self.path, offset, length)
    }

    fn read_compressed_section(&self, kind: SectionKind) -> Result<Vec<u8>> {
        let compressed = self.read_section(kind)?;
        zstd::decode_all(compressed.as_slice())
            .map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))
    }

    fn read_record_block(&self, compressed_offset: u64, length: u32) -> Result<Vec<u8>> {
        let offset = self
            .data_start
            .checked_add(self.sections.blocks.offset)
            .and_then(|n| n.checked_add(compressed_offset))
            .ok_or_else(|| Error::InvalidDatabase("record block offset overflow".into()))?;
        read_at(&self.path, offset, length as usize)
    }

    fn section(&self, kind: SectionKind) -> Section {
        match kind {
            SectionKind::Packages => self.sections.packages,
            SectionKind::BlockTable => self.sections.block_table,
            SectionKind::Trigrams => self.sections.trigrams,
            SectionKind::Postings => self.sections.postings,
        }
    }
}

impl Sections {
    fn from_entries(entries: &[SectionEntry]) -> Result<Self> {
        Ok(Self {
            packages: required_section(entries, 1)?,
            block_table: required_section(entries, 2)?,
            blocks: required_section(entries, 3)?,
            trigrams: required_section(entries, 4)?,
            postings: required_section(entries, 5)?,
        })
    }
}

#[derive(Clone)]
struct Block {
    first_record_id: u64,
    record_count: u32,
    compressed_offset: u64,
    compressed_length: u32,
    uncompressed_length: u32,
}

struct RecordStore {
    blocks: Vec<Block>,
}

impl RecordStore {
    fn open(
        container: &Container,
        block_table: &[u8],
        record_count: u64,
        expected_count: usize,
    ) -> Result<Self> {
        let blocks = parse_blocks(block_table, expected_count)?;
        validate_blocks(&blocks, record_count, container.sections.blocks.length)?;
        Ok(Self { blocks })
    }

    fn scan(
        &self,
        container: &Container,
        packages: &[String],
        query: &str,
    ) -> Result<Vec<FileRecord>> {
        let block_ids: Vec<u64> = (0..self.blocks.len() as u64).collect();
        self.decode_blocks(container, packages, &block_ids, query)
    }

    fn decode_blocks(
        &self,
        container: &Container,
        packages: &[String],
        block_ids: &[u64],
        query: &str,
    ) -> Result<Vec<FileRecord>> {
        let mut records = Vec::new();
        for &block_id in block_ids {
            let block_id = usize::try_from(block_id)
                .map_err(|_| Error::InvalidDatabase("candidate block id too large".into()))?;
            if block_id >= self.blocks.len() {
                return Err(Error::InvalidDatabase(
                    "candidate block id out of bounds".into(),
                ));
            }
            for (_, record) in self.decode_block(container, packages, block_id)? {
                if record.path.contains(query) {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn decode_block(
        &self,
        container: &Container,
        packages: &[String],
        block_id: usize,
    ) -> Result<Vec<(u64, FileRecord)>> {
        let block = &self.blocks[block_id];
        let compressed =
            container.read_record_block(block.compressed_offset, block.compressed_length)?;
        let raw = zstd::decode_all(compressed.as_slice())
            .map_err(|e| Error::InvalidDatabase(format!("zstd error: {e}")))?;
        if raw.len() != block.uncompressed_length as usize {
            return Err(Error::InvalidDatabase(
                "record block decompressed length mismatch".into(),
            ));
        }
        decode_records(&raw, block.first_record_id, block.record_count, packages)
    }
}

#[derive(Clone)]
struct TrigramEntry {
    trigram: u32,
    flags: u8,
    doc_freq: u32,
    postings_offset: u64,
    postings_length: u32,
}

enum CandidatePlan {
    Empty,
    Scan,
    Blocks(Vec<u64>),
}

struct TrigramIndex {
    entries: Vec<TrigramEntry>,
    postings: Vec<u8>,
    block_count: u64,
}

impl TrigramIndex {
    fn open(
        dictionary: &[u8],
        postings: &[u8],
        block_count: u64,
        expected_count: usize,
    ) -> Result<Self> {
        let entries = parse_trigram_dictionary(dictionary, expected_count)?;
        validate_trigram_dictionary(&entries, block_count, postings.len())?;
        let index = Self {
            entries,
            postings: postings.to_vec(),
            block_count,
        };
        index.validate_postings()?;
        Ok(index)
    }

    fn candidates(&self, query: &str) -> Result<CandidatePlan> {
        if query.len() < 3 {
            return Ok(CandidatePlan::Scan);
        }

        let mut posting_lists = Vec::new();
        for trigram in unique_trigrams(query.as_bytes()) {
            match self.find(trigram) {
                Some(entry) if entry.flags & TRIGRAM_SKIPPED != 0 => {}
                Some(entry) => posting_lists.push(self.decode(entry)?),
                None => return Ok(CandidatePlan::Empty),
            }
        }

        if posting_lists.is_empty() {
            return Ok(CandidatePlan::Scan);
        }

        posting_lists.sort_by_key(Vec::len);
        let mut candidates = posting_lists.remove(0);
        for list in posting_lists {
            candidates = intersect(&candidates, &list);
            if candidates.is_empty() {
                return Ok(CandidatePlan::Empty);
            }
        }

        Ok(CandidatePlan::Blocks(candidates))
    }

    fn validate_postings(&self) -> Result<()> {
        for entry in &self.entries {
            if entry.flags & TRIGRAM_SKIPPED == 0 {
                self.decode(entry)?;
            }
        }
        Ok(())
    }

    fn find(&self, trigram: u32) -> Option<&TrigramEntry> {
        self.entries
            .binary_search_by_key(&trigram, |entry| entry.trigram)
            .ok()
            .map(|idx| &self.entries[idx])
    }

    fn decode(&self, entry: &TrigramEntry) -> Result<Vec<u64>> {
        let start = usize::try_from(entry.postings_offset)
            .map_err(|_| Error::InvalidDatabase("postings offset too large".into()))?;
        let end = start
            .checked_add(entry.postings_length as usize)
            .ok_or_else(|| Error::InvalidDatabase("postings slice overflow".into()))?;
        let data = self
            .postings
            .get(start..end)
            .ok_or_else(|| Error::InvalidDatabase("postings slice out of bounds".into()))?;

        let mut reader = ByteReader::new(data);
        let mut ids = Vec::with_capacity(entry.doc_freq as usize);
        let mut current = 0;
        for i in 0..entry.doc_freq {
            let value = reader.varint()?;
            current = if i == 0 {
                value
            } else {
                current
                    .checked_add(value)
                    .ok_or_else(|| Error::InvalidDatabase("posting id overflow".into()))?
            };
            if current >= self.block_count {
                return Err(Error::InvalidDatabase("posting block id out of bounds".into()));
            }
            if let Some(previous) = ids.last()
                && *previous >= current
            {
                return Err(Error::InvalidDatabase("non-monotonic postings".into()));
            }
            ids.push(current);
        }
        reader.finish("postings")?;
        Ok(ids)
    }
}

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        for _ in 0..10 {
            let byte = *self
                .data
                .get(self.pos)
                .ok_or_else(|| Error::InvalidDatabase("truncated varint".into()))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(Error::InvalidDatabase("malformed varint".into()))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::InvalidDatabase("byte slice overflow".into()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| Error::InvalidDatabase("truncated byte slice".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn finish(self, context: &'static str) -> Result<()> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(Error::InvalidDatabase(format!("trailing bytes in {context}")))
        }
    }
}

fn parse_section_entries(data: &[u8], count: usize) -> Result<Vec<SectionEntry>> {
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let base = FIXED_HEADER_SIZE + i * SECTION_ENTRY_SIZE;
        let reserved = read_u16le(data, base + 2)?;
        if reserved != 0 {
            return Err(Error::InvalidDatabase(
                "non-zero reserved section field".into(),
            ));
        }
        sections.push(SectionEntry {
            kind: read_u16le(data, base)?,
            section: Section {
                offset: read_u64le(data, base + 4)?,
                length: read_u64le(data, base + 12)?,
            },
        });
    }
    Ok(sections)
}

fn validate_section_ranges(
    entries: &[SectionEntry],
    min_offset: u64,
    payload_len: u64,
) -> Result<()> {
    let mut ranges = Vec::with_capacity(entries.len());
    for entry in entries {
        let end = entry
            .section
            .offset
            .checked_add(entry.section.length)
            .ok_or_else(|| Error::InvalidDatabase("section offset overflow".into()))?;
        if entry.section.offset < min_offset {
            return Err(Error::InvalidDatabase(
                "section overlaps v1 header table".into(),
            ));
        }
        if end > payload_len {
            return Err(Error::InvalidDatabase("section slice out of bounds".into()));
        }
        ranges.push((entry.section.offset, end));
    }

    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(Error::InvalidDatabase("overlapping sections".into()));
        }
    }
    Ok(())
}

fn required_section(entries: &[SectionEntry], kind: u16) -> Result<Section> {
    let mut found = None;
    for entry in entries {
        if entry.kind == kind {
            if found.is_some() {
                return Err(Error::InvalidDatabase("duplicate required section".into()));
            }
            found = Some(entry.section);
        }
    }
    found.ok_or_else(|| Error::InvalidDatabase("missing required v1 section".into()))
}

fn parse_packages(data: &[u8], expected_count: usize) -> Result<Vec<String>> {
    if data.len() < 4 {
        return Err(Error::InvalidDatabase("truncated package string table".into()));
    }
    let count = read_u32le(data, 0)? as usize;
    if count != expected_count {
        return Err(Error::InvalidDatabase("package count mismatch".into()));
    }

    let offsets_start = 4usize;
    let offsets_len = (count + 1)
        .checked_mul(4)
        .ok_or_else(|| Error::InvalidDatabase("package offset table too large".into()))?;
    let names_start = offsets_start
        .checked_add(offsets_len)
        .ok_or_else(|| Error::InvalidDatabase("package offset table too large".into()))?;
    if data.len() < names_start {
        return Err(Error::InvalidDatabase("truncated package offset table".into()));
    }

    let names = &data[names_start..];
    let mut offsets = Vec::with_capacity(count + 1);
    for i in 0..=count {
        offsets.push(read_u32le(data, offsets_start + i * 4)? as usize);
    }
    for pair in offsets.windows(2) {
        if pair[0] > pair[1] || pair[1] > names.len() {
            return Err(Error::InvalidDatabase("invalid package string offset".into()));
        }
    }

    let mut packages = Vec::with_capacity(count);
    for i in 0..count {
        let name = std::str::from_utf8(&names[offsets[i]..offsets[i + 1]])
            .map_err(|_| Error::InvalidDatabase("non-UTF-8 package string".into()))?;
        packages.push(name.to_owned());
    }
    Ok(packages)
}

fn parse_blocks(data: &[u8], expected_count: usize) -> Result<Vec<Block>> {
    if data.len() < 4 {
        return Err(Error::InvalidDatabase("truncated record block table".into()));
    }
    let count = read_u32le(data, 0)? as usize;
    if count != expected_count {
        return Err(Error::InvalidDatabase("record block count mismatch".into()));
    }
    if data.len() != 4 + count * BLOCK_ENTRY_SIZE {
        return Err(Error::InvalidDatabase("record block table length mismatch".into()));
    }

    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let base = 4 + i * BLOCK_ENTRY_SIZE;
        blocks.push(Block {
            first_record_id: read_u64le(data, base)?,
            record_count: read_u32le(data, base + 8)?,
            compressed_offset: read_u64le(data, base + 12)?,
            compressed_length: read_u32le(data, base + 20)?,
            uncompressed_length: read_u32le(data, base + 24)?,
        });
    }
    Ok(blocks)
}

fn validate_blocks(blocks: &[Block], record_count: u64, blocks_len: u64) -> Result<()> {
    let mut expected_record_id = 0;
    let mut expected_offset = 0;
    for block in blocks {
        if block.first_record_id != expected_record_id {
            return Err(Error::InvalidDatabase("non-contiguous record blocks".into()));
        }
        if block.compressed_offset != expected_offset {
            return Err(Error::InvalidDatabase("non-contiguous compressed blocks".into()));
        }
        expected_record_id = expected_record_id
            .checked_add(block.record_count as u64)
            .ok_or_else(|| Error::InvalidDatabase("record block id overflow".into()))?;
        expected_offset = expected_offset
            .checked_add(block.compressed_length as u64)
            .ok_or_else(|| Error::InvalidDatabase("record block offset overflow".into()))?;
    }
    if expected_record_id != record_count || expected_offset != blocks_len {
        return Err(Error::InvalidDatabase("record block table does not cover index".into()));
    }
    Ok(())
}

fn parse_trigram_dictionary(data: &[u8], expected_count: usize) -> Result<Vec<TrigramEntry>> {
    if data.len() < 4 {
        return Err(Error::InvalidDatabase("truncated trigram dictionary".into()));
    }
    let count = read_u32le(data, 0)? as usize;
    if count != expected_count {
        return Err(Error::InvalidDatabase("trigram count mismatch".into()));
    }
    if data.len() != 4 + count * TRIGRAM_ENTRY_SIZE {
        return Err(Error::InvalidDatabase("trigram dictionary length mismatch".into()));
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let base = 4 + i * TRIGRAM_ENTRY_SIZE;
        entries.push(TrigramEntry {
            trigram: (data[base] as u32) << 16
                | (data[base + 1] as u32) << 8
                | data[base + 2] as u32,
            flags: data[base + 3],
            doc_freq: read_u32le(data, base + 4)?,
            postings_offset: read_u64le(data, base + 8)?,
            postings_length: read_u32le(data, base + 16)?,
        });
    }
    Ok(entries)
}

fn validate_trigram_dictionary(
    entries: &[TrigramEntry],
    block_count: u64,
    postings_len: usize,
) -> Result<()> {
    let mut previous = None;
    for entry in entries {
        if let Some(previous) = previous
            && previous >= entry.trigram
        {
            return Err(Error::InvalidDatabase("trigram dictionary is not sorted".into()));
        }
        previous = Some(entry.trigram);

        let end = entry
            .postings_offset
            .checked_add(entry.postings_length as u64)
            .ok_or_else(|| Error::InvalidDatabase("postings offset overflow".into()))?;
        if end > postings_len as u64 {
            return Err(Error::InvalidDatabase("postings slice out of bounds".into()));
        }

        if entry.flags & TRIGRAM_SKIPPED != 0 {
            if entry.postings_length != 0 {
                return Err(Error::InvalidDatabase(
                    "skipped trigram has postings payload".into(),
                ));
            }
        } else if entry.doc_freq as u64 > block_count {
            return Err(Error::InvalidDatabase("trigram block frequency too large".into()));
        }
    }
    Ok(())
}

fn decode_records(
    data: &[u8],
    first_record_id: u64,
    expected_count: u32,
    packages: &[String],
) -> Result<Vec<(u64, FileRecord)>> {
    let mut reader = ByteReader::new(data);
    let count = u32::try_from(reader.varint()?)
        .map_err(|_| Error::InvalidDatabase("record block count too large".into()))?;
    if count != expected_count {
        return Err(Error::InvalidDatabase("record block count mismatch".into()));
    }

    let mut previous_path = Vec::new();
    let mut records = Vec::with_capacity(count as usize);
    for i in 0..count {
        let record = decode_record(&mut reader, &mut previous_path, packages)?;
        records.push((first_record_id + i as u64, record));
    }

    reader.finish("record block")?;
    Ok(records)
}

fn decode_record(
    reader: &mut ByteReader<'_>,
    previous_path: &mut Vec<u8>,
    packages: &[String],
) -> Result<FileRecord> {
    let shared = usize::try_from(reader.varint()?)
        .map_err(|_| Error::InvalidDatabase("shared prefix too large".into()))?;
    let suffix_len = usize::try_from(reader.varint()?)
        .map_err(|_| Error::InvalidDatabase("path suffix too large".into()))?;
    if shared > previous_path.len() || !is_utf8_boundary(previous_path, shared) {
        return Err(Error::InvalidDatabase("invalid path prefix boundary".into()));
    }

    let suffix = reader.bytes(suffix_len)?;
    std::str::from_utf8(suffix)
        .map_err(|_| Error::InvalidDatabase("non-UTF-8 path suffix".into()))?;

    let mut path_bytes = previous_path[..shared].to_vec();
    path_bytes.extend_from_slice(suffix);
    let path = String::from_utf8(path_bytes.clone())
        .map_err(|_| Error::InvalidDatabase("non-UTF-8 path string".into()))?;
    *previous_path = path_bytes;

    let package_count = usize::try_from(reader.varint()?)
        .map_err(|_| Error::InvalidDatabase("package count too large".into()))?;
    let mut record_packages = Vec::with_capacity(package_count);
    for _ in 0..package_count {
        let package_id = usize::try_from(reader.varint()?)
            .map_err(|_| Error::InvalidDatabase("package id too large".into()))?;
        let package = packages
            .get(package_id)
            .ok_or_else(|| Error::InvalidDatabase("invalid package id".into()))?;
        record_packages.push(package.clone());
    }

    let kind = match reader.varint()? {
        0 => FileKind::Regular,
        1 => FileKind::Directory,
        2 => FileKind::Symlink,
        _ => return Err(Error::InvalidDatabase("invalid file kind code".into())),
    };
    let size = reader.varint()?;
    let executable = reader.varint()? != 0;
    let target_len = usize::try_from(reader.varint()?)
        .map_err(|_| Error::InvalidDatabase("target string too large".into()))?;
    let target = std::str::from_utf8(reader.bytes(target_len)?)
        .map_err(|_| Error::InvalidDatabase("non-UTF-8 target string".into()))?
        .to_owned();

    Ok(FileRecord {
        path,
        packages: record_packages,
        size,
        kind,
        executable,
        target,
    })
}

fn unique_trigrams(bytes: &[u8]) -> Vec<u32> {
    let mut set = BTreeSet::new();
    for window in bytes.windows(3) {
        set.insert((window[0] as u32) << 16 | (window[1] as u32) << 8 | window[2] as u32);
    }
    set.into_iter().collect()
}

fn intersect(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut ai = 0;
    let mut bi = 0;
    while ai < a.len() && bi < b.len() {
        match a[ai].cmp(&b[bi]) {
            std::cmp::Ordering::Equal => {
                out.push(a[ai]);
                ai += 1;
                bi += 1;
            }
            std::cmp::Ordering::Less => ai += 1,
            std::cmp::Ordering::Greater => bi += 1,
        }
    }
    out
}

fn is_utf8_boundary(bytes: &[u8], offset: usize) -> bool {
    offset == 0 || offset == bytes.len() || bytes.get(offset).is_some_and(|b| b & 0xc0 != 0x80)
}

fn read_at(path: &Path, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    let end = offset
        .checked_add(length as u64)
        .ok_or_else(|| Error::InvalidDatabase("read offset overflow".into()))?;
    if end > file_len {
        return Err(Error::InvalidDatabase("read slice out of bounds".into()));
    }

    let mut buf = vec![0; length];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u16le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::InvalidDatabase("truncated u16".into()))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::InvalidDatabase("truncated u32".into()))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64le(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| Error::InvalidDatabase("truncated u64".into()))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}
