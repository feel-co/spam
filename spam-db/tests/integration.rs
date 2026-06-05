use std::{collections::HashSet, io::Write};

const INDEX_COMPRESSION_LEVEL: i32 = 19;

/// Build a raw spam database in memory.
///
/// `kind` must be `"options"` or `"packages"`. `lines` are the raw
/// tab-separated records that will be placed into the appropriate buckets.
fn build_db(kind: &str, lines: &[&str]) -> Vec<u8> {
    const BUCKETS: usize = 256;
    const ENTRY_SIZE: usize = 16;

    let mut buckets: Vec<Vec<String>> = vec![Vec::new(); BUCKETS];

    for &line in lines {
        let key = line.split('\t').next().unwrap_or(line);
        let mut seen = HashSet::new();
        for byte in key.bytes() {
            if seen.insert(byte) {
                buckets[byte as usize].push(line.to_owned());
            }
        }
    }

    let mut index = vec![0u8; BUCKETS * ENTRY_SIZE];
    let mut data: Vec<u8> = Vec::new();

    for (i, bucket) in buckets.iter().enumerate() {
        let offset = data.len() as u64;
        let length: u64;
        if bucket.is_empty() {
            length = 0;
        } else {
            let text = format!("{}\n", bucket.join("\n"));
            let compressed = zstd::encode_all(text.as_bytes(), 3).unwrap();
            length = compressed.len() as u64;
            data.extend_from_slice(&compressed);
        }
        let base = i * ENTRY_SIZE;
        index[base..base + 8].copy_from_slice(&offset.to_le_bytes());
        index[base + 8..base + 16].copy_from_slice(&length.to_le_bytes());
    }

    let header = format!("# spam-db-v1\t{kind}\n");
    let mut out = Vec::new();
    out.write_all(header.as_bytes()).unwrap();
    out.write_all(&index).unwrap();
    out.write_all(&data).unwrap();
    out
}

#[derive(Clone)]
struct V1Record<'a> {
    path: &'a str,
    packages: Vec<u32>,
    size: u64,
    kind: u64,
    executable: bool,
    target: &'a str,
}

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn build_v1_index_db(packages: &[&str], records: &[V1Record<'_>]) -> Vec<u8> {
    let mut records = records.to_vec();
    records.sort_by(|a, b| a.path.cmp(b.path));

    let mut package_section = Vec::new();
    package_section.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    let mut names = Vec::new();
    package_section.extend_from_slice(&0u32.to_le_bytes());
    for package in packages {
        names.extend_from_slice(package.as_bytes());
        package_section.extend_from_slice(&(names.len() as u32).to_le_bytes());
    }
    package_section.extend_from_slice(&names);

    let mut raw_block = Vec::new();
    put_varint(records.len() as u64, &mut raw_block);
    let mut previous = String::new();
    for record in &records {
        let mut shared = previous
            .as_bytes()
            .iter()
            .zip(record.path.as_bytes())
            .take_while(|(a, b)| a == b)
            .count();
        while shared > 0
            && (!previous.is_char_boundary(shared) || !record.path.is_char_boundary(shared))
        {
            shared -= 1;
        }
        let suffix = &record.path.as_bytes()[shared..];
        put_varint(shared as u64, &mut raw_block);
        put_varint(suffix.len() as u64, &mut raw_block);
        raw_block.extend_from_slice(suffix);
        put_varint(record.packages.len() as u64, &mut raw_block);
        for package in &record.packages {
            put_varint(*package as u64, &mut raw_block);
        }
        put_varint(record.kind, &mut raw_block);
        put_varint(record.size, &mut raw_block);
        put_varint(u64::from(record.executable), &mut raw_block);
        put_varint(record.target.len() as u64, &mut raw_block);
        raw_block.extend_from_slice(record.target.as_bytes());
        previous = record.path.to_owned();
    }
    let compressed_block = zstd::encode_all(raw_block.as_slice(), INDEX_COMPRESSION_LEVEL).unwrap();

    let mut block_table = Vec::new();
    block_table.extend_from_slice(&1u32.to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(records.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(compressed_block.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());

    let mut block_trigrams = std::collections::BTreeSet::<u32>::new();
    for record in &records {
        let trigrams = unique_test_trigrams(record.path.as_bytes());
        block_trigrams.extend(trigrams);
    }

    let threshold = 1u32;
    let mut postings = Vec::new();
    let mut trigram_section = Vec::new();
    trigram_section.extend_from_slice(&(block_trigrams.len() as u32).to_le_bytes());
    for trigram in &block_trigrams {
        let doc_freq = 1u32;
        let skipped = doc_freq > threshold;
        let offset = postings.len() as u64;
        if !skipped {
            put_varint(0, &mut postings);
        }
        let length = postings.len() as u64 - offset;
        trigram_section.push((*trigram >> 16) as u8);
        trigram_section.push((*trigram >> 8) as u8);
        trigram_section.push(*trigram as u8);
        trigram_section.push(u8::from(skipped));
        trigram_section.extend_from_slice(&doc_freq.to_le_bytes());
        trigram_section.extend_from_slice(&offset.to_le_bytes());
        trigram_section.extend_from_slice(&(length as u32).to_le_bytes());
    }

    finish_v1_index(
        records.len() as u64,
        packages.len() as u32,
        1,
        block_trigrams.len() as u32,
        &[
            (1, package_section),
            (2, block_table),
            (3, compressed_block),
            (4, trigram_section),
            (5, postings),
        ],
    )
}

fn finish_v1_index(
    record_count: u64,
    package_count: u32,
    block_count: u32,
    trigram_count: u32,
    sections: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let sections: Vec<(u16, Vec<u8>)> = sections
        .iter()
        .map(|(kind, section)| {
            let payload = match *kind {
                1 | 4 | 5 => zstd::encode_all(section.as_slice(), INDEX_COMPRESSION_LEVEL).unwrap(),
                _ => section.clone(),
            };
            (*kind, payload)
        })
        .collect();

    let mut payload = Vec::new();
    payload.extend_from_slice(&record_count.to_le_bytes());
    payload.extend_from_slice(&package_count.to_le_bytes());
    payload.extend_from_slice(&block_count.to_le_bytes());
    payload.extend_from_slice(&trigram_count.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&(sections.len() as u32).to_le_bytes());

    let mut offset = (28 + sections.len() * 20) as u64;
    for (kind, section) in &sections {
        payload.extend_from_slice(&kind.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&(section.len() as u64).to_le_bytes());
        offset += section.len() as u64;
    }
    for (_, section) in sections {
        payload.extend_from_slice(&section);
    }

    let mut out = b"# spam-db-v1\tindex\n".to_vec();
    out.extend_from_slice(&payload);
    out
}

fn build_v1_raw_index(
    packages: &[&str],
    raw_block: &[u8],
    trigram_section: Vec<u8>,
    postings: Vec<u8>,
    record_count: u64,
    trigram_count: u32,
) -> Vec<u8> {
    let mut package_section = Vec::new();
    package_section.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    let mut names = Vec::new();
    package_section.extend_from_slice(&0u32.to_le_bytes());
    for package in packages {
        names.extend_from_slice(package.as_bytes());
        package_section.extend_from_slice(&(names.len() as u32).to_le_bytes());
    }
    package_section.extend_from_slice(&names);

    let compressed_block = zstd::encode_all(raw_block, INDEX_COMPRESSION_LEVEL).unwrap();
    let mut block_table = Vec::new();
    block_table.extend_from_slice(&1u32.to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(record_count as u32).to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(compressed_block.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());

    finish_v1_index(
        record_count,
        packages.len() as u32,
        1,
        trigram_count,
        &[
            (1, package_section),
            (2, block_table),
            (3, compressed_block),
            (4, trigram_section),
            (5, postings),
        ],
    )
}

fn build_v1_raw_index_blocks(
    packages: &[&str],
    raw_blocks: &[Vec<u8>],
    trigram_section: Vec<u8>,
    postings: Vec<u8>,
    trigram_count: u32,
) -> Vec<u8> {
    let mut package_section = Vec::new();
    package_section.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    let mut names = Vec::new();
    package_section.extend_from_slice(&0u32.to_le_bytes());
    for package in packages {
        names.extend_from_slice(package.as_bytes());
        package_section.extend_from_slice(&(names.len() as u32).to_le_bytes());
    }
    package_section.extend_from_slice(&names);

    let mut block_table = Vec::new();
    let mut blocks_section = Vec::new();
    block_table.extend_from_slice(&(raw_blocks.len() as u32).to_le_bytes());
    let mut first_record_id = 0u64;
    let mut compressed_offset = 0u64;
    for raw_block in raw_blocks {
        let compressed_block = zstd::encode_all(raw_block.as_slice(), INDEX_COMPRESSION_LEVEL).unwrap();
        block_table.extend_from_slice(&first_record_id.to_le_bytes());
        block_table.extend_from_slice(&1u32.to_le_bytes());
        block_table.extend_from_slice(&compressed_offset.to_le_bytes());
        block_table.extend_from_slice(&(compressed_block.len() as u32).to_le_bytes());
        block_table.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());
        first_record_id += 1;
        compressed_offset += compressed_block.len() as u64;
        blocks_section.extend_from_slice(&compressed_block);
    }

    finish_v1_index(
        first_record_id,
        packages.len() as u32,
        raw_blocks.len() as u32,
        trigram_count,
        &[
            (1, package_section),
            (2, block_table),
            (3, blocks_section),
            (4, trigram_section),
            (5, postings),
        ],
    )
}

fn unique_test_trigrams(bytes: &[u8]) -> Vec<u32> {
    let mut set = std::collections::BTreeSet::new();
    for window in bytes.windows(3) {
        set.insert((window[0] as u32) << 16 | (window[1] as u32) << 8 | window[2] as u32);
    }
    set.into_iter().collect()
}

/// Write `bytes` to a temporary file, returning a `NamedFile` handle that
/// deletes the file on drop.
struct TempFile {
    path: std::path::PathBuf,
}

impl TempFile {
    fn write(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).unwrap();
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn auto_detect_opens_as_options() {
    let bytes = build_db(
        "options",
        &["boot.loader.grub.enable\tWhether to enable GRUB"],
    );
    let f = TempFile::write("spam_test_auto_detect.db", &bytes);

    use spam_db::{DbKind, SpamDb};
    let db = SpamDb::open(f.path()).unwrap();
    assert_eq!(db.kind(), DbKind::Options);
}

#[test]
fn auto_detect_opens_as_packages() {
    let bytes = build_db("packages", &["/bin/hello\thello-2.12"]);
    let f = TempFile::write("spam_test_auto_pkg.db", &bytes);

    use spam_db::{DbKind, SpamDb};
    let db = SpamDb::open(f.path()).unwrap();
    assert_eq!(db.kind(), DbKind::Packages);
}

#[test]
fn auto_detect_opens_as_index() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 29488,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_auto_index.db", &bytes);

    use spam_db::{DbKind, SpamDb};
    let db = SpamDb::open(f.path()).unwrap();
    assert_eq!(db.kind(), DbKind::Index);
}

#[test]
fn options_db_opens_successfully() {
    let bytes = build_db(
        "options",
        &["boot.loader.grub.enable\tWhether to enable GRUB"],
    );
    let f = TempFile::write("spam_test_options_open.db", &bytes);
    spam_db::OptionsDb::open(f.path()).unwrap();
}

#[test]
fn options_query_finds_matching_record() {
    let bytes = build_db(
        "options",
        &[
            "boot.loader.grub.enable\tWhether to enable GRUB",
            "services.nginx.enable\tWhether to enable nginx",
        ],
    );
    let f = TempFile::write("spam_test_options_query.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();

    let results = db.query("boot").unwrap();
    assert!(!results.is_empty(), "expected results for \"boot\"");
    assert_eq!(results[0].name, "boot.loader.grub.enable");
    assert_eq!(
        results[0].summary.as_deref(),
        Some("Whether to enable GRUB")
    );
}

#[test]
fn options_query_results_all_contain_query() {
    let bytes = build_db(
        "options",
        &[
            "services.nginx.enable\tWhether to enable nginx",
            "services.nginx.port\tHTTP port",
            "boot.loader.grub.enable\tWhether to enable GRUB",
        ],
    );
    let f = TempFile::write("spam_test_options_filter.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();

    for rec in db.query("services").unwrap() {
        assert!(
            rec.name.contains("services"),
            "result {:?} does not contain query",
            rec.name
        );
    }
}

#[test]
fn options_query_empty_string_does_not_panic() {
    let bytes = build_db("options", &["boot.loader.grub.enable\t"]);
    let f = TempFile::write("spam_test_options_empty.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    let _ = db.query("").unwrap();
}

#[test]
fn options_query_no_results_for_impossible_string() {
    let bytes = build_db(
        "options",
        &["boot.loader.grub.enable\tWhether to enable GRUB"],
    );
    let f = TempFile::write("spam_test_options_nomatch.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    let results = db.query("ZZZNOMATCHZZZ").unwrap();
    assert!(
        results.is_empty(),
        "expected no results, got {}",
        results.len()
    );
}

#[test]
fn options_record_without_summary() {
    let bytes = build_db("options", &["boot.loader.grub.enable"]);
    let f = TempFile::write("spam_test_options_nosummary.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    let results = db.query("boot").unwrap();
    assert!(!results.is_empty());
    assert!(results[0].summary.is_none());
}

#[test]
fn packages_db_opens_successfully() {
    let bytes = build_db("packages", &["/bin/hello\thello-2.12"]);
    let f = TempFile::write("spam_test_pkg_open.db", &bytes);
    spam_db::PackagesDb::open(f.path()).unwrap();
}

#[test]
fn packages_db_opens_index_successfully() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 29488,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_index_open.db", &bytes);
    spam_db::PackagesDb::open(f.path()).unwrap();
}

#[test]
fn packages_query_index_with_metadata() {
    let bytes = build_v1_index_db(
        &["hello-2.12", "foo-1.0"],
        &[
            V1Record {
                path: "/bin/hello",
                packages: vec![0],
                size: 29488,
                kind: 0,
                executable: true,
                target: "",
            },
            V1Record {
                path: "/etc/hello-link",
                packages: vec![0],
                size: 0,
                kind: 2,
                executable: false,
                target: "/bin/hello",
            },
            V1Record {
                path: "/lib/libfoo.so",
                packages: vec![1],
                size: 153600,
                kind: 0,
                executable: false,
                target: "",
            },
        ],
    );
    let f = TempFile::write("spam_test_index_query.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/hello").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].packages, vec!["hello-2.12"]);
    assert_eq!(results[0].size, 29488);
    assert!(results[0].executable);

    let links = db.query("/etc/hello-link").unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].target, "/bin/hello");
    assert_eq!(links[0].kind, spam_db::packages::FileKind::Symlink);
}

#[test]
fn packages_query_index_with_unicode_delta_paths() {
    let bytes = build_v1_index_db(
        &["unicode-1.0"],
        &[
            V1Record {
                path: "/𝔞",
                packages: vec![0],
                size: 1,
                kind: 0,
                executable: false,
                target: "",
            },
            V1Record {
                path: "/𝔟",
                packages: vec![0],
                size: 1,
                kind: 0,
                executable: false,
                target: "",
            },
        ],
    );
    let f = TempFile::write("spam_test_index_unicode_delta.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/𝔟").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/𝔟");
    assert_eq!(results[0].packages, vec!["unicode-1.0"]);
}

#[test]
fn packages_query_v1_index_uses_trigram_candidates() {
    let bytes = build_v1_index_db(
        &["firefox-1.0", "hello-2.12"],
        &[
            V1Record {
                path: "/bin/firefox",
                packages: vec![0],
                size: 10,
                kind: 0,
                executable: true,
                target: "",
            },
            V1Record {
                path: "/bin/hello",
                packages: vec![1],
                size: 20,
                kind: 0,
                executable: true,
                target: "",
            },
            V1Record {
                path: "/share/doc/firefox/readme",
                packages: vec![0],
                size: 30,
                kind: 0,
                executable: false,
                target: "",
            },
        ],
    );
    let f = TempFile::write("spam_test_index_v1_query.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("readme").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/share/doc/firefox/readme");
    assert_eq!(results[0].packages, vec!["firefox-1.0"]);
}

#[test]
fn packages_query_v1_short_query_falls_back_to_scan() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_index_v1_short.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("he").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/bin/hello");
}

#[test]
fn packages_query_v1_absent_trigram_returns_empty() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_index_v1_absent.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("zzzz").unwrap().is_empty());
}

#[test]
fn packages_query_v1_rejects_bad_section_offset() {
    let mut bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let header_len = b"# spam-db-v1\tindex\n".len();
    let first_section_offset = header_len + 28 + 4;
    bytes[first_section_offset..first_section_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    let f = TempFile::write("spam_test_index_v1_bad_section.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_nonzero_flags() {
    let mut bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let header_len = b"# spam-db-v1\tindex\n".len();
    let flags_offset = header_len + 20;
    bytes[flags_offset..flags_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    let f = TempFile::write("spam_test_index_v1_nonzero_flags.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_nonzero_section_reserved() {
    let mut bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let header_len = b"# spam-db-v1\tindex\n".len();
    let first_section_reserved = header_len + 28 + 2;
    bytes[first_section_reserved..first_section_reserved + 2].copy_from_slice(&1u16.to_le_bytes());
    let f = TempFile::write("spam_test_index_v1_nonzero_reserved.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_invalid_package_id() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![99],
            size: 1,
            kind: 0,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_index_v1_bad_package.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_invalid_file_kind() {
    let bytes = build_v1_index_db(
        &["hello-2.12"],
        &[V1Record {
            path: "/bin/hello",
            packages: vec![0],
            size: 1,
            kind: 99,
            executable: true,
            target: "",
        }],
    );
    let f = TempFile::write("spam_test_index_v1_bad_kind.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_malformed_varint() {
    let bytes = build_v1_raw_index(&["hello-2.12"], &[0x80], vec![0, 0, 0, 0], Vec::new(), 1, 0);
    let f = TempFile::write("spam_test_index_v1_bad_varint.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("he").is_err());
}

#[test]
fn packages_query_v1_rejects_non_monotonic_postings() {
    let mut trigram_section = Vec::new();
    trigram_section.extend_from_slice(&1u32.to_le_bytes());
    trigram_section.extend_from_slice(b"abc");
    trigram_section.push(0);
    trigram_section.extend_from_slice(&2u32.to_le_bytes());
    trigram_section.extend_from_slice(&0u64.to_le_bytes());
    trigram_section.extend_from_slice(&2u32.to_le_bytes());

    let raw_blocks: Vec<Vec<u8>> = ["/abc-one", "/abc-two"]
        .iter()
        .map(|path| {
            let mut raw_block = Vec::new();
            put_varint(1, &mut raw_block);
            put_varint(0, &mut raw_block);
            put_varint(path.len() as u64, &mut raw_block);
            raw_block.extend_from_slice(path.as_bytes());
            put_varint(1, &mut raw_block);
            put_varint(0, &mut raw_block);
            put_varint(0, &mut raw_block);
            put_varint(1, &mut raw_block);
            put_varint(0, &mut raw_block);
            put_varint(0, &mut raw_block);
            raw_block
        })
        .collect();

    let bytes = build_v1_raw_index_blocks(
        &["pkg"],
        &raw_blocks,
        trigram_section,
        vec![0, 0],
        1,
    );
    let f = TempFile::write("spam_test_index_v1_bad_postings.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("abc").is_err());
}

#[test]
fn packages_query_v1_rejects_non_utf8_package_string() {
    let mut package_section = Vec::new();
    package_section.extend_from_slice(&1u32.to_le_bytes());
    package_section.extend_from_slice(&0u32.to_le_bytes());
    package_section.extend_from_slice(&1u32.to_le_bytes());
    package_section.push(0xff);

    let mut raw_block = Vec::new();
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(10, &mut raw_block);
    raw_block.extend_from_slice(b"/bin/hello");
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(0, &mut raw_block);

    let compressed_block = zstd::encode_all(raw_block.as_slice(), INDEX_COMPRESSION_LEVEL).unwrap();
    let mut block_table = Vec::new();
    block_table.extend_from_slice(&1u32.to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&1u32.to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(compressed_block.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&(raw_block.len() as u32).to_le_bytes());

    let mut trigram_section = Vec::new();
    trigram_section.extend_from_slice(&0u32.to_le_bytes());

    let bytes = finish_v1_index(
        1,
        1,
        1,
        0,
        &[
            (1, package_section),
            (2, block_table),
            (3, compressed_block),
            (4, trigram_section),
            (5, Vec::new()),
        ],
    );
    let f = TempFile::write("spam_test_index_v1_bad_package_utf8.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("hello").is_err());
}

#[test]
fn packages_query_v1_rejects_non_utf8_path_string() {
    let mut raw_block = Vec::new();
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(1, &mut raw_block);
    raw_block.push(0xff);
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(0, &mut raw_block);

    let bytes = build_v1_raw_index(&["pkg"], &raw_block, vec![0, 0, 0, 0], Vec::new(), 1, 0);
    let f = TempFile::write("spam_test_index_v1_bad_path_utf8.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("x").is_err());
}

#[test]
fn packages_query_v1_rejects_non_utf8_target_string() {
    let mut raw_block = Vec::new();
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(10, &mut raw_block);
    raw_block.extend_from_slice(b"/bin/hello");
    put_varint(1, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(2, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(0, &mut raw_block);
    put_varint(1, &mut raw_block);
    raw_block.push(0xff);

    let bytes = build_v1_raw_index(&["pkg"], &raw_block, vec![0, 0, 0, 0], Vec::new(), 1, 0);
    let f = TempFile::write("spam_test_index_v1_bad_target_utf8.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("he").is_err());
}

#[test]
fn packages_query_finds_matching_record() {
    let bytes = build_db(
        "packages",
        &["/bin/hello\thello-2.12", "/lib/libfoo.so\tfoo-1.0"],
    );
    let f = TempFile::write("spam_test_pkg_query.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/").unwrap();
    assert!(!results.is_empty(), "expected results for \"/bin/\"");
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].packages, vec!["hello-2.12"]);

    // Legacy records have zeroed metadata
    assert_eq!(results[0].size, 0);
    assert!(!results[0].executable);
    assert_eq!(results[0].target, "");
}

#[test]
fn packages_query_multiple_owners() {
    let bytes = build_db("packages", &["/bin/sh\tbash-5.2,busybox-1.36"]);
    let f = TempFile::write("spam_test_pkg_multi.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/sh").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].packages, vec!["bash-5.2", "busybox-1.36"]);
}

#[test]
fn packages_query_extended_format_with_metadata() {
    // Extended format: path\tkind\tsize\texec\ttarget\tpkg1,pkg2,...
    let bytes = build_db(
        "packages",
        &[
            "/bin/hello\tr\t29488\t1\t\thello-2.12",
            "/lib/libfoo.so\tr\t153600\t0\t\tfoo-1.0",
            "/etc/symlink\ts\t0\t0\t/bin/hello\thello-2.12",
        ],
    );
    let f = TempFile::write("spam_test_pkg_extended.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/hello").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].size, 29488);
    assert!(results[0].executable);
    assert_eq!(results[0].packages, vec!["hello-2.12"]);

    let sym = db.query("/etc/symlink").unwrap();
    assert_eq!(sym.len(), 1);
    assert_eq!(sym[0].target, "/bin/hello");
    use spam_db::packages::FileKind;
    assert_eq!(sym[0].kind, FileKind::Symlink);
}

#[test]
fn packages_query_extended_non_executable() {
    let bytes = build_db("packages", &["/lib/libfoo.so\tr\t153600\t0\t\tfoo-1.0"]);
    let f = TempFile::write("spam_test_pkg_nonexec.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/lib/").unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].executable);
    assert_eq!(results[0].size, 153600);
}

#[test]
fn packages_db_rejects_options_file() {
    let bytes = build_db("options", &["boot.loader.grub.enable\t"]);
    let f = TempFile::write("spam_test_wrong_kind.db", &bytes);

    let err = spam_db::PackagesDb::open(f.path())
        .expect_err("PackagesDb::open should fail on an options database");
    assert!(
        err.to_string().contains("packages"),
        "error should mention 'packages', got: {err}"
    );
}

#[test]
fn options_db_rejects_packages_file() {
    let bytes = build_db("packages", &["/bin/hello\thello-2.12"]);
    let f = TempFile::write("spam_test_wrong_kind2.db", &bytes);

    let err = spam_db::OptionsDb::open(f.path())
        .expect_err("OptionsDb::open should fail on a packages database");
    assert!(
        err.to_string().contains("options"),
        "error should mention 'options', got: {err}"
    );
}

#[test]
fn invalid_header_returns_error() {
    let f = TempFile::write("spam_test_bad_header.db", b"not a spam database\n");
    let err = spam_db::SpamDb::open(f.path()).expect_err("should fail on bad header");
    assert!(err.to_string().contains("invalid database"));
}
