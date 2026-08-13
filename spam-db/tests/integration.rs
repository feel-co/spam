use std::{collections::HashSet, io::Write};

const SCOPE_PKG: u16 = 0;
const SCOPE_OPT: u16 = 1;
const SCOPE_LIB: u16 = 2;

const ENC_BUCKETS: u16 = 1;
const ENC_INDEX_V1: u16 = 2;
const ENC_INDEX_V2: u16 = 3;

/// Build the payload of a bucketed section from raw tab-separated records.
fn bucketed_payload(lines: &[&str]) -> Vec<u8> {
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
        let length = if bucket.is_empty() {
            0
        } else {
            let text = format!("{}\n", bucket.join("\n"));
            let compressed = zstd::encode_all(text.as_bytes(), 3).unwrap();
            let length = compressed.len() as u64;
            data.extend_from_slice(&compressed);
            length
        };
        let base = i * ENTRY_SIZE;
        index[base..base + 8].copy_from_slice(&offset.to_le_bytes());
        index[base + 8..base + 16].copy_from_slice(&length.to_le_bytes());
    }

    let mut out = index;
    out.extend_from_slice(&data);
    out
}

/// Assemble a `# spam-db-v2` database from `(scope, encoding, payload)` sections.
fn build_db(sections: &[(u16, u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.write_all(b"# spam-db-v2\n").unwrap();
    out.write_all(&(sections.len() as u32).to_le_bytes()).unwrap();

    let mut offset = 0u64;
    for (scope, encoding, payload) in sections {
        out.write_all(&scope.to_le_bytes()).unwrap();
        out.write_all(&encoding.to_le_bytes()).unwrap();
        out.write_all(&offset.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u64).to_le_bytes()).unwrap();
        offset += payload.len() as u64;
    }
    for (_, _, payload) in sections {
        out.write_all(payload).unwrap();
    }
    out
}

/// Assemble a legacy `# spam-db-v1` single-kind database.
fn build_legacy_db(kind: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.write_all(format!("# spam-db-v1\t{kind}\n").as_bytes())
        .unwrap();
    out.write_all(payload).unwrap();
    out
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// A file record as the `index-v1` encoder sees it.
struct IndexRecord {
    path: &'static str,
    package: &'static str,
    size: u64,
    kind: u64,
    executable: bool,
    target: &'static str,
}

/// Build the payload of an `index-v1` section holding a single record block.
///
/// This mirrors the Nim writer closely enough to exercise the decoder: package
/// table, block table, one compressed block, and a trigram index over every
/// trigram of every path.
fn index_v1_payload(records: &[IndexRecord]) -> Vec<u8> {
    let mut packages: Vec<&str> = records.iter().map(|r| r.package).collect();
    packages.sort_unstable();
    packages.dedup();

    // Package table: count, (count + 1) string offsets, then the names.
    let mut packages_raw = (packages.len() as u32).to_le_bytes().to_vec();
    let mut names = Vec::new();
    let mut offsets = vec![0u32];
    for name in &packages {
        names.extend_from_slice(name.as_bytes());
        offsets.push(names.len() as u32);
    }
    for offset in &offsets {
        packages_raw.extend_from_slice(&offset.to_le_bytes());
    }
    packages_raw.extend_from_slice(&names);

    // One block holding every record, prefix-delta encoded against its
    // predecessor.
    let mut block_raw = Vec::new();
    put_varint(&mut block_raw, records.len() as u64);
    let mut previous = "";
    for record in records {
        let shared = previous
            .char_indices()
            .zip(record.path.char_indices())
            .take_while(|((_, a), (_, b))| a == b)
            .map(|((i, c), _)| i + c.len_utf8())
            .last()
            .unwrap_or(0);
        let suffix = &record.path[shared..];
        put_varint(&mut block_raw, shared as u64);
        put_varint(&mut block_raw, suffix.len() as u64);
        block_raw.extend_from_slice(suffix.as_bytes());
        put_varint(&mut block_raw, 1);
        let id = packages.iter().position(|p| *p == record.package).unwrap();
        put_varint(&mut block_raw, id as u64);
        put_varint(&mut block_raw, record.kind);
        put_varint(&mut block_raw, record.size);
        put_varint(&mut block_raw, u64::from(record.executable));
        put_varint(&mut block_raw, record.target.len() as u64);
        block_raw.extend_from_slice(record.target.as_bytes());
        previous = record.path;
    }
    let block_compressed = zstd::encode_all(block_raw.as_slice(), 19).unwrap();

    // Block table: one contiguous block starting at record 0, offset 0.
    let mut block_table = 1u32.to_le_bytes().to_vec();
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(records.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&0u64.to_le_bytes());
    block_table.extend_from_slice(&(block_compressed.len() as u32).to_le_bytes());
    block_table.extend_from_slice(&(block_raw.len() as u32).to_le_bytes());

    // Every trigram appears in the single block, so every posting list is [0].
    let mut trigrams: Vec<u32> = Vec::new();
    for record in records {
        for window in record.path.as_bytes().windows(3) {
            let trigram = (u32::from(window[0]) << 16)
                | (u32::from(window[1]) << 8)
                | u32::from(window[2]);
            trigrams.push(trigram);
        }
    }
    trigrams.sort_unstable();
    trigrams.dedup();

    let mut postings = Vec::new();
    let mut trigram_raw = (trigrams.len() as u32).to_le_bytes().to_vec();
    for trigram in &trigrams {
        let offset = postings.len() as u64;
        put_varint(&mut postings, 0);
        let length = postings.len() as u64 - offset;
        trigram_raw.push((trigram >> 16) as u8);
        trigram_raw.push((trigram >> 8) as u8);
        trigram_raw.push(*trigram as u8);
        trigram_raw.push(0); // flags: not skipped
        trigram_raw.extend_from_slice(&1u32.to_le_bytes()); // doc frequency
        trigram_raw.extend_from_slice(&offset.to_le_bytes());
        trigram_raw.extend_from_slice(&(length as u32).to_le_bytes());
    }

    let packages_section = zstd::encode_all(packages_raw.as_slice(), 19).unwrap();
    let trigram_section = zstd::encode_all(trigram_raw.as_slice(), 19).unwrap();
    let postings_section = zstd::encode_all(postings.as_slice(), 19).unwrap();

    let mut fixed = (records.len() as u64).to_le_bytes().to_vec();
    fixed.extend_from_slice(&(packages.len() as u32).to_le_bytes());
    fixed.extend_from_slice(&1u32.to_le_bytes()); // block count
    fixed.extend_from_slice(&(trigrams.len() as u32).to_le_bytes());
    fixed.extend_from_slice(&0u32.to_le_bytes()); // reserved
    fixed.extend_from_slice(&5u32.to_le_bytes()); // section count

    let payloads = [
        (1u16, packages_section),
        (2u16, block_table),
        (3u16, block_compressed),
        (4u16, trigram_section),
        (5u16, postings_section),
    ];

    let mut table = Vec::new();
    let mut offset = (fixed.len() + payloads.len() * 20) as u64;
    for (kind, payload) in &payloads {
        table.extend_from_slice(&kind.to_le_bytes());
        table.extend_from_slice(&0u16.to_le_bytes());
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        offset += payload.len() as u64;
    }

    let mut out = fixed;
    out.extend_from_slice(&table);
    for (_, payload) in &payloads {
        out.extend_from_slice(payload);
    }
    out
}

/// Build the payload of an `index-v2` section holding a single row group.
///
/// Mirrors the Nim writer: interned package sets, column-major storage with
/// the size column split into byte planes, and a trigram index over the groups.
fn index_v2_payload(records: &[IndexRecord]) -> Vec<u8> {
    const COLUMNS: usize = 11;
    const SIZE_PLANES: usize = 5;

    let mut names: Vec<&str> = records.iter().map(|r| r.package).collect();
    names.sort_unstable();
    names.dedup();

    // One interned set per distinct package list; here every record has one
    // package, so a set is a single id.
    let mut sets: Vec<Vec<usize>> = Vec::new();
    let mut set_of = Vec::new();
    for record in records {
        let id = names.iter().position(|n| *n == record.package).unwrap();
        let key = vec![id];
        let index = sets.iter().position(|s| *s == key).unwrap_or_else(|| {
            sets.push(key);
            sets.len() - 1
        });
        set_of.push(index);
    }

    let mut columns: Vec<Vec<u8>> = vec![Vec::new(); COLUMNS];
    let mut previous = "";
    let mut previous_shared: i32 = 0;
    for (i, record) in records.iter().enumerate() {
        let shared = previous
            .char_indices()
            .zip(record.path.char_indices())
            .take_while(|((_, a), (_, b))| a == b)
            .map(|((i, c), _)| i + c.len_utf8())
            .last()
            .unwrap_or(0);
        let diff = shared as i32 - previous_shared;
        if diff > -127 && diff < 127 {
            columns[0].push(diff as u8);
        } else {
            columns[0].push(0x80);
            columns[0].push((diff >> 8) as u8);
            columns[0].push(diff as u8);
        }

        let suffix = &record.path[shared..];
        put_varint(&mut columns[1], suffix.len() as u64);
        columns[2].extend_from_slice(suffix.as_bytes());
        columns[3].push(record.kind as u8 | if record.executable { 4 } else { 0 });

        if record.kind == 0 {
            for plane in 0..SIZE_PLANES {
                columns[4 + plane].push((record.size >> (8 * plane)) as u8);
            }
        }
        if record.kind == 2 {
            put_varint(&mut columns[10], record.target.len() as u64);
            columns[10].extend_from_slice(record.target.as_bytes());
        }
        put_varint(&mut columns[9], set_of[i] as u64);

        previous = record.path;
        previous_shared = shared as i32;
    }

    let mut column_data = Vec::new();
    let mut lengths = [0u32; COLUMNS];
    for (i, column) in columns.iter().enumerate() {
        let compressed = if column.is_empty() {
            Vec::new()
        } else {
            zstd::encode_all(column.as_slice(), 19).unwrap()
        };
        lengths[i] = compressed.len() as u32;
        column_data.extend_from_slice(&compressed);
    }

    // Group directory: one group covering every record, starting at offset 0.
    let mut directory = 0u64.to_le_bytes().to_vec();
    directory.extend_from_slice(&0u32.to_le_bytes());
    directory.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for length in &lengths {
        directory.extend_from_slice(&length.to_le_bytes());
    }

    // Every trigram lands in the only group, so each posting list is [0].
    let mut trigrams: Vec<u32> = Vec::new();
    for record in records {
        for window in record.path.as_bytes().windows(3) {
            trigrams.push(
                (u32::from(window[0]) << 16) | (u32::from(window[1]) << 8) | u32::from(window[2]),
            );
        }
    }
    trigrams.sort_unstable();
    trigrams.dedup();

    let mut postings = Vec::new();
    let mut trigram_raw = (trigrams.len() as u32).to_le_bytes().to_vec();
    for trigram in &trigrams {
        trigram_raw.push((trigram >> 16) as u8);
        trigram_raw.push((trigram >> 8) as u8);
        trigram_raw.push(*trigram as u8);
        trigram_raw.push(0); // flags: not skipped
        trigram_raw.extend_from_slice(&(postings.len() as u64).to_le_bytes()[..5]);
        put_varint(&mut postings, 0);
    }

    let mut names_raw = Vec::new();
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            names_raw.push(b'\n');
        }
        names_raw.extend_from_slice(name.as_bytes());
    }

    let mut sets_raw = Vec::new();
    for ids in &sets {
        put_varint(&mut sets_raw, ids.len() as u64);
        let mut previous = 0usize;
        for id in ids {
            put_varint(&mut sets_raw, (id - previous) as u64);
            previous = *id;
        }
    }

    let zc = |data: &[u8]| -> Vec<u8> {
        if data.is_empty() {
            Vec::new()
        } else {
            zstd::encode_all(data, 19).unwrap()
        }
    };

    let mut fixed = (records.len() as u64).to_le_bytes().to_vec();
    fixed.extend_from_slice(&(names.len() as u32).to_le_bytes());
    fixed.extend_from_slice(&(sets.len() as u32).to_le_bytes());
    fixed.extend_from_slice(&1u32.to_le_bytes()); // group count
    fixed.extend_from_slice(&(trigrams.len() as u32).to_le_bytes());
    fixed.extend_from_slice(&(COLUMNS as u32).to_le_bytes());
    fixed.extend_from_slice(&6u32.to_le_bytes()); // section count

    let payloads = [
        (1u16, zc(&names_raw)),
        (2u16, zc(&sets_raw)),
        (3u16, zc(&directory)),
        (4u16, column_data),
        (5u16, zc(&trigram_raw)),
        (6u16, zc(&postings)),
    ];

    let mut table = Vec::new();
    let mut offset = (fixed.len() + payloads.len() * 20) as u64;
    for (kind, payload) in &payloads {
        table.extend_from_slice(&kind.to_le_bytes());
        table.extend_from_slice(&0u16.to_le_bytes());
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        offset += payload.len() as u64;
    }

    let mut out = fixed;
    out.extend_from_slice(&table);
    for (_, payload) in &payloads {
        out.extend_from_slice(payload);
    }
    out
}

/// Write `bytes` to a temporary file, deleting it on drop.
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

fn options_db(lines: &[&str]) -> Vec<u8> {
    build_db(&[(SCOPE_OPT, ENC_BUCKETS, bucketed_payload(lines))])
}

fn packages_db(lines: &[&str]) -> Vec<u8> {
    build_db(&[(SCOPE_PKG, ENC_BUCKETS, bucketed_payload(lines))])
}

#[test]
fn scopes_are_reported_from_the_section_table() {
    use spam_db::{Scope, SectionEncoding, SpamDb};

    let bytes = build_db(&[
        (SCOPE_PKG, ENC_BUCKETS, bucketed_payload(&["/bin/hello\thello-2.12"])),
        (
            SCOPE_LIB,
            ENC_BUCKETS,
            bucketed_payload(&["lib.mapAttrs\tMap over an attrset\t\tlib/attrsets.nix:1\t0"]),
        ),
    ]);
    let f = TempFile::write("spam_test_scopes.db", &bytes);

    let db = SpamDb::open(f.path()).unwrap();
    assert!(db.has(Scope::Pkg));
    assert!(db.has(Scope::Lib));
    assert!(!db.has(Scope::Opt));
    assert_eq!(
        db.scopes(),
        &[
            (Scope::Pkg, SectionEncoding::Buckets),
            (Scope::Lib, SectionEncoding::Buckets)
        ]
    );
}

#[test]
fn absent_scopes_yield_none_rather_than_an_error() {
    use spam_db::SpamDb;

    let bytes = packages_db(&["/bin/hello\thello-2.12"]);
    let f = TempFile::write("spam_test_absent_scope.db", &bytes);

    let db = SpamDb::open(f.path()).unwrap();
    assert!(db.packages().unwrap().is_some());
    assert!(db.options().unwrap().is_none());
    assert!(db.functions().unwrap().is_none());
}

#[test]
fn each_scope_reads_only_its_own_section() {
    use spam_db::SpamDb;

    // Placing pkg after opt means a reader that ignored section offsets would
    // decode the wrong bytes here.
    let bytes = build_db(&[
        (
            SCOPE_OPT,
            ENC_BUCKETS,
            bucketed_payload(&["services.nginx.enable\tWhether to enable nginx"]),
        ),
        (SCOPE_PKG, ENC_BUCKETS, bucketed_payload(&["/bin/hello\thello-2.12"])),
        (
            SCOPE_LIB,
            ENC_BUCKETS,
            bucketed_payload(&["lib.mapAttrs\tMap over an attrset\ta -> b\tlib/attrsets.nix:7\t0"]),
        ),
    ]);
    let f = TempFile::write("spam_test_multi_scope.db", &bytes);
    let db = SpamDb::open(f.path()).unwrap();

    let options = db.options().unwrap().unwrap();
    assert_eq!(options.query("nginx").unwrap()[0].name, "services.nginx.enable");

    let packages = db.packages().unwrap().unwrap();
    assert_eq!(packages.query("/bin/").unwrap()[0].path, "/bin/hello");

    let functions = db.functions().unwrap().unwrap();
    let found = functions.query("mapAttrs").unwrap();
    assert_eq!(found[0].name, "lib.mapAttrs");
    assert_eq!(found[0].type_signature.as_deref(), Some("a -> b"));
    assert_eq!(found[0].location, "lib/attrsets.nix:7");
    assert!(!found[0].deprecated);
}

#[test]
fn options_query_finds_matching_record() {
    let bytes = options_db(&[
        "boot.loader.grub.enable\tWhether to enable GRUB",
        "services.nginx.enable\tWhether to enable nginx",
    ]);
    let f = TempFile::write("spam_test_options_query.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();

    let results = db.query("boot").unwrap();
    assert!(!results.is_empty(), "expected results for \"boot\"");
    assert_eq!(results[0].name, "boot.loader.grub.enable");
    assert_eq!(results[0].summary.as_deref(), Some("Whether to enable GRUB"));
}

#[test]
fn options_query_results_all_contain_query() {
    let bytes = options_db(&[
        "services.nginx.enable\tWhether to enable nginx",
        "services.nginx.port\tHTTP port",
        "boot.loader.grub.enable\tWhether to enable GRUB",
    ]);
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
    let bytes = options_db(&["boot.loader.grub.enable\t"]);
    let f = TempFile::write("spam_test_options_empty.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    let _ = db.query("").unwrap();
}

#[test]
fn options_query_no_results_for_impossible_string() {
    let bytes = options_db(&["boot.loader.grub.enable\tWhether to enable GRUB"]);
    let f = TempFile::write("spam_test_options_nomatch.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    assert!(db.query("ZZZNOMATCHZZZ").unwrap().is_empty());
}

#[test]
fn options_record_without_summary() {
    let bytes = options_db(&["boot.loader.grub.enable"]);
    let f = TempFile::write("spam_test_options_nosummary.db", &bytes);
    let db = spam_db::OptionsDb::open(f.path()).unwrap();
    let results = db.query("boot").unwrap();
    assert!(!results.is_empty());
    assert!(results[0].summary.is_none());
}

#[test]
fn packages_query_finds_matching_record() {
    let bytes = packages_db(&["/bin/hello\thello-2.12", "/lib/libfoo.so\tfoo-1.0"]);
    let f = TempFile::write("spam_test_pkg_query.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/").unwrap();
    assert!(!results.is_empty(), "expected results for \"/bin/\"");
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].packages, vec!["hello-2.12"]);

    // Manifest records carry no metadata.
    assert_eq!(results[0].size, 0);
    assert!(!results[0].executable);
    assert_eq!(results[0].target, "");
}

#[test]
fn packages_query_multiple_owners() {
    let bytes = packages_db(&["/bin/sh\tbash-5.2,busybox-1.36"]);
    let f = TempFile::write("spam_test_pkg_multi.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/sh").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].packages, vec!["bash-5.2", "busybox-1.36"]);
}

#[test]
fn packages_query_extended_format_with_metadata() {
    use spam_db::packages::FileKind;

    // Extended format: path\tkind\tsize\texec\ttarget\tpkg1,pkg2,...
    let bytes = packages_db(&[
        "/bin/hello\tr\t29488\t1\t\thello-2.12",
        "/lib/libfoo.so\tr\t153600\t0\t\tfoo-1.0",
        "/etc/symlink\ts\t0\t0\t/bin/hello\thello-2.12",
    ]);
    let f = TempFile::write("spam_test_pkg_extended.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/hello").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].size, 29488);
    assert!(results[0].executable);
    assert_eq!(results[0].packages, vec!["hello-2.12"]);

    let sym = db.query("/etc/symlink").unwrap();
    assert_eq!(sym.len(), 1);
    assert_eq!(sym[0].target, "/bin/hello");
    assert_eq!(sym[0].kind, FileKind::Symlink);
}

#[test]
fn index_v1_query_returns_full_metadata() {
    use spam_db::packages::FileKind;

    let payload = index_v1_payload(&[
        IndexRecord {
            path: "/bin/hello",
            package: "hello-2.12",
            size: 29488,
            kind: 0,
            executable: true,
            target: "",
        },
        IndexRecord {
            path: "/bin/hello-link",
            package: "hello-2.12",
            size: 0,
            kind: 2,
            executable: false,
            target: "/bin/hello",
        },
        IndexRecord {
            path: "/lib/libfoo.so",
            package: "foo-1.0",
            size: 153600,
            kind: 0,
            executable: false,
            target: "",
        },
    ]);
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V1, payload)]);
    let f = TempFile::write("spam_test_indexv1.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/hello").unwrap();
    assert_eq!(results.len(), 2, "prefix matches both hello entries");
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].size, 29488);
    assert!(results[0].executable);
    assert_eq!(results[0].packages, vec!["hello-2.12"]);
    assert_eq!(results[1].path, "/bin/hello-link");
    assert_eq!(results[1].kind, FileKind::Symlink);
    assert_eq!(results[1].target, "/bin/hello");

    let libs = db.query("libfoo").unwrap();
    assert_eq!(libs.len(), 1);
    assert_eq!(libs[0].packages, vec!["foo-1.0"]);
    assert_eq!(libs[0].size, 153600);
}

#[test]
fn index_v1_query_shorter_than_a_trigram_scans_every_block() {
    let payload = index_v1_payload(&[IndexRecord {
        path: "/bin/hello",
        package: "hello-2.12",
        size: 1,
        kind: 0,
        executable: true,
        target: "",
    }]);
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V1, payload)]);
    let f = TempFile::write("spam_test_indexv1_short.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert_eq!(db.query("he").unwrap().len(), 1);
}

#[test]
fn index_v1_query_with_an_unknown_trigram_matches_nothing() {
    let payload = index_v1_payload(&[IndexRecord {
        path: "/bin/hello",
        package: "hello-2.12",
        size: 1,
        kind: 0,
        executable: true,
        target: "",
    }]);
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V1, payload)]);
    let f = TempFile::write("spam_test_indexv1_miss.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("ZZZNOMATCHZZZ").unwrap().is_empty());
}

fn v2_sample() -> Vec<IndexRecord> {
    vec![
        IndexRecord {
            path: "/bin/hello",
            package: "hello-2.12",
            size: 29488,
            kind: 0,
            executable: true,
            target: "",
        },
        IndexRecord {
            path: "/bin/hello-link",
            package: "hello-2.12",
            size: 0,
            kind: 2,
            executable: false,
            target: "/bin/hello",
        },
        IndexRecord {
            path: "/lib",
            package: "foo-1.0",
            size: 0,
            kind: 1,
            executable: false,
            target: "",
        },
        IndexRecord {
            path: "/lib/libfoo.so",
            package: "foo-1.0",
            size: 153600,
            kind: 0,
            executable: false,
            target: "",
        },
    ]
}

#[test]
fn index_v2_query_returns_full_metadata() {
    use spam_db::packages::FileKind;

    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V2, index_v2_payload(&v2_sample()))]);
    let f = TempFile::write("spam_test_indexv2.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("/bin/hello").unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].path, "/bin/hello");
    assert_eq!(results[0].size, 29488);
    assert!(results[0].executable);
    assert_eq!(results[0].kind, FileKind::Regular);
    assert_eq!(results[0].packages, vec!["hello-2.12"]);
    assert_eq!(results[1].path, "/bin/hello-link");
    assert_eq!(results[1].kind, FileKind::Symlink);
    assert_eq!(results[1].target, "/bin/hello");
    assert_eq!(results[1].size, 0);

    // A directory carries no size and no target, and contributes nothing to
    // either column; the row cursors still have to stay aligned across it.
    let libs = db.query("/lib").unwrap();
    assert_eq!(libs.len(), 2);
    assert_eq!(libs[0].kind, FileKind::Directory);
    assert_eq!(libs[0].size, 0);
    assert_eq!(libs[1].path, "/lib/libfoo.so");
    assert_eq!(libs[1].size, 153600);
    assert_eq!(libs[1].packages, vec!["foo-1.0"]);
}

#[test]
fn index_v2_reports_its_encoding() {
    use spam_db::{Scope, SectionEncoding, SpamDb};

    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V2, index_v2_payload(&v2_sample()))]);
    let f = TempFile::write("spam_test_indexv2_encoding.db", &bytes);
    let db = SpamDb::open(f.path()).unwrap();
    assert_eq!(db.scopes(), &[(Scope::Pkg, SectionEncoding::IndexV2)]);
}

#[test]
fn index_v2_query_shorter_than_a_trigram_scans_every_group() {
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V2, index_v2_payload(&v2_sample()))]);
    let f = TempFile::write("spam_test_indexv2_short.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert_eq!(db.query("he").unwrap().len(), 2);
}

#[test]
fn index_v2_query_with_an_unknown_trigram_matches_nothing() {
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V2, index_v2_payload(&v2_sample()))]);
    let f = TempFile::write("spam_test_indexv2_miss.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    assert!(db.query("ZZZNOMATCHZZZ").unwrap().is_empty());
}

#[test]
fn index_v2_multi_byte_paths_survive_prefix_deltas() {
    let records = vec![
        IndexRecord {
            path: "/\u{1D51E}",
            package: "unicode-1.0",
            size: 1,
            kind: 0,
            executable: false,
            target: "",
        },
        IndexRecord {
            path: "/\u{1D51F}",
            package: "unicode-1.0",
            size: 2,
            kind: 0,
            executable: false,
            target: "",
        },
    ];
    let bytes = build_db(&[(SCOPE_PKG, ENC_INDEX_V2, index_v2_payload(&records))]);
    let f = TempFile::write("spam_test_indexv2_unicode.db", &bytes);
    let db = spam_db::PackagesDb::open(f.path()).unwrap();

    let results = db.query("\u{1D51F}").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/\u{1D51F}");
    assert_eq!(results[0].size, 2);
}

#[test]
fn opening_a_scope_the_database_lacks_is_an_error() {
    let bytes = options_db(&["boot.loader.grub.enable\t"]);
    let f = TempFile::write("spam_test_wrong_scope.db", &bytes);

    let err = spam_db::PackagesDb::open(f.path())
        .expect_err("PackagesDb::open should fail without a pkg section");
    assert!(
        err.to_string().contains("pkg"),
        "error should mention 'pkg', got: {err}"
    );
}

#[test]
fn legacy_v1_databases_still_open() {
    use spam_db::{Scope, SpamDb};

    let bytes = build_legacy_db(
        "options",
        &bucketed_payload(&["boot.loader.grub.enable\tWhether to enable GRUB"]),
    );
    let f = TempFile::write("spam_test_legacy.db", &bytes);

    let db = SpamDb::open(f.path()).unwrap();
    assert!(db.has(Scope::Opt));
    let options = db.options().unwrap().unwrap();
    assert_eq!(options.query("grub").unwrap()[0].name, "boot.loader.grub.enable");
}

#[test]
fn invalid_header_returns_error() {
    let f = TempFile::write("spam_test_bad_header.db", b"not a spam database\n");
    let err = spam_db::SpamDb::open(f.path()).expect_err("should fail on bad header");
    assert!(err.to_string().contains("invalid database"));
}

#[test]
fn a_section_reaching_past_the_payload_is_rejected() {
    let mut bytes = Vec::new();
    bytes.write_all(b"# spam-db-v2\n").unwrap();
    bytes.write_all(&1u32.to_le_bytes()).unwrap();
    bytes.write_all(&SCOPE_PKG.to_le_bytes()).unwrap();
    bytes.write_all(&ENC_BUCKETS.to_le_bytes()).unwrap();
    bytes.write_all(&0u64.to_le_bytes()).unwrap();
    bytes.write_all(&4096u64.to_le_bytes()).unwrap();
    bytes.write_all(b"short").unwrap();

    let f = TempFile::write("spam_test_oob_section.db", &bytes);
    let err = spam_db::SpamDb::open(f.path()).expect_err("should reject an out-of-bounds section");
    assert!(err.to_string().contains("out of bounds"), "got: {err}");
}

#[test]
fn two_sections_for_one_scope_are_rejected() {
    let payload = bucketed_payload(&["/bin/hello\thello-2.12"]);
    let bytes = build_db(&[
        (SCOPE_PKG, ENC_BUCKETS, payload.clone()),
        (SCOPE_PKG, ENC_BUCKETS, payload),
    ]);
    let f = TempFile::write("spam_test_dup_scope.db", &bytes);

    let err = spam_db::SpamDb::open(f.path()).expect_err("should reject a duplicate scope");
    assert!(err.to_string().contains("duplicate"), "got: {err}");
}
