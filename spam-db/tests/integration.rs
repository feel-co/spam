use std::{collections::HashSet, io::Write};

/// Build a raw spam database in memory.
///
/// `kind` must be `"options"` or `"packages"`. `lines` are the raw
/// tab-separated records that will be placed into the appropriate buckets.
fn build_db(kind: &str, lines: &[&str]) -> Vec<u8> {
  const BUCKETS: usize = 256;
  const ENTRY_SIZE: usize = 8;

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
    let offset = data.len() as u32;
    let length: u32;
    if bucket.is_empty() {
      length = 0;
    } else {
      let text = format!("{}\n", bucket.join("\n"));
      let compressed = zstd::encode_all(text.as_bytes(), 3).unwrap();
      length = compressed.len() as u32;
      data.extend_from_slice(&compressed);
    }
    let base = i * ENTRY_SIZE;
    index[base..base + 4].copy_from_slice(&offset.to_le_bytes());
    index[base + 4..base + 8].copy_from_slice(&length.to_le_bytes());
  }

  let header = format!("# spam-db-v1\t{kind}\n");
  let mut out = Vec::new();
  out.write_all(header.as_bytes()).unwrap();
  out.write_all(&index).unwrap();
  out.write_all(&data).unwrap();
  out
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
  let err =
    spam_db::SpamDb::open(f.path()).expect_err("should fail on bad header");
  assert!(err.to_string().contains("invalid database"));
}
