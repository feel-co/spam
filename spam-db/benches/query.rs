use std::{hint::black_box, path::PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};

fn env_path(name: &str) -> Option<PathBuf> {
  let path = std::env::var_os(name).map(PathBuf::from)?;
  if path.exists() {
    Some(path)
  } else {
    eprintln!("{name} points to a missing path: {}", path.display());
    None
  }
}

fn bench_package_query(c: &mut Criterion) {
  let Some(path) = env_path("SPAM_BENCH_PACKAGES_DB") else {
    eprintln!("skipping package query benchmark: SPAM_BENCH_PACKAGES_DB is not set");
    return;
  };
  let query = std::env::var("SPAM_BENCH_PACKAGES_QUERY")
    .unwrap_or_else(|_| "/bin/hello".to_owned());
  let db = spam_db::PackagesDb::open(&path).unwrap();

  c.bench_function("packages query", |b| {
    b.iter(|| db.query(black_box(query.as_str())).unwrap())
  });
}

fn bench_options_query(c: &mut Criterion) {
  let Some(path) = env_path("SPAM_BENCH_OPTIONS_DB") else {
    eprintln!("skipping options query benchmark: SPAM_BENCH_OPTIONS_DB is not set");
    return;
  };
  let query = std::env::var("SPAM_BENCH_OPTIONS_QUERY")
    .unwrap_or_else(|_| "services".to_owned());
  let db = spam_db::OptionsDb::open(&path).unwrap();

  c.bench_function("options query", |b| {
    b.iter(|| db.query(black_box(query.as_str())).unwrap())
  });
}

criterion_group!(benches, bench_package_query, bench_options_query);
criterion_main!(benches);
