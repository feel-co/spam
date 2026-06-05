# spam-db

Rust library for reading [spam](https://github.com/feel-co/spam) databases.

SPAM indexes Nix package closures and `nixosOptionsDoc` output into compressed,
bucket-indexed databases. This crate lets you open those databases and run
substring queries against them.

## Usage

```toml
[dependencies]
spam-db = "0.2"
```

### Query an options database

```rust
use spam_db::OptionsDb;

let db = OptionsDb::open("options.db")?;
for rec in db.query("services.nginx")? {
    println!("{}", rec.name);
    if let Some(summary) = rec.summary {
        println!("  {summary}");
    }
}
```

### Query a packages database

```rust
use spam_db::PackagesDb;

let db = PackagesDb::open("files.db")?;
for rec in db.query("/bin/")? {
    println!("{} -> {}", rec.path, rec.packages.join(", "));
}
```

### Auto-detect database kind

```rust
use spam_db::SpamDb;

match SpamDb::open("unknown.db")? {
    SpamDb::Options(db) => { /* ... */ }
    SpamDb::Packages(db) => { /* ... */ }
    SpamDb::Index(db) => { /* ... */ }
}
```

## Database format

`options` and `packages` databases are bucket-indexed binary files:

```plaintext
# spam-db-v1\t{options|packages}\n
[256 x 16-byte index entries: (offset: u64le, length: u64le)]
[concatenated zstd-compressed bucket blobs]
```

Each line in the database is placed in every bucket corresponding to a unique
byte in its search key. Queries decompress only the bucket for `query[0]`,
keeping lookup sublinear in the total database size.

`index` databases are autonomous package indexes:

```plaintext
# spam-db-v1\tindex\n
[sectioned package string table, record blocks, trigram dictionary, postings]
```

The index stores package names once, keeps paths in independently decodable
front-coded record blocks, and uses a compact byte-trigram-to-block index to
avoid full-index scans for substring queries.

The `packages` kind is produced by `spam db build` from local package manifests.
The `index` kind is produced by `spam index` from nixpkgs and binary-cache file
listings. `PackagesDb` can query both kinds, but consumers can distinguish them
with `SpamDb::kind()`.

## Building spam databases

Use the [spam CLI](https://github.com/feel-co/spam):

```bash
spam db build --manifest packages.json --output files.db
spam db build --manifest options.json --output options.db
```
