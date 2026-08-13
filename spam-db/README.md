# spam-db

Rust library for reading [spam](https://github.com/feel-co/spam) databases. SPAM
indexes Nix package closures, `nixosOptionsDoc` output and documented Nix
library functions into compressed databases. This crate lets you open those
databases and run substring queries against them.

## Usage

```toml
[dependencies]
spam-db = "0.3.0"
```

A database holds up to three independent sections, one per scope: `pkg` for
package file paths, `opt` for NixOS module options, and `lib` for documented
library functions. A query touches only the section of the scope it asks for.

### Query the scopes a database happens to carry

```rust
use spam_db::SpamDb;

let db = SpamDb::open("spam.db")?;

if let Some(pkg) = db.packages()? {
    for rec in pkg.query("/bin/")? {
        println!("{} -> {}", rec.path, rec.packages.join(", "));
    }
}

if let Some(opt) = db.options()? {
    for rec in opt.query("services.nginx")? {
        println!("{}", rec.name);
    }
}

if let Some(lib) = db.functions()? {
    for rec in lib.query("mapAttrs")? {
        println!("{} at {}", rec.name, rec.location);
    }
}
```

### Open a single scope directly

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

`PackagesDb::open` and `FunctionsDb::open` behave the same way, and fail if the
database has no section for that scope.

## Database format

<!--markdownlint-disable MD013-->

```plaintext
"# spam-db-v2\n"
[u32le section count]
[count x 20-byte entries: (scope: u16le, encoding: u16le, offset: u64le, length: u64le)]
[section payloads, in table order]
```

<!--markdownlint-enable MD013-->

Section offsets are relative to the first payload byte. Two encodings exist.

`Buckets` is a 256-bucket layout, used for options, library functions and
package sections built from a local manifest:

```plaintext
[256 x 16-byte index entries: (offset: u64le, length: u64le)]
[concatenated zstd-compressed bucket blobs]
```

Each record is placed in every bucket corresponding to a unique byte of its
search key. Queries decompress only the bucket for `query[0]`, keeping lookup
sublinear in the total section size.

`IndexV2` is used for the package section of a nixpkgs index. Records are
grouped into row groups, and each group stores every column in its own zstd
frame: prefix-delta path columns, a flags byte, the file size split into five
byte planes, an interned package-set id, and symlink targets. A trigram index
over the groups narrows the candidate set, and because matching only needs the
three path columns, the size, package and target columns of a group are
decompressed solely when that group contains a hit. `IndexV1`, indicated by
`# spam-db-v1`, is the earlier row-major format, still read (as one synthesised
section) so existing databases keep working. Records are prefix-delta encoded
into zstd blocks of roughly 128 KiB with a trigram index over the blocks.

In both, trigrams appearing in too many blocks or groups are marked skipped and
carry no postings, since intersecting them would cost more than it saves.

## Building spam databases

Use the [spam CLI](https://github.com/feel-co/spam):

```bash
spam index --nixpkgs '<nixpkgs>' --output spam.db
spam index --manifest packages.json --nix ./lib --prefix lib --output all.db
spam index --options options.json --output options.db
```
