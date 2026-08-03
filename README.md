# spam

**S**earch **P**ackages **A**nd **M**odule options in the wider Nix ecosystem.

spam indexes Nix package closures, `nixosOptionsDoc` output and documented Nix
library functions into one zstd-compressed database. Given a substring, it finds
which packages own matching files, which module options match a name, or which
library functions are documented under one.

```bash
# Search every scope the database has
$ spam search ripgrep

# Search one scope
$ spam search --lib mapAttrs

# Search several
$ spam search --scope pkg,opt firewall
```

## `search`

`spam search` reads the database at `--db`, defaulting to
`$XDG_CACHE_HOME/spam/spam.db`. With no scope selected it covers everything the
database carries; `--scope` takes a comma-separated list or `all`, and `--pkg`,
`--opt` and `--lib` are shorthand for adding one scope to it.

Package matches are substring matches against store-output-relative paths, so
`bin/foo` matches `/bin/foo`. Option and library matches are substring matches
against the option or attribute name.

```bash
# Which package ships this file
$ spam search --pkg libfoo.so

# JSON, keyed by scope
$ spam search --json --pkg /bin/foo
```

Two options search a source directly instead of a database, which is the mode
intended for files you are working on. Either one implies its own scope, so no
`--scope` is needed alongside it.

```bash
# Scan Nix files directly, works on files that do not evaluate yet
$ spam search --nix ./lib --prefix lib concatMapStrings

# Search an options.json without building a database first
$ spam search --module-options options.json services.nginx
```

## `index`

`spam index` writes one database. Each source contributes one scope, and several
may be combined into a single file.

```bash
# Index nixpkgs: packages, options and library functions
$ spam index --nixpkgs '<nixpkgs>' --output nixpkgs.db

# Just the parts you want
$ spam index --nixpkgs '<nixpkgs>' --scope pkg,lib --output nixpkgs.db

# Local sources, combined
$ spam index --manifest packages.json --nix ./lib --prefix lib --output all.db

# One scope at a time
$ spam index --options options.json --output options.db
```

`--nixpkgs` draws each scope from a different place: packages are enumerated
with `nix-env -qaP --xml --out-path` and their file listings fetched from a Nix
binary cache, library functions are scanned out of the tree's `lib` directory,
and module options come from a `nixosOptionsDoc` build. The last of those
evaluates the whole module system, so it is by far the slowest part; `--scope`
narrows the set when you do not need it.

`--manifest` indexes the file paths of already-realized store outputs. Store
hashes are not recorded; paths are stored relative to each output and
deduplicated across packages. Accepted shapes:

- Array of objects with attr, pname, version, and outputs
- Object mapping attr to a store path string
- Object mapping attr to an object with named output paths

Options that only affect `--nixpkgs`: `--cache-url`, `--system`, `--attr-set`
(limit to a single attr set), `--attrs` (an explicit comma-separated attr list,
for bounded benchmarks), `--concurrent`, and `--no-follow-refs`.

### Library function coverage

[RFC 145]: https://github.com/NixOS/rfcs/blob/master/rfcs/0145-doc-strings.md
[nixdoc]: https://github.com/feel-co/nixdoc

The `lib` scope covers Nix library functions documented with [RFC 145]
`/** ... */` doc comments. Comments are parsed by [nixdoc]; spam supplies the
lexical scan that finds them in Nix source and binds each to the attribute it
documents. Because it is lexical rather than an evaluation, it works on files
that do not evaluate yet. The scan sees only the binding site, so
`lib/strings.nix` yields `concatStrings` rather than
`lib.strings.concatStrings`. `--prefix` supplies the enclosing attribute path.

Doc comments that document no binding, i.e., a file-level comment above
`{ lib }:`, or a comment on a lambda parameter are not indexed since there is no
attribute name to record them under. On nixpkgs' `lib` this reaches **488 of the
490 bindable doc comments**. Which is pretty good.

## Database format

A database is a `# spam-db-v2` header followed by a section table and one
section per scope, so a scoped search reads only the bytes belonging to that
scope.

```text
"# spam-db-v2\n"
u32                section count
section table      count x { u16 scope, u16 encoding, u64 offset, u64 length }
payload            sections in table order
```

Sections use one of three encodings. `buckets` is 256 zstd blobs indexed by
every distinct byte of the record key, used for options, library functions and
manifest-built package sections. `index-v2` is the column-major format described
below, used for the nixpkgs package section. `index-v1`, the earlier blocked
row-major format, is still read so existing databases keep working.

> [!TIP]
> Single-kind `# spam-db-v1` databases written by earlier releases are still
> read, as one synthesised section.

### The package index

Package records are grouped into row groups of 65536, and each group stores
every column in its own zstd frame at level 22:

```text
fixed header      record, package, group and trigram counts
section table     count x { u16 kind, u16 0, u64 offset, u64 length }
package names     newline separated, zstd
package sets      per set: varint count, delta varint package ids, zstd
group directory   per group: u64 data offset, u32 first record, u32 count,
                  then one u32 compressed length per column
column data       per group, one zstd frame per column, in column order
trigram table     per trigram: 3 bytes trigram, u8 flags, 5 bytes postings
                  offset; a list ends where the next one begins
postings          delta varint group ids, zstd
```

The row-major predecessor mixed each record's path text, size, flags and package
ids into one frame, so the compressor never saw a homogeneous stream. Splitting
the columns fixes that, and three further things follow from it:

- The size column is transposed into byte planes. The high planes of a file size
  distribution are nearly all zero, so they collapse. Interleaved, sizes were
  30% of the whole file, the largest column after the path suffixes.
- Only regular files carry a size and only symlinks a target, so no placeholders
  are stored for the rest.
- The set of packages shipping a path is interned once and referenced by id,
  rather than repeating a list per record.

The layout also makes matching cheaper than a single mixed stream can be. Only
the three path columns are needed to evaluate a substring query, so the size,
package and target columns of a group are decompressed solely when that group
contains a hit.

### Measurements

Against nix-index, encoding its frcode-plus-one-zstd-22 stream format over an
identical record set drawn from the nixpkgs `.ls` corpus. Bytes per (path,
package) entry, lower is better:

| packages | entries | nix-index | index-v1 | index-v2  |
| -------- | ------- | --------- | -------- | --------- |
| 12000    | 3.26M   | 4.312     | 6.683    | **3.926** |
| 40000    | 12.57M  | 3.136     | 5.924    | **2.883** |

That is 8.9% and 8.1% under nix-index, while still carrying a trigram index that
nix-index has no equivalent of.

Over the whole 25.9M-entry corpus, v2 is **40.5% smaller than v1** at the same
record set, and larger row groups push that further.

The row group size is the one real knob. Bigger groups compress better but cost
more to read, since a group is the unit a query decodes. On the 40000-package
set:

| records per group | B/entry | vs nix-index |
| ----------------- | ------- | ------------ |
| 65536             | 3.191   | +1.7%        |
| 262144 (default)  | 2.883   | -8.1%        |
| 524288            | 2.767   | -11.8%       |
| 1048576           | 2.682   | -14.5%       |

Read cost, however, moves the other way. Broad(er) query mixes that lands in
nearly every group runs about a third slower at 262144 than at 65536. Selective
queries, the normal case, touch few groups and are barely affected. The default
sits where the format is comfortably under nix-index at every scale measured
without paying for the last few percent. The group size is a writer-side choice
only. Each group's size is recorded in the directory, so changing it does not
change the format or break existing databases.

## Building

[feel-co/nixdoc]: https://github.com/feel-co/nixdoc

Requires Nim >= 2.2.0, libzstd, libbrotlidec, and `libnixdoc` from
[feel-co/nixdoc] (built by the flake as the `nixdoc-ffi` package).

```bash
# Compile the project
$ nimble build
```

Release build:

```bash
# Release build with optimizations
$ nimble release
```

Nix:

```bash
# Build via Nix flake
$ nix build
```

## Pre-built indexes

[Actions tab]: https://github.com/feel-co/spam/actions/workflows/auto-index.yml

Weekly database indexes are generated by CI for all supported systems. You can
download them from the [Actions tab] under the most recent successful
`auto-index` run. Each system's index is uploaded as a separate artifact
(`spam-index-x86_64-linux`, `spam-index-aarch64-linux`, etc.). Artifacts are
retained for 90 days. To use a downloaded index:

```bash
# Point spam at the downloaded database
$ spam search --db ./spam-index-x86_64-linux <query>
```

> [!NOTE]
> Linux indexes carry all three scopes. The Darwin index carries `pkg` and `lib`
> only, since there is no NixOS module system to enumerate options from.

You may also generate the indexes yourself, however, keep in mind that it is
rather RAM intensive and might run your system out of memory.
