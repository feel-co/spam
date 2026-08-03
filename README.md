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

Sections use one of two encodings. `buckets` is 256 zstd blobs indexed by every
distinct byte of the record key, used for options, library functions and
manifest-built package sections. `index-v1` is the blocked, prefix-delta encoded
record format with a trigram index, used for the nixpkgs package section.

Single-kind `# spam-db-v1` databases written by earlier releases are still read,
as one synthesised section.

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
