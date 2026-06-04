% spam(1)

# NAME

spam - a utility to search nix packages and module options

# SYNOPSIS

`spam <`[`opt`](#option-search)`|`[`pkg`](#package-search)`> [--json]`

`spam db build --manifest [packages.json] --output [files.db] [--json]`

`spam db build --manifest [options.json] --output [options.db] [--json]`

`spam index [--output` _files.db_ `] [--nixpkgs` _path_ `] [--system` _system_ `]`
`          [--scope` _attr_ `] [--concurrent` _n_ `] [--no-follow-refs] [--verbose]`

# OPTIONS
`-h, --help`
: Display help message

`--json`
: Output results in JSON format

`--db`
: Path to a generated database. Defaults to `$XDG_CACHE_HOME/spam/files.db`.

`--verbose`
: Print progress to stderr.

# OPTION SEARCH

## SYNOPSIS

`spam opt --module-options [options.json] [SEARCH STRING]`

`spam opt --db [options.db] [SEARCH STRING]`

## `options.json`
Path to the JSON options file from `nixosOptionsDoc`.

# PACKAGE SEARCH

## SYNOPSIS

`spam pkg --db [files.db] [SEARCH STRING]`

Searches a package-manifest database from `spam db build` or an autonomous index
from `spam index`. Matches are substring matches against store-output-relative
paths, so `bin/foo` matches `/bin/foo`.

# DATABASE GENERATION

## SYNOPSIS

`spam db build --manifest [packages.json] --output [files.db] [--json]`

Builds a compact file database from a JSON manifest of already-realized store
outputs. Store hashes are not recorded; paths are stored relative to each output
and deduplicated across packages.

If the manifest is an `options.json` produced by `nixosOptionsDoc`, `spam`
builds an option database instead. The generated option database keeps option
names and compact summaries, not the full source JSON.

Supported manifest shapes:

```json
[
  {
    "attr": "hello",
    "pname": "hello",
    "version": "2.12",
    "outputs": {
      "out": "/nix/store/...-hello-2.12"
    }
  }
]
```

```json
{
  "hello": "/nix/store/...-hello-2.12",
  "git": {
    "out": "/nix/store/...-git-2.51.0",
    "man": "/nix/store/...-git-2.51.0-man"
  }
}
```

# AUTONOMOUS INDEXING

## SYNOPSIS

`spam index [--output [files.db]] [--nixpkgs [path]] [--cache-url` _url_ `]`
`          [--system [system]] [--scope [attr]] [--concurrent [n]]`
`          [--no-follow-refs] [--verbose]`

Enumerates packages from nixpkgs via `nix-env -qaP --xml --out-path`, then
fetches file listings from a Nix binary cache (default: https://cache.nixos.org)
using BFS reference traversal. Produces an autonomous index database usable with
`spam pkg`.

Equivalent to `nix-index`, but uses spam's bucket-indexed zstd-compressed
database for faster queries.

## Options

`--output [files.db]`
: Database output path. Defaults to the `--db` path.

`--nixpkgs [path]`
: Nixpkgs path or expression for `nix-env -f`. Defaults to `<nixpkgs>`.

`--cache-url` _url_
: Binary cache URL. Defaults to `https://cache.nixos.org`.

`--system [system]`
: Override the target system (e.g. `x86_64-linux`).

`--scope [attr]`
: Limit indexing to a single attr set (e.g. `python3Packages`).

`--concurrent [n]`
: Maximum parallel HTTP requests (default: 32).

`--no-follow-refs`
: Only index direct package outputs; skip transitive store reference
  traversal. Much faster. Enabled by default.

`--verbose`
: Print progress to stderr.

# BUGS

https://github.com/feel-co/spam/issues
