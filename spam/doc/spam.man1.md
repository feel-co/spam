% spam(1)

# NAME

spam - a utility to search nix packages and module options

# SYNOPSIS

`spam <`[`opt`](#option-search)`|`[`pkg`](#package-search)`> [--json]`

`spam db build --manifest [packages.json] --output [files.db] [--json]`

`spam db build --manifest [options.json] --output [options.db] [--json]`

# OPTIONS
`-h, --help`
: Display help message

`--json`
: Output results in JSON format

`--db`
: Path to a generated database. Defaults to `$XDG_CACHE_HOME/spam/files.db`.

# OPTION SEARCH

## SYNOPSIS

`spam opt --module-options [options.json] [SEARCH STRING]`

`spam opt --db [options.db] [SEARCH STRING]`

## `options.json`
Path to the JSON options file from `nixosOptionsDoc`.

# PACKAGE SEARCH

## SYNOPSIS

`spam pkg --db [files.db] [SEARCH STRING]`

Searches a generated package file database. Matches are substring matches against
store-output-relative paths, so `bin/foo` matches `/bin/foo`.

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

# BUGS

https://github.com/feel-co/spam/issues
