## File metadata types for extended package file records.
##
## nix-index stores per-file: path, size, executable bit, symlink target, file kind.
## This module mirrors that capability for spam's package database.

import std/[sequtils, strutils]

type
  FileKind* = enum
    fkRegular = "r"
    fkDirectory = "d"
    fkSymlink = "s"

  FileEntry* = object
    ## A single file entry within a Nix store output.
    path*: string
      ## Path relative to the store output root, e.g. "/bin/hello".
    size*: uint64
      ## File size in bytes; 0 for directories and symlinks.
    kind*: FileKind
      ## File type.
    executable*: bool
      ## True if the file has the executable bit set (only meaningful for fkRegular).
    target*: string
      ## Symlink target; only set when kind == fkSymlink.
    packages*: seq[string]
      ## Package names that ship this entry (may be multiple via hardlinks).

proc encodeEntry*(e: FileEntry): string =
  ## Encode a FileEntry to a tab-separated database line:
  ##   path\tkind\tsize\texec\ttarget\tpkg1,pkg2,...
  ##
  ## This is the format written by writePackagesDatabase / read by parsePackages.
  let execFlag = if e.executable: "1" else: "0"
  e.path & "\t" & $e.kind & "\t" & $e.size & "\t" & execFlag & "\t" &
    e.target & "\t" & e.packages.join(",")

proc decodeEntry*(line: string): FileEntry =
  ## Decode a tab-separated database line back to a FileEntry.
  ## Falls back gracefully for legacy lines (path\tpkg1,pkg2,...).
  ## Returns a zero-value FileEntry (empty path) for blank or single-field lines;
  ## callers should skip entries where path.len == 0.
  if line.len == 0:
    return
  let parts = line.split('\t')
  if parts.len >= 6:
    # New extended format
    let kind = case parts[1]
      of "d": fkDirectory
      of "s": fkSymlink
      else: fkRegular
    result = FileEntry(
      path: parts[0],
      kind: kind,
      size: try: parseUInt(parts[2]) except: 0'u64,
      executable: parts[3] == "1",
      target: parts[4],
      packages: parts[5].split(',').filterIt(it.len > 0),
    )
  elif parts.len >= 2:
    # Legacy format: path\tpkg1,pkg2,...
    result = FileEntry(
      path: parts[0],
      kind: fkRegular,
      packages: parts[1].split(',').filterIt(it.len > 0),
    )
