## Round-trip tests for the v2 column-major package index.

import std/[algorithm, os, strutils, unittest]
import dbformat
import filemeta
import indexv2

proc entry(path: string, packages: seq[string], size = 0'u64,
    kind = fkRegular, executable = false, target = ""): FileEntry =
  FileEntry(path: path, packages: packages, size: size, kind: kind,
    executable: executable, target: target)

proc roundTrip(records: seq[FileEntry], query: string, dbPath: string,
    groupRecords = IndexV2GroupRecords): seq[FileEntry] =
  var assembler = initDatabaseAssembler()
  defer: assembler.cleanup()
  writeIndexV2Payload(assembler.reserve(scopePkg, encIndexV2), records,
    groupRecords)
  assembler.finish(dbPath)

  let db = openDatabase(dbPath)
  let section = db.section(scopePkg)
  check section.encoding == encIndexV2
  matchingIndexV2(db, section, query)

suite "v2 round trip":
  setup:
    let dir = makeTempDir()
    let dbPath = dir / "v2.db"
  teardown:
    removeDir(dir)

  test "every field survives a round trip":
    let records = @[
      entry("/bin/hello", @["hello-2.12"], size = 29488, executable = true),
      entry("/bin/hello-link", @["hello-2.12"], kind = fkSymlink,
        target = "/bin/hello"),
      entry("/lib", @["foo-1.0"], kind = fkDirectory),
      entry("/lib/libfoo.so", @["foo-1.0", "bar-2.0"], size = 153600),
    ]

    let hello = roundTrip(records, "/bin/hello", dbPath)
    check hello.len == 2
    check hello[0].path == "/bin/hello"
    check hello[0].size == 29488
    check hello[0].executable
    check hello[0].kind == fkRegular
    check hello[0].packages == @["hello-2.12"]
    check hello[1].path == "/bin/hello-link"
    check hello[1].kind == fkSymlink
    check hello[1].target == "/bin/hello"
    check hello[1].size == 0

    let libs = roundTrip(records, "libfoo", dbPath)
    check libs.len == 1
    check libs[0].size == 153600
    check not libs[0].executable
    # Package sets are interned, so a multi-package record must come back with
    # both names, in the order the name table assigns.
    check libs[0].packages.sorted() == @["bar-2.0", "foo-1.0"]

    let dirs = roundTrip(records, "/lib", dbPath)
    check dirs.len == 2
    check dirs[0].path == "/lib"
    check dirs[0].kind == fkDirectory
    check dirs[0].size == 0
    check dirs[1].path == "/lib/libfoo.so"

  test "a query shorter than a trigram still matches":
    let records = @[entry("/bin/hello", @["hello-2.12"], size = 1)]
    check roundTrip(records, "he", dbPath).len == 1
    check roundTrip(records, "z", dbPath).len == 0

  test "an unknown trigram matches nothing":
    let records = @[entry("/bin/hello", @["hello-2.12"], size = 1)]
    check roundTrip(records, "ZZZNOMATCHZZZ", dbPath).len == 0

  test "multi-byte paths survive prefix deltas":
    # The shared prefix must snap to a scalar boundary, or the suffix of the
    # second record would start mid-codepoint.
    let records = @[
      entry("/\u{1D51E}", @["unicode-1.0"], size = 1),
      entry("/\u{1D51F}", @["unicode-1.0"], size = 2),
    ]
    let found = roundTrip(records, "\u{1D51F}", dbPath)
    check found.len == 1
    check found[0].path == "/\u{1D51F}"
    check found[0].size == 2

  test "prefix deltas too wide for one byte round-trip":
    # A long shared prefix followed by a short path swings the shared length by
    # far more than a signed byte holds, in both directions.
    let deep = "/" & repeat('a', 300)
    let records = @[
      entry(deep & "/x", @["deep-1.0"], size = 1),
      entry(deep & "/y", @["deep-1.0"], size = 2),
      entry("/b", @["shallow-1.0"], size = 3),
      entry("/b" & repeat('c', 400), @["shallow-1.0"], size = 4),
    ]

    let deepHits = roundTrip(records, "/y", dbPath)
    check deepHits.len == 1
    check deepHits[0].path == deep & "/y"
    check deepHits[0].size == 2

    let shallow = roundTrip(records, "/b", dbPath)
    check shallow.len == 2
    check shallow[0].path == "/b"
    check shallow[0].size == 3
    check shallow[1].path == "/b" & repeat('c', 400)
    check shallow[1].size == 4

  test "a size needing every byte plane round-trips":
    let big = (1'u64 shl 39) + 12345'u64
    let records = @[entry("/big", @["big-1.0"], size = big)]
    let found = roundTrip(records, "/big", dbPath)
    check found.len == 1
    check found[0].size == big

  test "a size beyond the size column is refused rather than truncated":
    var assembler = initDatabaseAssembler()
    defer: assembler.cleanup()
    expect DbError:
      writeIndexV2Payload(assembler.reserve(scopePkg, encIndexV2),
        @[entry("/huge", @["huge-1.0"], size = IndexV2MaxSize + 1)])

  test "records spanning several row groups are all found":
    # Two full groups plus a remainder, so the group directory, the per-group
    # column frames and the trigram postings all have to line up. The group
    # size is forced small here; the shipped default would need half a million
    # records to reach a second group.
    const Group = 500
    var records: seq[FileEntry]
    for i in 0 ..< Group * 2 + 7:
      records.add(entry("/nix/store/pkg/file-" & align($i, 8, '0'),
        @["pkg-" & $(i mod 32)], size = uint64(i)))
    records.sort(proc(a, b: FileEntry): int = cmp(a.path, b.path))

    let found = roundTrip(records, "file-00000042", dbPath, Group)
    check found.len == 1
    check found[0].path == "/nix/store/pkg/file-00000042"
    check found[0].size == 42
    check found[0].packages == @["pkg-10"]

    # A query matching in every group must come back complete, which only
    # holds if each group's columns are decoded independently.
    check roundTrip(records, "/nix/store/pkg/file-", dbPath, Group).len ==
      records.len

  test "an empty index is queryable":
    check roundTrip(@[], "anything", dbPath).len == 0
