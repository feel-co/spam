import std/[os]
import dbformat
import filemeta
import spam

let
  previous = "/𝔞"
  current = "/𝔟"
  shared = sharedPrefixLen(previous, current)

doAssert shared == 1
doAssert current[shared .. ^1] == "𝔟"

let
  sameScalarPrevious = "/𝔞-a"
  sameScalarCurrent = "/𝔞-b"
  sameScalarShared = sharedPrefixLen(sameScalarPrevious, sameScalarCurrent)

doAssert sameScalarShared == "/𝔞-".len
doAssert sameScalarCurrent[sameScalarShared .. ^1] == "b"

let dbPath = getTempDir() / "spam-test-index-v1.db"
var assembler = initDatabaseAssembler()
try:
  # Reserve a filler section first so the package section does not start at
  # offset zero; a reader that ignored the section offset would still pass
  # otherwise.
  block:
    let filler = assembler.reserve(scopeOpt, encBuckets)
    var file = open(filler, fmWrite)
    defer: file.close()
    file.writeRaw("not a real options section", "filler")

  writeIndexV1Payload(assembler.reserve(scopePkg, encIndexV1), @[
    FileEntry(
      path: "/bin/firefox",
      size: 10'u64,
      kind: fkRegular,
      executable: true,
      packages: @["firefox-1.0"],
    ),
    FileEntry(
      path: "/share/doc/firefox/readme",
      size: 20'u64,
      kind: fkRegular,
      packages: @["firefox-1.0"],
    ),
    FileEntry(
      path: "/bin/hello",
      size: 30'u64,
      kind: fkRegular,
      executable: true,
      packages: @["hello-2.12"],
    ),
  ])
  assembler.finish(dbPath)

  # Query through the container, so a section that is not at offset zero would
  # be caught here rather than only in the single-section case.
  let
    db = openDatabase(dbPath)
    section = db.section(scopePkg)
  doAssert section.encoding == encIndexV1

  let matches = matchingIndexV1(db, section, "readme")
  doAssert matches.len == 1
  doAssert matches[0].path == "/share/doc/firefox/readme"

  let shortMatches = matchingIndexV1(db, section, "he")
  doAssert shortMatches.len == 1
  doAssert shortMatches[0].path == "/bin/hello"

  doAssert matchingIndexV1(db, section, "zzzz").len == 0
finally:
  assembler.cleanup()
  if fileExists(dbPath):
    removeFile(dbPath)
