import std/[os]
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
try:
  writeIndexV1Database(dbPath, @[
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

  let matches = matchingIndexV1(dbPath, "readme")
  doAssert matches.len == 1
  doAssert matches[0].path == "/share/doc/firefox/readme"

  let shortMatches = matchingIndexV1(dbPath, "he")
  doAssert shortMatches.len == 1
  doAssert shortMatches[0].path == "/bin/hello"

  doAssert matchingIndexV1(dbPath, "zzzz").len == 0
finally:
  if fileExists(dbPath):
    removeFile(dbPath)
