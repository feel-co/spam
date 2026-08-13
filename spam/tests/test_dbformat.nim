## Tests for the multi-scope database container.

import std/[os, strutils, unittest]
import dbformat

proc writeFileBytes(path, data: string) =
  var file = open(path, fmWrite)
  defer: file.close()
  file.writeRaw(data, "test fixture")

suite "scope parsing":
  test "a list of scopes":
    check parseScopes("pkg,lib") == {scopePkg, scopeLib}

  test "surrounding whitespace and empty entries are ignored":
    check parseScopes(" opt , ,pkg ") == {scopeOpt, scopePkg}

  test "all expands to every scope":
    check parseScopes("all") == AllScopes

  test "an unknown scope is rejected":
    expect DbError:
      discard parseScopes("pkgs")

  test "an empty list is rejected":
    expect DbError:
      discard parseScopes(",")

  test "describe round-trips":
    check parseScopes(AllScopes.describe()) == AllScopes

suite "container round trip":
  setup:
    let dir = makeTempDir()
    let dbPath = dir / "test.db"
  teardown:
    removeDir(dir)

  test "sections are recovered with their bounds":
    var assembler = initDatabaseAssembler()
    writeFileBytes(assembler.reserve(scopePkg, encIndexV1), "package-bytes")
    writeFileBytes(assembler.reserve(scopeLib, encBuckets), "lib-bytes!")
    assembler.finish(dbPath)
    assembler.cleanup()

    let db = openDatabase(dbPath)
    check db.scopes() == {scopePkg, scopeLib}
    check not db.hasScope(scopeOpt)

    let pkg = db.section(scopePkg)
    check pkg.encoding == encIndexV1
    check pkg.offset == 0
    check pkg.length == uint64("package-bytes".len)

    let lib = db.section(scopeLib)
    check lib.encoding == encBuckets
    check lib.offset == uint64("package-bytes".len)
    check lib.length == uint64("lib-bytes!".len)

    # A section's payload must land exactly where the table says it does.
    var file = open(dbPath, fmRead)
    defer: file.close()
    file.setFilePos(db.start(lib))
    check file.readExact(dbPath, int(lib.length)) == "lib-bytes!"

  test "asking for an absent scope fails":
    var assembler = initDatabaseAssembler()
    writeFileBytes(assembler.reserve(scopeOpt, encBuckets), "opt")
    assembler.finish(dbPath)
    assembler.cleanup()

    expect DbError:
      discard openDatabase(dbPath).section(scopeLib)

  test "a scope cannot be written twice":
    var assembler = initDatabaseAssembler()
    defer: assembler.cleanup()
    discard assembler.reserve(scopeOpt, encBuckets)
    expect DbError:
      discard assembler.reserve(scopeOpt, encIndexV1)

  test "an empty database is refused rather than written":
    var assembler = initDatabaseAssembler()
    defer: assembler.cleanup()
    expect DbError:
      assembler.finish(dbPath)
    check not fileExists(dbPath)

suite "malformed containers":
  setup:
    let dir = makeTempDir()
    let dbPath = dir / "test.db"
  teardown:
    removeDir(dir)

  test "an unknown magic is rejected":
    writeFileBytes(dbPath, "# spam-db-v9\n")
    expect DbError:
      discard openDatabase(dbPath)

  test "a section reaching past the payload is rejected":
    writeFileBytes(dbPath, DbMagicV2 & "\n" & putUint32(1) &
      putUint16(uint16(ord(scopePkg))) & putUint16(uint16(ord(encBuckets))) &
      putUint64(0) & putUint64(64) & "short")
    expect DbError:
      discard openDatabase(dbPath)

  test "two sections for one scope are rejected":
    var table = ""
    for _ in 0 .. 1:
      table.add(putUint16(uint16(ord(scopeOpt))))
      table.add(putUint16(uint16(ord(encBuckets))))
      table.add(putUint64(0))
      table.add(putUint64(0))
    writeFileBytes(dbPath, DbMagicV2 & "\n" & putUint32(2) & table)
    expect DbError:
      discard openDatabase(dbPath)

  test "an implausible section count is rejected before allocating":
    writeFileBytes(dbPath, DbMagicV2 & "\n" & putUint32(uint32.high))
    expect DbError:
      discard openDatabase(dbPath)

suite "legacy v1 databases":
  setup:
    let dir = makeTempDir()
    let dbPath = dir / "legacy.db"
  teardown:
    removeDir(dir)

  test "each v1 kind maps onto a scope and encoding":
    for (kindName, scope, encoding) in [
      ("options", scopeOpt, encBuckets),
      ("packages", scopePkg, encBuckets),
      ("lib", scopeLib, encBuckets),
      ("index", scopePkg, encIndexV1),
    ]:
      writeFileBytes(dbPath, DbMagicV1 & "\t" & kindName & "\npayload")
      let db = openDatabase(dbPath)
      check db.sections.len == 1
      check db.sections[0].scope == scope
      check db.sections[0].encoding == encoding
      check db.sections[0].offset == 0
      check db.sections[0].length == uint64("payload".len)
      check db.start(db.sections[0]) ==
        DbMagicV1.len + 1 + kindName.len + 1

  test "an unknown v1 kind is rejected":
    writeFileBytes(dbPath, DbMagicV1 & "\tfunctions\npayload")
    expect DbError:
      discard openDatabase(dbPath)

suite "integer encoding":
  test "fixed-width values round-trip little-endian":
    check getUint16(putUint16(0xbeef'u16), 0) == 0xbeef'u16
    check getUint32(putUint32(0xdeadbeef'u32), 0) == 0xdeadbeef'u32
    check getUint64(putUint64(uint64.high), 0) == uint64.high
    check putUint32(1'u32) == "\x01\x00\x00\x00"

  test "reading past the end fails instead of returning zero":
    expect DbError:
      discard getUint64("short", 0)

  test "varints are minimal":
    check putVarint(0'u64).len == 1
    check putVarint(127'u64).len == 1
    check putVarint(128'u64).len == 2
