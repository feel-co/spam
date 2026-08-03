## Container format for spam databases.
##
## A database is a sequence of scope sections. Each section holds the records
## for one search scope in one of two encodings, so a scoped search reads only
## the bytes belonging to that scope.
##
## ```text
##   "# spam-db-v2\n"
##   u32                section count
##   section table      count x { u16 scope, u16 encoding, u64 offset, u64 length }
##   payload            sections in table order; offsets are relative to the
##                      first payload byte
## ```
##
## Databases written by earlier releases carry a `# spam-db-v1\t<kind>` header
## and hold exactly one kind. They are read as a single synthesised section.

import std/[os, strutils]

const
  DbMagicV2* = "# spam-db-v2"
  DbMagicV1* = "# spam-db-v1"
  SectionEntrySize* = 20
  MaxSectionCount* = 64

type
  DbError* = object of CatchableError
    ## Raised for any malformed or truncated database. `main` reports it.

  Scope* = enum
    ## A search scope. Each maps to at most one section per database.
    scopePkg = "pkg"
    scopeOpt = "opt"
    scopeLib = "lib"

  ScopeSet* = set[Scope]

  SectionEncoding* = enum
    encBuckets = 1 ## 256 zstd blobs, bucketed by every distinct byte of the record key.
    encIndexV1 = 2 ## blocked, prefix-delta encoded records with a trigram index.
    encIndexV2 = 3 ## column-major row groups with a trigram index.

  DbSection* = object
    scope*: Scope
    encoding*: SectionEncoding
    offset*: uint64 ## relative to the first payload byte.
    length*: uint64

  Database* = object
    path*: string
    payloadStart*: int
    sections*: seq[DbSection]

const AllScopes* = {scopePkg, scopeOpt, scopeLib}

proc dbFail*(message: string) {.noreturn.} =
  raise newException(DbError, message)

proc describe*(scopes: ScopeSet): string =
  var names: seq[string]
  for scope in Scope:
    if scope in scopes:
      names.add($scope)
  names.join(",")

proc parseScopes*(value: string): ScopeSet =
  ## Parse a `--scope` value: a comma-separated scope list, or `all`.
  for item in value.split(','):
    let name = item.strip()
    if name.len == 0:
      continue
    if name == "all":
      result.incl(AllScopes)
      continue
    var matched = false
    for scope in Scope:
      if $scope == name:
        result.incl(scope)
        matched = true
    if not matched:
      dbFail("unknown scope '" & name & "'; expected one of " &
        AllScopes.describe() & " or all")
  if result == {}:
    dbFail("--scope requires at least one scope")

proc putUint64*(value: uint64): string =
  for shift in countup(0, 56, 8):
    result.add(char((value shr shift) and 0xff'u64))

proc putUint32*(value: uint32): string =
  for shift in countup(0, 24, 8):
    result.add(char((value shr shift) and 0xff'u32))

proc putUint16*(value: uint16): string =
  for shift in countup(0, 8, 8):
    result.add(char((value shr shift) and 0xff'u16))

proc putVarint*(value: uint64): string =
  var remaining = value
  while remaining >= 0x80'u64:
    result.add(char((remaining and 0x7f'u64) or 0x80'u64))
    remaining = remaining shr 7
  result.add(char(remaining))

proc getUint64*(data: string, offset: int): uint64 =
  if offset < 0 or offset + 8 > data.len:
    dbFail("truncated database")
  for shift in countup(0, 56, 8):
    result = result or (uint64(data[offset + shift div 8]) shl shift)

proc getUint32*(data: string, offset: int): uint32 =
  if offset < 0 or offset + 4 > data.len:
    dbFail("truncated database")
  for shift in countup(0, 24, 8):
    result = result or (uint32(data[offset + shift div 8]) shl shift)

proc getUint16*(data: string, offset: int): uint16 =
  if offset < 0 or offset + 2 > data.len:
    dbFail("truncated database")
  for shift in countup(0, 8, 8):
    result = result or (uint16(data[offset + shift div 8]) shl shift)

proc ensureParent*(path: string) =
  let dir = path.parentDir()
  if dir.len > 0:
    createDir(dir)

proc makeTempDir*(): string =
  let base = getTempDir() / ("spam-db-" & $getCurrentProcessId())
  var suffix = 0
  while true:
    result = base & "-" & $suffix
    if not dirExists(result) and not fileExists(result):
      createDir(result)
      return
    inc suffix

proc writeRaw*(file: File, data: string, label: string) =
  if data.len == 0:
    return
  let written = file.writeBuffer(unsafeAddr data[0], data.len)
  if written != data.len:
    dbFail("failed to write " & label)

proc writeRaw*(file: File, data: pointer, length: int, label: string) =
  if length == 0:
    return
  let written = file.writeBuffer(data, length)
  if written != length:
    dbFail("failed to write " & label)

proc readExact*(file: File, path: string, length: int): string =
  if length == 0:
    return ""
  result = newString(length)
  let read = file.readBuffer(addr result[0], length)
  if read != length:
    dbFail("truncated database: " & path)

proc legacySection(kindName, path: string, payloadLength: uint64): DbSection =
  ## Map a v1 `<kind>` header onto the scope and encoding it implied.
  case kindName
  of "options": DbSection(scope: scopeOpt, encoding: encBuckets, offset: 0,
      length: payloadLength)
  of "packages": DbSection(scope: scopePkg, encoding: encBuckets, offset: 0,
      length: payloadLength)
  of "lib": DbSection(scope: scopeLib, encoding: encBuckets, offset: 0,
      length: payloadLength)
  of "index": DbSection(scope: scopePkg, encoding: encIndexV1, offset: 0,
      length: payloadLength)
  else: dbFail("unknown database kind '" & kindName & "' in " & path)

proc parseSectionTable(data: string, count: int, path: string,
    payloadLength: uint64): seq[DbSection] =
  var seenScopes: ScopeSet
  for i in 0 ..< count:
    let
      base = i * SectionEntrySize
      scopeCode = getUint16(data, base)
      encodingCode = getUint16(data, base + 2)
      offset = getUint64(data, base + 4)
      length = getUint64(data, base + 12)

    if scopeCode > uint16(ord(Scope.high)):
      dbFail("unknown scope code in " & path)
    if encodingCode < 1'u16 or encodingCode > uint16(ord(SectionEncoding.high)):
      dbFail("unknown section encoding in " & path)

    let section = DbSection(
      scope: Scope(scopeCode),
      encoding: SectionEncoding(encodingCode),
      offset: offset,
      length: length,
    )
    if section.scope in seenScopes:
      dbFail("duplicate " & $section.scope & " section in " & path)
    seenScopes.incl(section.scope)

    let endOffset = offset + length
    if endOffset < offset or endOffset > payloadLength:
      dbFail("section slice out of bounds in " & path)
    result.add(section)

proc openDatabase*(path: string): Database =
  ## Read the header and section table of `path`. No payload is read.
  if not fileExists(path):
    dbFail("database does not exist: " & path)

  var file = open(path, fmRead)
  defer: file.close()

  let
    headerLine = file.readLine()
    fileSize = getFileSize(path)
  if fileSize > BiggestInt(int.high):
    dbFail("database is too large for this platform: " & path)

  result.path = path

  if headerLine.startsWith(DbMagicV1):
    let rest = headerLine[DbMagicV1.len .. ^1]
    let kindName = if rest.startsWith("\t"): rest[1 .. ^1] else: rest
    result.payloadStart = headerLine.len + 1
    result.sections = @[legacySection(kindName, path,
      uint64(fileSize) - uint64(result.payloadStart))]
    return

  if headerLine != DbMagicV2:
    dbFail("unsupported database format: " & path)

  let count = int(getUint32(file.readExact(path, 4), 0))
  if count < 0 or count > MaxSectionCount:
    dbFail("implausible section count in " & path)

  let
    tableSize = count * SectionEntrySize
    table = file.readExact(path, tableSize)
  result.payloadStart = headerLine.len + 1 + 4 + tableSize
  if BiggestInt(result.payloadStart) > fileSize:
    dbFail("truncated section table in " & path)
  result.sections = parseSectionTable(table, count, path,
    uint64(fileSize) - uint64(result.payloadStart))

proc hasScope*(db: Database, scope: Scope): bool =
  for section in db.sections:
    if section.scope == scope:
      return true

proc scopes*(db: Database): ScopeSet =
  for section in db.sections:
    result.incl(section.scope)

proc section*(db: Database, scope: Scope): DbSection =
  for candidate in db.sections:
    if candidate.scope == scope:
      return candidate
  dbFail("database has no " & $scope & " section: " & db.path)

proc start*(db: Database, section: DbSection): int =
  ## Absolute file offset of `section`.
  if section.offset > uint64(int.high - db.payloadStart):
    dbFail("section offset overflow in " & db.path)
  db.payloadStart + int(section.offset)

type
  PendingSection = object
    scope: Scope
    encoding: SectionEncoding
    payloadPath: string

  DatabaseAssembler* = object
    ## Collects one payload file per scope, then writes them out as one
    ## database. Payloads are built on disk so a full nixpkgs index never has
    ## to be held in memory twice.
    tempDir*: string
    pending: seq[PendingSection]

proc initDatabaseAssembler*(): DatabaseAssembler =
  result.tempDir = makeTempDir()

proc cleanup*(assembler: var DatabaseAssembler) =
  if assembler.tempDir.len > 0 and dirExists(assembler.tempDir):
    removeDir(assembler.tempDir)
    assembler.tempDir = ""

proc reserve*(assembler: var DatabaseAssembler, scope: Scope,
    encoding: SectionEncoding): string =
  ## Reserve a payload file for `scope` and return the path to write it to.
  for existing in assembler.pending:
    if existing.scope == scope:
      dbFail("cannot write two " & $scope & " sections into one database")
  result = assembler.tempDir / ("section-" & $scope)
  assembler.pending.add(PendingSection(scope: scope, encoding: encoding,
      payloadPath: result))

proc isEmpty*(assembler: DatabaseAssembler): bool =
  assembler.pending.len == 0

proc finish*(assembler: var DatabaseAssembler, path: string) =
  if assembler.pending.len == 0:
    dbFail("refusing to write a database with no sections")

  path.ensureParent()
  var output = open(path, fmWrite)
  defer: output.close()

  output.writeRaw(DbMagicV2 & "\n", "database header")
  output.writeRaw(putUint32(uint32(assembler.pending.len)), "section count")

  var
    table = ""
    offset = 0'u64
  for entry in assembler.pending:
    let length = uint64(getFileSize(entry.payloadPath))
    table.add(putUint16(uint16(ord(entry.scope))))
    table.add(putUint16(uint16(ord(entry.encoding))))
    table.add(putUint64(offset))
    table.add(putUint64(length))
    offset += length
  output.writeRaw(table, "section table")

  var buffer = newString(128 * 1024)
  for entry in assembler.pending:
    var input = open(entry.payloadPath, fmRead)
    defer: input.close()
    while true:
      let read = input.readBuffer(addr buffer[0], buffer.len)
      if read == 0:
        break
      output.writeRaw(addr buffer[0], read, "section payload")
