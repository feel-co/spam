## spam - search Nix package files and module options
##
## `spam` searches NixOS module options, package-manifest file databases, and
## autonomous package indexes.
##
## Usage
## =====
##
## ```
##
##   spam opt --module-options options.json QUERY
##   spam opt --db options.db QUERY
##   spam pkg --db files.db QUERY
##   spam db build --manifest packages.json --output files.db
##   spam db build --manifest options.json --output options.db
##   spam index --output files.db --nixpkgs PATH --cache-url URL
##              --system SYSTEM --scope ATTR --concurrent N
##              --follow-refs --verbose
## ```
##
## `--json` may be added to search and database build commands.
##
## Global Options
## ==============
##
## `-h`, `--help`
##   Display the help message.
##
## `--json`
##   Output results in JSON format.
##
## `--db <path>`
##   Path to a generated database. Defaults to `$XDG_CACHE_HOME/spam/files.db`.
##
## `--verbose`
##   Print progress to stderr.
##
## Option Search
## =============
##
## ```
##
##   spam opt --module-options options.json <query>
##   spam opt --db options.db <query>
## ```
##
## `--module-options` reads an `options.json` file produced by
## `nixosOptionsDoc`. `--db` reads a generated options database.
##
## Package Search
## ==============
##
## ```
##
##   spam pkg --db files.db <query>
## ```
##
## `spam pkg` searches a package-manifest database from `spam db build` or an
## autonomous index from `spam index`. Matches are substring matches against
## store-output-relative paths, so `bin/foo` matches `/bin/foo`.
##
## Database Generation
## ===================
##
## ```
##
##   spam db build --manifest packages.json --output files.db
##   spam db build --manifest options.json --output options.db
## ```
##
## Package manifests describe already-realized store outputs. Store hashes are
## not recorded; paths are stored relative to each output and deduplicated
## across packages. If the manifest is an `options.json` produced by
## `nixosOptionsDoc`, `spam` builds an option database instead.
##
## Supported package manifest shapes include an array of package objects, an
## object mapping attr names to store paths, and an object mapping attr names to
## named output paths.
##
## ```
##
##   {
##     "hello": "/nix/store/...-hello-2.12",
##     "git": {
##       "out": "/nix/store/...-git-2.51.0",
##       "man": "/nix/store/...-git-2.51.0-man"
##     }
##   }
## ```
##
## Autonomous Indexing
## ===================
##
## ```
##
##   spam index --output files.db --nixpkgs PATH --cache-url URL
##              --system SYSTEM --scope ATTR --concurrent N
##              --no-follow-refs --verbose
## ```
##
## `spam index` enumerates packages from nixpkgs via
## `nix-env -qaP --xml --out-path`, then fetches file listings from a Nix binary
## cache using BFS reference traversal. It produces an autonomous index database
## usable with `spam pkg`.
##
## Index options:
##
## `--output <files.db>`
##   Database output path. Defaults to the `--db` path.
##
## `--nixpkgs <path>`
##   Nixpkgs path or expression for `nix-env -f`. Defaults to `<nixpkgs>`.
##
## `--cache-url <url>`
##   Binary cache URL. Defaults to `https://cache.nixos.org`.
##
## `--system <system>`
##   Override the target system, for example `x86_64-linux`.
##
## `--scope <attr>`
##   Limit indexing to a single attr set, for example `python3Packages`.
##
## `--concurrent <n>`
##   Maximum parallel HTTP requests.
##
## `--no-follow-refs`
##   Only index direct package outputs and skip transitive store-reference
##   traversal.
##
## Bugs
## ====
##
## Report issues at https://github.com/feel-co/spam/issues.

import std/[algorithm, asyncdispatch, hashes, json, os, parseopt, sequtils,
    sets, strformat, strutils, tables]
from std/unicode import validateUtf8
import filemeta
import cache
import index

{.passL: "-lzstd".}

const
  DbMagic = "# spam-db-v1"
  DefaultDbName = "spam/files.db"
  IndexBuckets = 256
  IndexEntrySize = 16
  IndexSize = IndexBuckets * IndexEntrySize
  PackageSpoolPartitions = 256
  ZstdBufferSize = 128 * 1024
  BucketCompressionLevel = 3
  IndexCompressionLevel = 19
  IndexV1BlockSize = 64 * 1024
  IndexV1SectionPackages = 1'u16
  IndexV1SectionBlockTable = 2'u16
  IndexV1SectionBlocks = 3'u16
  IndexV1SectionTrigrams = 4'u16
  IndexV1SectionPostings = 5'u16
  IndexV1TrigramSkipped = 1'u8
  ZstdContentSizeUnknown = uint64.high
  ZstdContentSizeError = uint64.high - 1

type
  Command = enum
    cmdNone, cmdOpt, cmdPkg, cmdDb, cmdIndex

  DbCommand = enum
    dbNone, dbBuild

  OptSource = enum
    optSourceNone, optSourceJson, optSourceDb

  DbKind = enum
    dbOptions, dbPackages, dbIndex

  Config = object
    command: Command
    dbCommand: DbCommand
    optSource: OptSource
    jsonOutput: bool
    moduleOptions: string
    database: string
    manifest: string
    output: string
    query: string
    ## Options for 'spam index'
    indexNixpkgs: string
    indexSystem: string
    indexScope: string
    indexCacheUrl: string
    indexConcurrent: int
    indexFollowRefs: bool
    verbose: bool

  OptionRecord = object
    name: string
    summary: string

  PackageOutput = object
    name: string
    path: string

  ZstdInBuffer = object
    src: pointer
    size: csize_t
    pos: csize_t

  ZstdOutBuffer = object
    dst: pointer
    size: csize_t
    pos: csize_t

  IndexedDatabaseBuilder = object
    path: string
    kind: DbKind
    tempDir: string
    bucketPaths: array[IndexBuckets, string]
    bucketFiles: array[IndexBuckets, File]
    bucketFilesOpen: bool

  PackageEntrySpool = object
    tempDir: string
    partitionPaths: array[PackageSpoolPartitions, string]
    partitionFiles: array[PackageSpoolPartitions, File]
    partitionFilesOpen: bool

  IndexV1Block = object
    firstRecordId: uint64
    recordCount: uint32
    compressedOffset: uint64
    compressedLength: uint32
    uncompressedLength: uint32

  IndexV1TrigramEntry = object
    trigram: uint32
    flags: uint8
    docFreq: uint32
    postingsOffset: uint64
    postingsLength: uint32

  IndexV1Section = object
    kind: uint16
    offset: uint64
    length: uint64

  IndexV1DecodedBlock = object
    firstRecordId: uint64
    recordCount: uint32
    compressedOffset: uint64
    compressedLength: uint32
    uncompressedLength: uint32

proc zstdGetFrameContentSize(src: pointer, srcSize: csize_t): uint64 {.
    importc: "ZSTD_getFrameContentSize".}
proc zstdDecompress(
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  compressedSize: csize_t,
): csize_t {.importc: "ZSTD_decompress".}
proc zstdIsError(code: csize_t): cuint {.importc: "ZSTD_isError".}
proc zstdGetErrorName(code: csize_t): cstring {.importc: "ZSTD_getErrorName".}
proc zstdCreateCStream(): pointer {.importc: "ZSTD_createCStream".}
proc zstdFreeCStream(stream: pointer): csize_t {.importc: "ZSTD_freeCStream".}
proc zstdInitCStream(stream: pointer, compressionLevel: cint): csize_t {.
    importc: "ZSTD_initCStream".}
proc zstdSetPledgedSrcSize(stream: pointer, pledgedSrcSize: uint64): csize_t {.
    importc: "ZSTD_CCtx_setPledgedSrcSize".}
proc zstdCompressStream(
  stream: pointer,
  output: ptr ZstdOutBuffer,
  input: ptr ZstdInBuffer,
): csize_t {.importc: "ZSTD_compressStream".}
proc zstdEndStream(stream: pointer, output: ptr ZstdOutBuffer): csize_t {.
    importc: "ZSTD_endStream".}

proc fail(message: string) {.noreturn.} =
  stderr.writeLine("spam: " & message)
  quit(1)

proc showHelp() {.noreturn.} =
  stdout.write("""
spam - search Nix module options and package file indexes

Usage:
  spam opt --module-options options.json [--json] <query>
  spam opt --db options.db [--json] <query>
  spam pkg [--db files.db] [--json] <query>
  spam db build --manifest packages.json --output files.db [--json]
  spam db build --manifest options.json --output options.db [--json]
  spam index [--output files.db] [--nixpkgs <path>] [--cache-url <url>]
             [--system <system>] [--scope <attr>] [--concurrent <n>]
             [--follow-refs] [--verbose]
  spam --help

Commands:
  opt       Search an options.json produced by nixosOptionsDoc.
  pkg       Search a package-manifest database or autonomous index.
  db build  Build a package-file or option database from a local manifest JSON.
  index     Autonomously index nixpkgs by fetching file listings from the
            binary cache. Produces an index database, separate from databases
            produced by 'spam db build'.

Global options:
  -h, --help         Show this help text.
      --json         Emit JSON results.
      --db <path>    Database path. Defaults to $XDG_CACHE_HOME/""" &
      DefaultDbName & """.

opt options:
      --module-options <path>  Path to nixosOptionsDoc options.json.
      --db <path>              Path to a generated options database.

db build options:
      --manifest <path>  JSON package manifest or nixosOptionsDoc options.json.
      --output <path>    Database output path.

index options:
      --output <path>      Database output path. Defaults to --db value.
      --nixpkgs <path>     Nixpkgs path or expression for nix-env -f.
                           Defaults to <nixpkgs>.
      --cache-url <url>    Binary cache URL. Defaults to https://cache.nixos.org.
      --system <system>    Override the target system (e.g. x86_64-linux).
      --scope <attr>       Limit indexing to a single attr set (e.g. python3Packages).
      --concurrent <n>     Maximum parallel HTTP requests (default: 32).
      --follow-refs        Also index transitive references from each package.
      --no-follow-refs     Only index direct package outputs, skip transitive
                            reference traversal (much faster). Enabled by default.
      --verbose            Print progress to stderr.

Manifest formats for 'db build':
  [
    {"attr":"hello","pname":"hello","version":"2.12","outputs":{"out":"/nix/store/...-hello-2.12"}}
  ]

  {"hello": "/nix/store/...-hello-2.12"}
  {"hello": {"out": "/nix/store/...-hello-2.12", "man": "/nix/store/...-hello-2.12-man"}}
""")
  quit(0)

proc defaultDatabasePath(): string =
  let cacheHome =
    if getEnv("XDG_CACHE_HOME").len > 0: getEnv("XDG_CACHE_HOME")
    else: getHomeDir() / ".cache"
  cacheHome / DefaultDbName

proc requireValue(option, value: string): string =
  if value.len == 0:
    fail(option & " requires a value")
  value

proc rememberQuery(config: var Config, value: string) =
  if config.query.len > 0:
    fail("unexpected argument: " & value)
  config.query = value

proc parseCommand(config: var Config, args: var seq[string], value: string) =
  args.add(value)

  if config.command == cmdNone:
    case value
    of "opt": config.command = cmdOpt
    of "pkg": config.command = cmdPkg
    of "db": config.command = cmdDb
    of "index": config.command = cmdIndex
    else: fail("unknown command: " & value)
  elif config.command == cmdDb and args.len == 2:
    case value
    of "build": config.dbCommand = dbBuild
    else: fail("unknown db command: " & value)
  else:
    config.rememberQuery(value)

proc parseArgs(): Config =
  result.database = defaultDatabasePath()
  result.indexCacheUrl = DefaultCacheUrl
  result.indexNixpkgs = "<nixpkgs>"
  result.indexConcurrent = MaxConcurrent

  var parser = initOptParser(
    shortNoVal = {'h'},
    longNoVal = @["help", "json", "verbose", "follow-refs", "no-follow-refs"],
  )
  var args: seq[string]

  for kind, key, value in parser.getopt():
    case kind
    of cmdArgument:
      result.parseCommand(args, key)
    of cmdLongOption, cmdShortOption:
      case key
      of "h", "help":
        showHelp()
      of "json":
        result.jsonOutput = true
      of "verbose":
        result.verbose = true
      of "db":
        if result.optSource == optSourceJson:
          fail("opt accepts either --module-options or --db, not both")
        result.optSource = optSourceDb
        result.database = requireValue("--db", value)
      of "module-options":
        if result.optSource == optSourceDb:
          fail("opt accepts either --module-options or --db, not both")
        result.optSource = optSourceJson
        result.moduleOptions = requireValue("--module-options", value)
      of "manifest":
        result.manifest = requireValue("--manifest", value)
      of "output":
        result.output = requireValue("--output", value)
      of "nixpkgs":
        result.indexNixpkgs = requireValue("--nixpkgs", value)
      of "cache-url":
        result.indexCacheUrl = requireValue("--cache-url", value)
      of "system":
        result.indexSystem = requireValue("--system", value)
      of "scope":
        result.indexScope = requireValue("--scope", value)
      of "concurrent":
        let n = parseInt(requireValue("--concurrent", value))
        if n < 1 or n > 256:
          fail("--concurrent must be between 1 and 256")
        result.indexConcurrent = n
      of "follow-refs":
        result.indexFollowRefs = true
      of "no-follow-refs":
        result.indexFollowRefs = false
      else:
        fail("unknown option: --" & key)
    of cmdEnd:
      discard

  if result.command == cmdNone:
    showHelp()

proc validatePath(path, label: string) =
  if not fileExists(path):
    fail(label & " does not exist: " & path)

proc validate(config: Config) =
  case config.command
  of cmdOpt:
    if config.optSource == optSourceNone:
      fail("opt requires --module-options or --db")
    if config.query.len == 0:
      fail("opt requires a search query")
    case config.optSource
    of optSourceJson:
      validatePath(config.moduleOptions, "options file")
    of optSourceDb:
      validatePath(config.database, "options database")
    of optSourceNone:
      discard
  of cmdPkg:
    if config.query.len == 0:
      fail("pkg requires a search query")
    validatePath(config.database, "database")
  of cmdDb:
    if config.dbCommand == dbNone:
      fail("db requires a subcommand")
    if config.query.len > 0:
      fail("unexpected argument: " & config.query)
    if config.manifest.len == 0:
      fail("db build requires --manifest")
    if config.output.len == 0:
      fail("db build requires --output")
    validatePath(config.manifest, "manifest")
  of cmdIndex:
    discard # all index options have sensible defaults
  of cmdNone:
    discard

proc header(kind: DbKind): string =
  case kind
  of dbOptions: DbMagic & "\toptions"
  of dbPackages: DbMagic & "\tpackages"
  of dbIndex: DbMagic & "\tindex"

proc ensureParent(path: string) =
  let dir = path.parentDir()
  if dir.len > 0:
    createDir(dir)

proc putUint64(value: uint64): string =
  for shift in countup(0, 56, 8):
    result.add(char((value shr shift) and 0xff'u64))

proc putUint32(value: uint32): string =
  for shift in countup(0, 24, 8):
    result.add(char((value shr shift) and 0xff'u32))

proc putUint16(value: uint16): string =
  for shift in countup(0, 8, 8):
    result.add(char((value shr shift) and 0xff'u16))

proc putVarint(value: uint64): string =
  var remaining = value
  while remaining >= 0x80'u64:
    result.add(char((remaining and 0x7f'u64) or 0x80'u64))
    remaining = remaining shr 7
  result.add(char(remaining))

proc getUint64(data: string, offset: int): uint64 =
  if offset + 8 > data.len:
    fail("truncated database index")

  for shift in countup(0, 56, 8):
    result = result or (uint64(data[offset + shift div 8]) shl shift)

proc getUint32(data: string, offset: int): uint32 =
  if offset + 4 > data.len:
    fail("truncated database")

  for shift in countup(0, 24, 8):
    result = result or (uint32(data[offset + shift div 8]) shl shift)

proc getUint16(data: string, offset: int): uint16 =
  if offset + 2 > data.len:
    fail("truncated database")

  for shift in countup(0, 8, 8):
    result = result or (uint16(data[offset + shift div 8]) shl shift)

proc zstdDecompress(input: string): string =
  if input.len == 0:
    return ""

  let contentSize = zstdGetFrameContentSize(unsafeAddr input[0], csize_t(input.len))
  if contentSize == ZstdContentSizeError:
    fail("invalid zstd frame in database")
  if contentSize == ZstdContentSizeUnknown:
    fail("zstd frame has unknown decompressed size")
  if contentSize > uint64(int.high):
    fail("zstd frame is too large")

  result = newString(int(contentSize))
  if result.len == 0:
    return

  let decompressedSize = zstdDecompress(addr result[0], csize_t(result.len),
    unsafeAddr input[0], csize_t(input.len))
  if zstdIsError(decompressedSize) != 0:
    fail("zstd decompression failed: " & $zstdGetErrorName(decompressedSize))
  result.setLen(int(decompressedSize))

proc searchableKey(line: string): string =
  let tab = line.find('\t')
  if tab < 0: line else: line[0 ..< tab]

proc writeRaw(file: File, data: string, label: string) =
  if data.len == 0:
    return

  let written = file.writeBuffer(unsafeAddr data[0], data.len)
  if written != data.len:
    fail("failed to write " & label)

proc writeRaw(file: File, data: pointer, length: int, label: string) =
  if length == 0:
    return

  let written = file.writeBuffer(data, length)
  if written != length:
    fail("failed to write " & label)

proc checkedZstd(code: csize_t, action: string) =
  if zstdIsError(code) != 0:
    fail(action & ": " & $zstdGetErrorName(code))

proc zstdCompressFile(inputPath: string, output: File,
    compressionLevel: cint = BucketCompressionLevel): uint64 =
  let stream = zstdCreateCStream()
  if stream == nil:
    fail("zstd compression failed: could not create stream")
  defer:
    discard zstdFreeCStream(stream)

  checkedZstd(zstdInitCStream(stream, compressionLevel),
    "zstd compression failed")
  checkedZstd(zstdSetPledgedSrcSize(stream, uint64(getFileSize(inputPath))),
    "zstd compression failed")

  var input = open(inputPath, fmRead)
  defer: input.close()

  var
    inputChunk = newString(ZstdBufferSize)
    outputChunk = newString(ZstdBufferSize)
    compressedSize = 0'u64

  while true:
    let read = input.readBuffer(addr inputChunk[0], inputChunk.len)
    if read == 0:
      break

    var inputBuffer = ZstdInBuffer(
      src: addr inputChunk[0],
      size: csize_t(read),
      pos: 0,
    )
    while inputBuffer.pos < inputBuffer.size:
      var outputBuffer = ZstdOutBuffer(
        dst: addr outputChunk[0],
        size: csize_t(outputChunk.len),
        pos: 0,
      )
      checkedZstd(zstdCompressStream(stream, addr outputBuffer,
          addr inputBuffer),
        "zstd compression failed")
      output.writeRaw(addr outputChunk[0], int(outputBuffer.pos), "database")
      compressedSize += uint64(outputBuffer.pos)

  while true:
    var outputBuffer = ZstdOutBuffer(
      dst: addr outputChunk[0],
      size: csize_t(outputChunk.len),
      pos: 0,
    )
    let remaining = zstdEndStream(stream, addr outputBuffer)
    checkedZstd(remaining, "zstd compression failed")
    output.writeRaw(addr outputChunk[0], int(outputBuffer.pos), "database")
    compressedSize += uint64(outputBuffer.pos)
    if remaining == 0:
      break

  compressedSize

proc cleanup(builder: var IndexedDatabaseBuilder) =
  if builder.bucketFilesOpen:
    for i in 0 ..< IndexBuckets:
      try:
        builder.bucketFiles[i].close()
      except IOError:
        discard
    builder.bucketFilesOpen = false

  if builder.tempDir.len > 0 and dirExists(builder.tempDir):
    removeDir(builder.tempDir)

proc makeTempDir(): string =
  let base = getTempDir() / ("spam-db-" & $getCurrentProcessId())
  var suffix = 0
  while true:
    result = base & "-" & $suffix
    if not dirExists(result) and not fileExists(result):
      createDir(result)
      return
    inc suffix

proc initIndexedDatabaseBuilder(path: string,
    kind: DbKind): IndexedDatabaseBuilder =
  result.path = path
  result.kind = kind
  result.tempDir = makeTempDir()
  for i in 0 ..< IndexBuckets:
    result.bucketPaths[i] = result.tempDir / $i
    result.bucketFiles[i] = open(result.bucketPaths[i], fmWrite)
  result.bucketFilesOpen = true

proc addLine(builder: var IndexedDatabaseBuilder, line: string) =
  var seenBytes: set[char]
  for byte in line.searchableKey():
    if byte notin seenBytes:
      seenBytes.incl(byte)
      builder.bucketFiles[ord(byte)].writeRaw(line, "bucket spool")
      builder.bucketFiles[ord(byte)].writeRaw("\n", "bucket spool")

proc closeBucketFiles(builder: var IndexedDatabaseBuilder) =
  if not builder.bucketFilesOpen:
    return
  for i in 0 ..< IndexBuckets:
    builder.bucketFiles[i].close()
  builder.bucketFilesOpen = false

proc finish(builder: var IndexedDatabaseBuilder) =
  builder.path.ensureParent()
  builder.closeBucketFiles()

  var output = open(builder.path, fmWrite)
  defer: output.close()

  let headerLine = header(builder.kind) & "\n"
  output.writeRaw(headerLine, "database header")
  output.writeRaw(newString(IndexSize), "database index")

  var
    index = newStringOfCap(IndexSize)
    offset = 0'u64

  for i in 0 ..< IndexBuckets:
    let length =
      if getFileSize(builder.bucketPaths[i]) == 0: 0'u64
      else: zstdCompressFile(builder.bucketPaths[i], output)
    index.add(putUint64(offset))
    index.add(putUint64(length))
    offset += length

  output.setFilePos(headerLine.len)
  output.writeRaw(index, "database index")
  builder.cleanup()

proc cleanup(spool: var PackageEntrySpool) =
  if spool.partitionFilesOpen:
    for i in 0 ..< PackageSpoolPartitions:
      try:
        spool.partitionFiles[i].close()
      except IOError:
        discard
    spool.partitionFilesOpen = false

  if spool.tempDir.len > 0 and dirExists(spool.tempDir):
    removeDir(spool.tempDir)

proc initPackageEntrySpool(): PackageEntrySpool =
  result.tempDir = makeTempDir()
  for i in 0 ..< PackageSpoolPartitions:
    result.partitionPaths[i] = result.tempDir / $i
    result.partitionFiles[i] = open(result.partitionPaths[i], fmWrite)
  result.partitionFilesOpen = true

proc partitionFor(value: string): int =
  int(uint(hash(value)) and uint(PackageSpoolPartitions - 1))

proc addEntry(spool: var PackageEntrySpool, entry: FileEntry) =
  let packageName = if entry.packages.len > 0: entry.packages[0] else: ""
  let partition = partitionFor(packageName)
  spool.partitionFiles[partition].writeRaw(encodeEntry(entry), "entry spool")
  spool.partitionFiles[partition].writeRaw("\n", "entry spool")

proc closePartitionFiles(spool: var PackageEntrySpool) =
  if not spool.partitionFilesOpen:
    return
  for i in 0 ..< PackageSpoolPartitions:
    spool.partitionFiles[i].close()
  spool.partitionFilesOpen = false

proc isUtf8Boundary(s: string, offset: int): bool =
  offset <= 0 or offset >= s.len or (ord(s[offset]) and 0xc0) != 0x80

proc sharedPrefixLen*(a, b: string): int =
  let maxLen = min(a.len, b.len)
  while result < maxLen and a[result] == b[result]:
    inc result
  while result > 0 and (not a.isUtf8Boundary(result) or
      not b.isUtf8Boundary(result)):
    dec result

proc suffixFrom(path: string, shared: int): string =
  if shared >= path.len: "" else: path[shared .. ^1]

proc indexRecordKey(entry: FileEntry): string =
  entry.path & "\t" & $entry.kind & "\t" & $entry.size & "\t" &
    (if entry.executable: "1" else: "0") & "\t" & entry.target

proc collectIndexRecords(spool: var PackageEntrySpool): seq[FileEntry] =
  spool.closePartitionFiles()
  var byRecord = initTable[string, FileEntry]()

  for i in 0 ..< PackageSpoolPartitions:
    if getFileSize(spool.partitionPaths[i]) == 0:
      continue

    for line in lines(spool.partitionPaths[i]):
      let entry = decodeEntry(line)
      if entry.path.len == 0 or entry.path == "/":
        continue

      let key = entry.indexRecordKey()
      var record =
        if key in byRecord: byRecord[key]
        else: FileEntry(
          path: entry.path,
          size: entry.size,
          kind: entry.kind,
          executable: entry.executable,
          target: entry.target,
          packages: @[],
        )
      for packageName in entry.packages:
        if packageName.len > 0:
          record.packages.add(packageName)
      byRecord[key] = record

  for key in byRecord.keys:
    var record = byRecord[key]
    record.packages.sort()
    var uniquePackages: seq[string]
    for packageName in record.packages:
      if uniquePackages.len == 0 or uniquePackages[^1] != packageName:
        uniquePackages.add(packageName)
    record.packages = uniquePackages
    result.add(record)

  result.sort(proc(a, b: FileEntry): int =
    result = cmp(a.path, b.path)
    if result == 0: result = cmp($a.kind, $b.kind)
    if result == 0: result = cmp(a.target, b.target)
    if result == 0: result = cmp(a.size, b.size)
  )

proc compressString(data, tempDir, name: string): string =
  let
    rawPath = tempDir / (name & ".raw")
    compressedPath = tempDir / (name & ".zst")
  block:
    var raw = open(rawPath, fmWrite)
    raw.writeRaw(data, name & " raw")
    raw.close()
  block:
    var compressed = open(compressedPath, fmWrite)
    discard zstdCompressFile(rawPath, compressed, IndexCompressionLevel)
    compressed.close()
  block:
    var compressed = open(compressedPath, fmRead)
    defer: compressed.close()
    let length = getFileSize(compressedPath)
    if length > BiggestInt(int.high):
      fail("compressed block is too large")
    result = newString(int(length))
    if result.len > 0:
      let read = compressed.readBuffer(addr result[0], result.len)
      if read != result.len:
        fail("truncated compressed block: " & compressedPath)

proc appendVarint(dst: var string, value: uint64) =
  dst.add(putVarint(value))

proc kindCode(kind: FileKind): uint64 =
  case kind
  of fkDirectory: 1
  of fkSymlink: 2
  of fkRegular: 0

proc uniquePathTrigrams(path: string): seq[uint32] =
  var seen = initHashSet[uint32]()
  if path.len < 3:
    return
  for i in 0 .. path.len - 3:
    let trigram =
      (uint32(ord(path[i])) shl 16) or
      (uint32(ord(path[i + 1])) shl 8) or
      uint32(ord(path[i + 2]))
    if trigram notin seen:
      seen.incl(trigram)
      result.add(trigram)

proc encodePackageTable(packageNames: seq[string]): string =
  result.add(putUint32(uint32(packageNames.len)))
  var
    names = ""
    offsets: seq[uint32]
  offsets.add(0'u32)
  for packageName in packageNames:
    names.add(packageName)
    offsets.add(uint32(names.len))
  for offset in offsets:
    result.add(putUint32(offset))
  result.add(names)

proc encodeRecordPayload(
  record: FileEntry,
  previousPath: var string,
  packageIds: Table[string, int],
): string =
  let shared = sharedPrefixLen(previousPath, record.path)
  let suffix = suffixFrom(record.path, shared)
  result.appendVarint(uint64(shared))
  result.appendVarint(uint64(suffix.len))
  result.add(suffix)
  result.appendVarint(uint64(record.packages.len))
  for packageName in record.packages:
    result.appendVarint(uint64(packageIds[packageName]))
  result.appendVarint(record.kind.kindCode())
  result.appendVarint(record.size)
  result.appendVarint(if record.executable: 1'u64 else: 0'u64)
  result.appendVarint(uint64(record.target.len))
  result.add(record.target)
  previousPath = record.path

proc flushIndexV1Block(
  currentRecords: var seq[string],
  currentSize: var int,
  firstRecordId: var uint64,
  compressedOffset: var uint64,
  previousPath: var string,
  tempDir: string,
  blocks: var seq[IndexV1Block],
  output: var string,
) =
  if currentRecords.len == 0:
    return
  var raw = putVarint(uint64(currentRecords.len))
  for recordData in currentRecords:
    raw.add(recordData)
  let compressed = compressString(raw, tempDir, "index-v1-block-" & $blocks.len)
  blocks.add(IndexV1Block(
    firstRecordId: firstRecordId,
    recordCount: uint32(currentRecords.len),
    compressedOffset: compressedOffset,
    compressedLength: uint32(compressed.len),
    uncompressedLength: uint32(raw.len),
  ))
  output.add(compressed)
  firstRecordId += uint64(currentRecords.len)
  compressedOffset += uint64(compressed.len)
  currentRecords.setLen(0)
  currentSize = 0
  previousPath = ""

proc encodeRecordBlocks(
  records: seq[FileEntry],
  packageIds: Table[string, int],
  tempDir: string,
  blocks: var seq[IndexV1Block],
): string =
  var
    currentRecords: seq[string]
    currentSize = 0
    firstRecordId = 0'u64
    compressedOffset = 0'u64
    previousPath = ""
  for record in records:
    var recordData = encodeRecordPayload(record, previousPath, packageIds)
    if currentRecords.len > 0 and currentSize + recordData.len > IndexV1BlockSize:
      flushIndexV1Block(currentRecords, currentSize, firstRecordId,
        compressedOffset, previousPath, tempDir, blocks, result)
      recordData = encodeRecordPayload(record, previousPath, packageIds)
    currentRecords.add(recordData)
    currentSize += recordData.len
  flushIndexV1Block(currentRecords, currentSize, firstRecordId,
    compressedOffset, previousPath, tempDir, blocks, result)

proc encodeBlockTable(blocks: seq[IndexV1Block]): string =
  result.add(putUint32(uint32(blocks.len)))
  for recordBlock in blocks:
    result.add(putUint64(recordBlock.firstRecordId))
    result.add(putUint32(recordBlock.recordCount))
    result.add(putUint64(recordBlock.compressedOffset))
    result.add(putUint32(recordBlock.compressedLength))
    result.add(putUint32(recordBlock.uncompressedLength))

proc encodePostings(
  records: seq[FileEntry],
  trigrams: var seq[IndexV1TrigramEntry],
): string =
  var postingsByTrigram = initTable[uint32, seq[uint64]]()
  for recordId, record in records:
    for trigram in uniquePathTrigrams(record.path):
      postingsByTrigram.mgetOrPut(trigram, @[]).add(uint64(recordId))

  let threshold = max(1, records.len div 8)
  var trigramKeys = toSeq(postingsByTrigram.keys)
  trigramKeys.sort()

  for trigram in trigramKeys:
    let postings = postingsByTrigram[trigram]
    let skipped = postings.len > threshold
    var entry = IndexV1TrigramEntry(
      trigram: trigram,
      flags: if skipped: IndexV1TrigramSkipped else: 0'u8,
      docFreq: uint32(postings.len),
      postingsOffset: uint64(result.len),
      postingsLength: 0'u32,
    )
    if not skipped:
      var previous = 0'u64
      var first = true
      for id in postings:
        result.appendVarint(if first: id else: id - previous)
        previous = id
        first = false
      entry.postingsLength = uint32(uint64(result.len) - entry.postingsOffset)
    trigrams.add(entry)

proc encodeTrigramTable(trigrams: seq[IndexV1TrigramEntry]): string =
  result.add(putUint32(uint32(trigrams.len)))
  for entry in trigrams:
    result.add(char((entry.trigram shr 16) and 0xff'u32))
    result.add(char((entry.trigram shr 8) and 0xff'u32))
    result.add(char(entry.trigram and 0xff'u32))
    result.add(char(entry.flags))
    result.add(putUint32(entry.docFreq))
    result.add(putUint64(entry.postingsOffset))
    result.add(putUint32(entry.postingsLength))

proc sectionEntry(kind: uint16, offset, length: uint64): string =
  result.add(putUint16(kind))
  result.add(putUint16(0'u16))
  result.add(putUint64(offset))
  result.add(putUint64(length))

proc writeIndexV1Database*(path: string, records: seq[FileEntry]) =
  path.ensureParent()
  let tempDir = makeTempDir()
  defer:
    if dirExists(tempDir):
      removeDir(tempDir)

  var packageNames: seq[string]
  for record in records:
    for packageName in record.packages:
      packageNames.add(packageName)
  packageNames.sort()
  var uniquePackages: seq[string]
  for packageName in packageNames:
    if uniquePackages.len == 0 or uniquePackages[^1] != packageName:
      uniquePackages.add(packageName)

  var packageIds = initTable[string, int]()
  for id, packageName in uniquePackages:
    packageIds[packageName] = id

  let packagesSection = encodePackageTable(uniquePackages)
  var blocks: seq[IndexV1Block]
  let blocksSection = encodeRecordBlocks(records, packageIds, tempDir, blocks)
  let blockTableSection = encodeBlockTable(blocks)
  var trigramEntries: seq[IndexV1TrigramEntry]
  let postingsSection = encodePostings(records, trigramEntries)
  let trigramSection = encodeTrigramTable(trigramEntries)

  const sectionCount = 5
  var fixed = ""
  fixed.add(putUint64(uint64(records.len)))
  fixed.add(putUint32(uint32(uniquePackages.len)))
  fixed.add(putUint32(uint32(blocks.len)))
  fixed.add(putUint32(uint32(trigramEntries.len)))
  fixed.add(putUint32(0'u32))
  fixed.add(putUint32(uint32(sectionCount)))

  let sectionTableSize = sectionCount * 20
  var offset = uint64(fixed.len + sectionTableSize)
  var sectionTable = ""
  sectionTable.add(sectionEntry(IndexV1SectionPackages, offset,
      uint64(packagesSection.len)))
  offset += uint64(packagesSection.len)
  sectionTable.add(sectionEntry(IndexV1SectionBlockTable, offset,
      uint64(blockTableSection.len)))
  offset += uint64(blockTableSection.len)
  sectionTable.add(sectionEntry(IndexV1SectionBlocks, offset,
      uint64(blocksSection.len)))
  offset += uint64(blocksSection.len)
  sectionTable.add(sectionEntry(IndexV1SectionTrigrams, offset,
      uint64(trigramSection.len)))
  offset += uint64(trigramSection.len)
  sectionTable.add(sectionEntry(IndexV1SectionPostings, offset,
      uint64(postingsSection.len)))

  var output = open(path, fmWrite)
  defer: output.close()
  output.writeRaw(header(dbIndex) & "\n", "database header")
  output.writeRaw(fixed, "v1 fixed header")
  output.writeRaw(sectionTable, "v1 section table")
  output.writeRaw(packagesSection, "v1 package table")
  output.writeRaw(blockTableSection, "v1 block table")
  output.writeRaw(blocksSection, "v1 record blocks")
  output.writeRaw(trigramSection, "v1 trigram table")
  output.writeRaw(postingsSection, "v1 postings")

proc readExact(file: File, path: string, length: int): string =
  if length == 0:
    return ""

  result = newString(length)
  let read = file.readBuffer(addr result[0], length)
  if read != length:
    fail("truncated database: " & path)

proc indexedBucketLines(path: string, kind: DbKind, bucket: int): seq[string] =
  var file = open(path, fmRead)
  defer: file.close()

  let headerLine = file.readLine()
  if headerLine != header(kind):
    fail("unsupported database format: " & path)

  let
    indexStart = headerLine.len + 1
    dataStart = indexStart + IndexSize
    index = file.readExact(path, IndexSize)

  let entry = bucket * IndexEntrySize
  let
    offset64 = getUint64(index, entry)
    length64 = getUint64(index, entry + 8)
  if offset64 > uint64(int.high) or length64 > uint64(int.high):
    fail("database bucket is too large for this platform")
  let
    offset = int(offset64)
    length = int(length64)
  if length == 0:
    return

  file.setFilePos(dataStart + offset)
  let body = zstdDecompress(file.readExact(path, length))
  for line in body.splitLines():
    if line.len > 0:
      result.add(line)

proc queryBucket(query: string): int =
  if query.len == 0: 0 else: ord(query[0])

proc packageSearchKind(path: string): DbKind =
  var file = open(path, fmRead)
  defer: file.close()

  let headerLine = file.readLine()
  if headerLine == header(dbPackages):
    dbPackages
  elif headerLine == header(dbIndex):
    dbIndex
  else:
    fail("unsupported package database format: " & path)

proc writeIndexedDatabase(path: string, kind: DbKind, lines: seq[string]) =
  var builder = initIndexedDatabaseBuilder(path, kind)
  defer: builder.cleanup()

  for line in lines:
    builder.addLine(line)
  builder.finish()

proc readVarint(data: string, pos: var int): uint64 =
  var shift = 0
  for _ in 0 ..< 10:
    if pos >= data.len:
      fail("truncated varint in v1 index")
    let byte = ord(data[pos])
    inc pos
    result = result or (uint64(byte and 0x7f) shl shift)
    if (byte and 0x80) == 0:
      return
    shift += 7
  fail("malformed varint in v1 index")

proc readBytes(data: string, pos: var int, length: int): string =
  if length < 0 or pos + length > data.len:
    fail("truncated byte slice in v1 index")
  result = data[pos ..< pos + length]
  pos += length

proc requireUtf8(value, label: string) =
  if value.validateUtf8() != -1:
    fail("non-UTF-8 " & label & " in v1 index")

proc readSectionPayload(file: File, path: string, dataStart: int,
    section: IndexV1Section): string =
  if section.offset > uint64(int.high) or section.length > uint64(int.high):
    fail("v1 section is too large")
  let
    start = int(section.offset)
    length = int(section.length)
  if start > int.high - length:
    fail("v1 section slice overflow")
  if dataStart > int.high - start:
    fail("v1 section file offset overflow")
  file.setFilePos(dataStart + start)
  file.readExact(path, length)

proc parseV1Sections(data: string, sectionCount: int,
    payloadLength: uint64): seq[IndexV1Section] =
  if sectionCount > (int.high - 28) div 20:
    fail("v1 section table is too large")
  let tableEnd = 28 + sectionCount * 20
  if sectionCount < 0 or tableEnd > data.len:
    fail("truncated v1 section table")

  for i in 0 ..< sectionCount:
    let base = 28 + i * 20
    result.add(IndexV1Section(
      kind: getUint16(data, base),
      offset: getUint64(data, base + 4),
      length: getUint64(data, base + 12),
    ))

  var ranges: seq[(uint64, uint64)]
  for section in result:
    let endOffset = section.offset + section.length
    if endOffset < section.offset or section.offset < uint64(tableEnd) or
        endOffset > payloadLength:
      fail("v1 section slice out of bounds")
    ranges.add((section.offset, endOffset))
  ranges.sort(proc(a, b: (uint64, uint64)): int = cmp(a[0], b[0]))
  for i in 1 ..< ranges.len:
    if ranges[i - 1][1] > ranges[i][0]:
      fail("overlapping v1 sections")

proc findV1Section(sections: seq[IndexV1Section],
    kind: uint16): IndexV1Section =
  var found = false
  for section in sections:
    if section.kind == kind:
      if found:
        fail("duplicate v1 section")
      result = section
      found = true
  if not found:
    fail("missing v1 section")

proc parseV1Packages(data: string, expectedCount: int): seq[string] =
  if data.len < 4:
    fail("truncated v1 package table")
  let count = int(getUint32(data, 0))
  if count != expectedCount:
    fail("v1 package count mismatch")
  let namesStart = 4 + (count + 1) * 4
  if namesStart > data.len:
    fail("truncated v1 package offset table")
  let names = data[namesStart .. ^1]
  var offsets: seq[int]
  for i in 0 .. count:
    offsets.add(int(getUint32(data, 4 + i * 4)))
  for i in 1 ..< offsets.len:
    if offsets[i - 1] > offsets[i] or offsets[i] > names.len:
      fail("invalid v1 package string offset")
  for i in 0 ..< count:
    let packageName = names[offsets[i] ..< offsets[i + 1]]
    packageName.requireUtf8("package string")
    result.add(packageName)

proc parseV1Blocks(data: string, expectedCount: int,
    recordCount, blocksLength: uint64): seq[IndexV1DecodedBlock] =
  if data.len < 4:
    fail("truncated v1 block table")
  let count = int(getUint32(data, 0))
  if count != expectedCount or data.len != 4 + count * 28:
    fail("v1 block table length mismatch")

  var
    expectedRecordId = 0'u64
    expectedOffset = 0'u64
  for i in 0 ..< count:
    let base = 4 + i * 28
    let recordBlock = IndexV1DecodedBlock(
      firstRecordId: getUint64(data, base),
      recordCount: getUint32(data, base + 8),
      compressedOffset: getUint64(data, base + 12),
      compressedLength: getUint32(data, base + 20),
      uncompressedLength: getUint32(data, base + 24),
    )
    if recordBlock.firstRecordId != expectedRecordId or
        recordBlock.compressedOffset != expectedOffset:
      fail("non-contiguous v1 record blocks")
    if uint64(recordBlock.recordCount) > uint64.high - expectedRecordId or
        uint64(recordBlock.compressedLength) > uint64.high - expectedOffset:
      fail("v1 block table overflow")
    expectedRecordId += uint64(recordBlock.recordCount)
    expectedOffset += uint64(recordBlock.compressedLength)
    result.add(recordBlock)
  if expectedRecordId != recordCount or expectedOffset != blocksLength:
    fail("v1 record block table does not cover index")

proc parseV1Trigrams(data: string, expectedCount: int, postingsLength: int,
    recordCount: uint64): seq[IndexV1TrigramEntry] =
  if data.len < 4:
    fail("truncated v1 trigram table")
  let count = int(getUint32(data, 0))
  if count != expectedCount or data.len != 4 + count * 20:
    fail("v1 trigram table length mismatch")
  var previous: uint32
  for i in 0 ..< count:
    let base = 4 + i * 20
    let trigram =
      (uint32(ord(data[base])) shl 16) or
      (uint32(ord(data[base + 1])) shl 8) or
      uint32(ord(data[base + 2]))
    if i > 0 and previous >= trigram:
      fail("v1 trigram table is not sorted")
    previous = trigram
    let entry = IndexV1TrigramEntry(
      trigram: trigram,
      flags: uint8(ord(data[base + 3])),
      docFreq: getUint32(data, base + 4),
      postingsOffset: getUint64(data, base + 8),
      postingsLength: getUint32(data, base + 16),
    )
    let postingsEnd = entry.postingsOffset + uint64(entry.postingsLength)
    if postingsEnd < entry.postingsOffset or postingsEnd > uint64(postingsLength):
      fail("v1 postings slice out of bounds")
    if (entry.flags and IndexV1TrigramSkipped) != 0 and entry.postingsLength != 0:
      fail("skipped v1 trigram has postings")
    if (entry.flags and IndexV1TrigramSkipped) == 0 and
        uint64(entry.docFreq) > recordCount:
      fail("v1 trigram doc frequency too large")
    result.add(entry)

proc decodeV1Postings(entry: IndexV1TrigramEntry, postings: string,
    recordCount: uint64): seq[uint64] =
  let
    start = int(entry.postingsOffset)
    stop = start + int(entry.postingsLength)
  if start < 0 or stop > postings.len:
    fail("v1 postings slice out of bounds")
  var
    pos = start
    current = 0'u64
  for i in 0 ..< int(entry.docFreq):
    let value = readVarint(postings, pos)
    if i == 0:
      current = value
    else:
      if value > uint64.high - current:
        fail("v1 posting id overflow")
      current += value
    if current >= recordCount:
      fail("v1 posting id out of bounds")
    if result.len > 0 and result[^1] >= current:
      fail("non-monotonic v1 postings")
    result.add(current)
  if pos != stop:
    fail("trailing bytes in v1 postings")

proc uniqueQueryTrigrams(query: string): seq[uint32] =
  uniquePathTrigrams(query)

proc intersectSorted(a, b: seq[uint64]): seq[uint64] =
  var
    i = 0
    j = 0
  while i < a.len and j < b.len:
    if a[i] == b[j]:
      result.add(a[i])
      inc i
      inc j
    elif a[i] < b[j]:
      inc i
    else:
      inc j

proc decodeV1Block(raw: string, firstRecordId: uint64, expectedCount: uint32,
    packages: seq[string]): seq[(uint64, FileEntry)] =
  var
    pos = 0
    previousPath = ""
  let count = readVarint(raw, pos)
  if count != uint64(expectedCount):
    fail("v1 record block count mismatch")

  for i in 0 ..< int(count):
    let
      shared = int(readVarint(raw, pos))
      suffixLength = int(readVarint(raw, pos))
    if shared > previousPath.len or not previousPath.isUtf8Boundary(shared):
      fail("invalid v1 path prefix boundary")
    let suffix = readBytes(raw, pos, suffixLength)
    suffix.requireUtf8("path suffix")
    let path = previousPath[0 ..< shared] & suffix
    path.requireUtf8("path string")
    previousPath = path

    let packageCount = int(readVarint(raw, pos))
    var recordPackages: seq[string]
    for _ in 0 ..< packageCount:
      let packageId = int(readVarint(raw, pos))
      if packageId < 0 or packageId >= packages.len:
        fail("invalid v1 package id")
      recordPackages.add(packages[packageId])

    let kind = case readVarint(raw, pos)
      of 1: fkDirectory
      of 2: fkSymlink
      else: fkRegular
    let
      size = readVarint(raw, pos)
      executable = readVarint(raw, pos) != 0
      targetLength = int(readVarint(raw, pos))
      target = readBytes(raw, pos, targetLength)
    target.requireUtf8("target string")
    result.add((firstRecordId + uint64(i), FileEntry(
      path: path,
      packages: recordPackages,
      size: size,
      kind: kind,
      executable: executable,
      target: target,
    )))

  if pos != raw.len:
    fail("trailing bytes in v1 record block")

proc blockForRecord(blocks: seq[IndexV1DecodedBlock], recordId: uint64): int =
  for i, recordBlock in blocks:
    if uint64(recordBlock.recordCount) > uint64.high -
        recordBlock.firstRecordId:
      fail("v1 record block id overflow")
    let endId = recordBlock.firstRecordId + uint64(recordBlock.recordCount)
    if recordId >= recordBlock.firstRecordId and recordId < endId:
      return i
  fail("v1 candidate record id has no block")

proc matchingIndexV1*(path, query: string): seq[FileEntry] =
  var file = open(path, fmRead)
  defer: file.close()
  let headerLine = file.readLine()
  if headerLine != header(dbIndex):
    fail("unsupported database format: " & path)
  let
    dataStart = int(file.getFilePos())
    payloadLength = getFileSize(path) - file.getFilePos()
  if payloadLength > BiggestInt(int.high):
    fail("v1 index is too large for this platform")
  let fixed = file.readExact(path, 28)
  if fixed.len < 28:
    fail("truncated v1 index header")

  let
    recordCount = getUint64(fixed, 0)
    packageCount = int(getUint32(fixed, 8))
    blockCount = int(getUint32(fixed, 12))
    trigramCount = int(getUint32(fixed, 16))
    sectionCount = int(getUint32(fixed, 24))
  if sectionCount > int.high div 20:
    fail("v1 section table is too large")
  let
    sectionTable = file.readExact(path, sectionCount * 20)
    sections = parseV1Sections(fixed & sectionTable, sectionCount,
      uint64(payloadLength))
    packagesSection = sections.findV1Section(IndexV1SectionPackages)
    blockTableSection = sections.findV1Section(IndexV1SectionBlockTable)
    blocksSection = sections.findV1Section(IndexV1SectionBlocks)
    trigramsSection = sections.findV1Section(IndexV1SectionTrigrams)
    postingsSection = sections.findV1Section(IndexV1SectionPostings)
    packages = parseV1Packages(file.readSectionPayload(path, dataStart,
      packagesSection), packageCount)
    blocks = parseV1Blocks(file.readSectionPayload(path, dataStart,
      blockTableSection), blockCount,
      recordCount, blocksSection.length)
    postings = file.readSectionPayload(path, dataStart, postingsSection)
    trigrams = parseV1Trigrams(file.readSectionPayload(path, dataStart,
      trigramsSection),
      trigramCount, postings.len, recordCount)

  var trigramIndex = initTable[uint32, IndexV1TrigramEntry]()
  for entry in trigrams:
    trigramIndex[entry.trigram] = entry
    if (entry.flags and IndexV1TrigramSkipped) == 0:
      discard decodeV1Postings(entry, postings, recordCount)

  var candidates: seq[uint64]
  if query.len < 3:
    for recordId in 0'u64 ..< recordCount:
      candidates.add(recordId)
  else:
    var postingLists: seq[seq[uint64]]
    for trigram in uniqueQueryTrigrams(query):
      if trigram notin trigramIndex:
        return
      let entry = trigramIndex[trigram]
      if (entry.flags and IndexV1TrigramSkipped) == 0:
        postingLists.add(decodeV1Postings(entry, postings, recordCount))
    if postingLists.len == 0:
      for recordId in 0'u64 ..< recordCount:
        candidates.add(recordId)
    else:
      postingLists.sort(proc(a, b: seq[uint64]): int = cmp(a.len, b.len))
      candidates = postingLists[0]
      for i in 1 ..< postingLists.len:
        candidates = intersectSorted(candidates, postingLists[i])
        if candidates.len == 0:
          return

  var byBlock = initTable[int, seq[uint64]]()
  for recordId in candidates:
    byBlock.mgetOrPut(blockForRecord(blocks, recordId), @[]).add(recordId)
  var blockIds = toSeq(byBlock.keys)
  blockIds.sort()
  for blockId in blockIds:
    let recordBlock = blocks[blockId]
    let
      start = int(recordBlock.compressedOffset)
      length = int(recordBlock.compressedLength)
    if start > int.high - length:
      fail("v1 compressed block slice overflow")
    let stop = start + length
    if start < 0 or stop > int(blocksSection.length):
      fail("v1 compressed block slice out of bounds")
    if dataStart > int.high - int(blocksSection.offset) or
        dataStart + int(blocksSection.offset) > int.high - start:
      fail("v1 compressed block file offset overflow")
    file.setFilePos(dataStart + int(blocksSection.offset) + start)
    let raw = zstdDecompress(file.readExact(path, length))
    if raw.len != int(recordBlock.uncompressedLength):
      fail("v1 record block length mismatch")
    let wanted = byBlock[blockId].toHashSet()
    for (recordId, entry) in decodeV1Block(raw, recordBlock.firstRecordId,
        recordBlock.recordCount, packages):
      if recordId in wanted and query in entry.path:
        result.add(entry)

proc compact(value: string): string =
  value.splitWhitespace().join(" ")

proc stringField(node: JsonNode, key: string): string =
  if node.kind == JObject and node.hasKey(key) and node[key].kind == JString:
    node[key].getStr()
  else:
    ""

proc optionSummary(node: JsonNode): string =
  if node.kind != JObject:
    return ""

  for key in ["description", "type", "defaultText"]:
    if not node.hasKey(key):
      continue

    case node[key].kind
    of JString:
      return compact(node[key].getStr())
    of JObject:
      let text = node[key].stringField("text")
      if text.len > 0:
        return compact(text)
    else:
      discard

  ""

proc isOptionNode(node: JsonNode): bool =
  node.kind == JObject and node.hasKey("loc") and node.hasKey("type")

proc optionRecords(options: JsonNode): seq[OptionRecord] =
  for name, node in options:
    if isOptionNode(node):
      result.add(OptionRecord(name: name, summary: optionSummary(node)))

  result.sort(proc(a, b: OptionRecord): int = cmp(a.name, b.name))

proc writeOptionsDatabase(path: string, records: seq[OptionRecord]) =
  var lines: seq[string]
  for record in records:
    lines.add(record.name & "\t" & record.summary)
  writeIndexedDatabase(path, dbOptions, lines)

proc parseOptions(lines: seq[string]): seq[OptionRecord] =
  for line in lines:
    let tab = line.find('\t')
    if tab < 0:
      result.add(OptionRecord(name: line))
    else:
      result.add(OptionRecord(name: line[0 ..< tab], summary: line[tab + 1 .. ^1]))

proc matchingOptions(records: seq[OptionRecord], query: string): seq[OptionRecord] =
  for record in records:
    if query in record.name:
      result.add(record)

proc loadMatchingOptionsDatabase(path, query: string): seq[OptionRecord] =
  matchingOptions(parseOptions(indexedBucketLines(path, dbOptions,
      query.queryBucket)), query)

proc printOptions(records: seq[OptionRecord], jsonOutput: bool) =
  if jsonOutput:
    var output = newJArray()
    for record in records:
      var item = %* {"name": record.name}
      if record.summary.len > 0:
        item["summary"] = %record.summary
      output.add(item)
    echo output.pretty()
  else:
    for record in records:
      echo record.name

proc searchOptionsJson(config: Config) =
  let records = optionRecords(parseFile(config.moduleOptions))
  printOptions(matchingOptions(records, config.query), config.jsonOutput)

proc searchOptionsDb(config: Config) =
  printOptions(loadMatchingOptionsDatabase(config.database, config.query),
    config.jsonOutput)

proc packageName(attr, pname, version, output: string): string =
  result = if attr.len > 0: attr else: pname
  if version.len > 0 and version notin result:
    result &= "-" & version
  if output.len > 0 and output != "out":
    result &= "." & output

proc addOutput(
  outputs: var seq[PackageOutput],
  attr, pname, version, output, path: string,
) =
  if path.len == 0 or not dirExists(path):
    return

  outputs.add(PackageOutput(
    name: packageName(attr, pname, version, output),
    path: path,
  ))

proc packageOutputs(attr: string, node: JsonNode): seq[PackageOutput] =
  case node.kind
  of JString:
    result.addOutput(attr, attr, "", "out", node.getStr())
  of JObject:
    let attrField = node.stringField("attr")
    let pnameField = node.stringField("pname")
    let
      realAttr = if attrField.len > 0: attrField else: attr
      pname = if pnameField.len > 0: pnameField else: realAttr
      version = node.stringField("version")

    let path = node.stringField("path")
    if path.len > 0:
      result.addOutput(realAttr, pname, version, "out", path)

    if not node.hasKey("outputs"):
      return

    let outputs = node["outputs"]
    case outputs.kind
    of JObject:
      for output, outputPath in outputs:
        if outputPath.kind == JString:
          result.addOutput(realAttr, pname, version, output, outputPath.getStr())
    of JArray:
      for outputPath in outputs:
        if outputPath.kind == JString:
          result.addOutput(realAttr, pname, version, "out", outputPath.getStr())
    of JString:
      result.addOutput(realAttr, pname, version, "out", outputs.getStr())
    else:
      discard
  else:
    discard

proc manifestOutputs(manifest: JsonNode): seq[PackageOutput] =
  case manifest.kind
  of JArray:
    for item in manifest:
      if item.kind == JObject:
        result.add(packageOutputs(item.stringField("attr"), item))
  of JObject:
    for attr, node in manifest:
      result.add(packageOutputs(attr, node))
  else:
    fail("manifest must be a JSON array or object")

proc relativeStorePath(root, path: string): string =
  result = relativePath(path, root)
  when defined(windows):
    result = result.replace('\\', '/')
  if result == ".":
    result = "/"
  else:
    result = "/" & result

proc packageFileRecords(
  outputs: seq[PackageOutput],
): Table[string, HashSet[string]] =
  result = initTable[string, HashSet[string]]()
  for output in outputs:
    for filePath in walkDirRec(output.path, yieldFilter = {pcFile,
        pcLinkToFile}):
      let rel = relativeStorePath(output.path, filePath)
      if rel != "/":
        result.mgetOrPut(rel, initHashSet[string]()).incl(output.name)

proc writePackagesDatabaseLegacy(
  path: string,
  records: Table[string, HashSet[string]],
) =
  ## Write a packages database in the legacy (path\tpkg,...) format.
  var paths = toSeq(records.keys)
  paths.sort()

  var lines: seq[string]
  for p in paths:
    var packages = toSeq(records[p])
    packages.sort()
    lines.add(p & "\t" & packages.join(","))
  writeIndexedDatabase(path, dbPackages, lines)

proc parsePackages(lines: seq[string]): seq[FileEntry] =
  for line in lines:
    let entry = decodeEntry(line)
    if entry.path.len > 0:
      result.add(entry)

proc matchingPackages(records: seq[FileEntry], query: string): seq[FileEntry] =
  for record in records:
    if query in record.path:
      result.add(record)

proc loadMatchingPackagesDatabase(path, query: string): seq[FileEntry] =
  let kind = path.packageSearchKind
  case kind
  of dbPackages:
    matchingPackages(parsePackages(indexedBucketLines(path, kind,
        query.queryBucket)), query)
  of dbIndex:
    matchingIndexV1(path, query)
  of dbOptions:
    fail("unsupported package database format: " & path)

proc printPackages(records: seq[FileEntry], jsonOutput: bool) =
  if jsonOutput:
    var output = newJArray()
    for record in records:
      var item = %* {
        "path": record.path,
        "packages": record.packages,
        "size": record.size,
        "kind": $record.kind,
        "executable": record.executable,
      }
      if record.target.len > 0:
        item["target"] = %record.target
      output.add(item)
    echo output.pretty()
  else:
    for record in records:
      let sizeStr = if record.size > 0: $record.size else: "-"
      let execFlag = if record.executable: "x" else: " "
      let kindChar = case record.kind
        of fkDirectory: "d"
        of fkSymlink: "l"
        else: execFlag
      echo kindChar & " " & sizeStr & "\t" & record.path & "\t" &
        record.packages.join(", ")

proc countOptionShapes(manifest: JsonNode): tuple[options, other: int] =
  if manifest.kind != JObject:
    return

  for _, node in manifest:
    if isOptionNode(node):
      inc result.options
    else:
      inc result.other

proc buildDatabase(config: Config) =
  let manifest = parseFile(config.manifest)
  let optionShapes = countOptionShapes(manifest)

  if optionShapes.options > 0:
    if optionShapes.other > 0:
      fail("manifest mixes options with non-option entries")

    let records = optionRecords(manifest)
    writeOptionsDatabase(config.output, records)
    if config.jsonOutput:
      echo( %* {"kind": "options", "options": records.len,
          "output": config.output})
    else:
      stderr.writeLine(&"indexed {records.len} options")
    return

  let outputs = manifestOutputs(manifest)
  if outputs.len == 0:
    fail("manifest did not contain options or existing package output paths")

  let records = packageFileRecords(outputs)
  writePackagesDatabaseLegacy(config.output, records)
  if config.jsonOutput:
    echo( %* {"kind": "packages", "paths": records.len, "outputs": outputs.len,
        "output": config.output})
  else:
    stderr.writeLine(&"indexed {records.len} file paths from {outputs.len} outputs")

proc runIndex(config: Config) =
  ## Execute 'spam index': autonomous binary-cache indexing.
  let outPath =
    if config.output.len > 0: config.output
    else: config.database

  outPath.ensureParent()

  var opts = defaultIndexOptions()
  opts.cacheUrl = config.indexCacheUrl
  opts.nixpkgs = config.indexNixpkgs
  opts.system = config.indexSystem
  opts.scope = config.indexScope
  opts.maxConcurrent = config.indexConcurrent
  opts.followRefs = config.indexFollowRefs
  opts.verbose = config.verbose

  if opts.verbose:
    stderr.writeLine("spam: starting autonomous index -> " & outPath)

  var spool = initPackageEntrySpool()
  defer: spool.cleanup()

  let rawEntries = waitFor buildIndexDatabase(opts, proc(entry: FileEntry) =
    spool.addEntry(entry)
  )

  let records = spool.collectIndexRecords()
  writeIndexV1Database(outPath, records)

  if config.jsonOutput:
    echo( %* {"kind": "index", "format": "v1", "files": records.len,
        "entries": rawEntries,
        "output": outPath})
  else:
    stderr.writeLine(&"indexed {records.len} file paths ({rawEntries} entries) -> {outPath}")

proc main() {.used.} =
  let config = parseArgs()
  validate(config)

  case config.command
  of cmdOpt:
    case config.optSource
    of optSourceJson:
      searchOptionsJson(config)
    of optSourceDb:
      searchOptionsDb(config)
    of optSourceNone:
      discard
  of cmdPkg:
    printPackages(loadMatchingPackagesDatabase(config.database, config.query),
      config.jsonOutput)
  of cmdDb:
    buildDatabase(config)
  of cmdIndex:
    runIndex(config)
  of cmdNone:
    discard

when isMainModule:
  main()
