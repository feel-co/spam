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
import filemeta
import cache
import index

{.passL: "-lzstd".}

const
  DbMagic = "# spam-db-v2"
  DefaultDbName = "spam/files.db"
  IndexBuckets = 256
  IndexEntrySize = 16
  IndexSize = IndexBuckets * IndexEntrySize
  PackageSpoolPartitions = 256
  ZstdBufferSize = 128 * 1024
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

proc getUint64(data: string, offset: int): uint64 =
  if offset + 8 > data.len:
    fail("truncated database index")

  for shift in countup(0, 56, 8):
    result = result or (uint64(data[offset + shift div 8]) shl shift)

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

proc zstdCompressFile(inputPath: string, output: File): uint64 =
  let stream = zstdCreateCStream()
  if stream == nil:
    fail("zstd compression failed: could not create stream")
  defer:
    discard zstdFreeCStream(stream)

  checkedZstd(zstdInitCStream(stream, 3), "zstd compression failed")
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

proc partitionFor(path: string): int =
  int(uint(hash(path)) and uint(PackageSpoolPartitions - 1))

proc addEntry(spool: var PackageEntrySpool, entry: FileEntry) =
  let partition = partitionFor(entry.path)
  spool.partitionFiles[partition].writeRaw(encodeEntry(entry), "entry spool")
  spool.partitionFiles[partition].writeRaw("\n", "entry spool")

proc closePartitionFiles(spool: var PackageEntrySpool) =
  if not spool.partitionFilesOpen:
    return
  for i in 0 ..< PackageSpoolPartitions:
    spool.partitionFiles[i].close()
  spool.partitionFilesOpen = false

proc mergeInto(
  spool: var PackageEntrySpool,
  builder: var IndexedDatabaseBuilder,
): int =
  spool.closePartitionFiles()

  for i in 0 ..< PackageSpoolPartitions:
    if getFileSize(spool.partitionPaths[i]) == 0:
      continue

    var
      packagesByPath = initTable[string, HashSet[string]]()
      metadataByPath = initTable[string, FileEntry]()

    for line in lines(spool.partitionPaths[i]):
      let entry = decodeEntry(line)
      if entry.path.len == 0:
        continue
      metadataByPath[entry.path] = entry
      for packageName in entry.packages:
        packagesByPath.mgetOrPut(entry.path, initHashSet[string]()).incl(packageName)

    var paths = toSeq(packagesByPath.keys)
    paths.sort()
    for path in paths:
      var entry = metadataByPath[path]
      entry.packages = toSeq(packagesByPath[path])
      entry.packages.sort()
      builder.addLine(encodeEntry(entry))
      inc result

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
  matchingPackages(parsePackages(indexedBucketLines(path,
      path.packageSearchKind, query.queryBucket)), query)

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

  var builder = initIndexedDatabaseBuilder(outPath, dbIndex)
  defer: builder.cleanup()
  let entries = spool.mergeInto(builder)

  builder.finish()

  if config.jsonOutput:
    echo( %* {"kind": "index", "files": entries, "entries": rawEntries,
        "output": outPath})
  else:
    stderr.writeLine(&"indexed {entries} file paths ({rawEntries} entries) -> {outPath}")

proc main() =
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
