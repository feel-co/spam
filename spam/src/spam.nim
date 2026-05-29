import std/[algorithm, asyncdispatch, json, os, parseopt, sequtils, sets,
    strformat, strutils, tables]
import filemeta
import cache
import index

{.passL: "-lzstd".}

const
  DbMagic = "# spam-db-v1"
  DefaultDbName = "spam/files.db"
  IndexBuckets = 256
  IndexEntrySize = 8
  IndexSize = IndexBuckets * IndexEntrySize
  ZstdContentSizeError = uint64.high
  ZstdContentSizeUnknown = uint64.high - 1

type
  Command = enum
    cmdNone, cmdOpt, cmdPkg, cmdDb, cmdIndex

  DbCommand = enum
    dbNone, dbBuild

  OptSource = enum
    optSourceNone, optSourceJson, optSourceDb

  DbKind = enum
    dbOptions, dbPackages

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

  FileRecord = object
    path: string
    packages: seq[string]

  PackageOutput = object
    name: string
    path: string

proc zstdCompressBound(srcSize: csize_t): csize_t {.importc: "ZSTD_compressBound".}
proc zstdCompress(
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  srcSize: csize_t,
  compressionLevel: cint,
): csize_t {.importc: "ZSTD_compress".}
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
             [--system <system>] [--scope <attr>] [--concurrent <n>] [--verbose]
  spam --help

Commands:
  opt       Search an options.json produced by nixosOptionsDoc.
  pkg       Search a spam package-file database.
  db build  Build a package-file or option database from a local manifest JSON.
  index     Autonomously index nixpkgs by fetching file listings from the
            binary cache. Equivalent to nix-index, but uses spam's bucket-
            indexed database format for faster queries.

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
      --concurrent <n>     Maximum parallel HTTP requests (default: 512).
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
    longNoVal = @["help", "json", "verbose", "no-follow-refs"],
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

proc ensureParent(path: string) =
  let dir = path.parentDir()
  if dir.len > 0:
    createDir(dir)

proc putUint32(value: uint32): string =
  for shift in countup(0, 24, 8):
    result.add(char((value shr shift) and 0xff'u32))

proc getUint32(data: string, offset: int): uint32 =
  if offset + 4 > data.len:
    fail("truncated database index")

  for shift in countup(0, 24, 8):
    result = result or (uint32(data[offset + shift div 8]) shl shift)

proc zstdCompress(input: string): string =
  if input.len == 0:
    return ""

  result = newString(int(zstdCompressBound(csize_t(input.len))))
  let compressedSize = zstdCompress(addr result[0], csize_t(result.len),
    unsafeAddr input[0], csize_t(input.len), 3)
  if zstdIsError(compressedSize) != 0:
    fail("zstd compression failed: " & $zstdGetErrorName(compressedSize))
  result.setLen(int(compressedSize))

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
    offset = int(getUint32(index, entry))
    length = int(getUint32(index, entry + 4))
  if length == 0:
    return

  file.setFilePos(dataStart + offset)
  let body = zstdDecompress(file.readExact(path, length))
  for line in body.splitLines():
    if line.len > 0:
      result.add(line)

proc queryBucket(query: string): int =
  if query.len == 0: 0 else: ord(query[0])

proc writeIndexedDatabase(path: string, kind: DbKind, lines: seq[string]) =
  path.ensureParent()

  var buckets: array[IndexBuckets, seq[string]]
  for line in lines:
    var seenBytes: set[char]
    let key = line.searchableKey()
    for byte in key:
      if byte notin seenBytes:
        seenBytes.incl(byte)
        buckets[ord(byte)].add(line)

  var
    index = newStringOfCap(IndexSize)
    payload = ""
    offset = 0'u32

  for bucket in buckets:
    let compressed =
      if bucket.len == 0: ""
      else: zstdCompress(bucket.join("\n") & "\n")
    if offset.uint64 + compressed.len.uint64 > uint32.high.uint64:
      fail("database is too large for the index")
    index.add(putUint32(offset))
    index.add(putUint32(uint32(compressed.len)))
    payload.add(compressed)
    offset += uint32(compressed.len)

  writeFile(path, header(kind) & "\n" & index & payload)

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

proc fileEntriesToLines(entries: seq[FileEntry]): seq[string] =
  ## Encode extended FileEntry records to database lines.
  for e in entries:
    result.add(encodeEntry(e))

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

proc writePackagesDatabaseExtended(path: string, entries: seq[FileEntry]) =
  ## Write a packages database with full file metadata.
  writeIndexedDatabase(path, dbPackages, fileEntriesToLines(entries))

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
  matchingPackages(parsePackages(indexedBucketLines(path, dbPackages,
      query.queryBucket)), query)

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

  let entries = waitFor buildIndexDatabase(opts)

  writePackagesDatabaseExtended(outPath, entries)

  if config.jsonOutput:
    echo( %* {"kind": "packages", "files": entries.len, "output": outPath})
  else:
    stderr.writeLine(&"indexed {entries.len} file paths -> {outPath}")

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
