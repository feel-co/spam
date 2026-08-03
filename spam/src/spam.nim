## spam - search Nix packages, module options and library functions
##
## `spam` has two verbs. `spam search` queries a database, `spam index` builds
## one. Both work in terms of the same three scopes: `pkg` for package file
## paths, `opt` for NixOS module options, and `lib` for documented Nix library
## functions.
##
## Usage
## =====
##
## ```
##
##   spam search [--scope LIST] [--pkg] [--opt] [--lib] [--db DB] QUERY
##   spam index --nixpkgs PATH --output DB
##   spam index --manifest packages.json --output DB
##   spam index --options options.json --output DB
##   spam index --nix ./lib --prefix lib --output DB
## ```
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
##   Path to a database. Defaults to `$XDG_CACHE_HOME/spam/spam.db`.
##
## `--verbose`
##   Print progress to stderr.
##
## Search
## ======
##
## ```
##
##   spam search ripgrep
##   spam search --lib mapAttrs
##   spam search --scope pkg,opt firewall
##   spam search --nix ./lib --prefix lib concatStrings
##   spam search --module-options options.json networking.firewall
## ```
##
## A search with no scope selected covers every scope the database carries.
## `--scope` takes a comma-separated list or `all`; `--pkg`, `--opt` and `--lib`
## are shorthand for adding a single scope to it.
##
## Package matches are substring matches against store-output-relative paths, so
## `bin/foo` matches `/bin/foo`. Option and library matches are substring
## matches against the option or attribute name.
##
## Two options search a source directly instead of a database, which is the mode
## intended for files you are working on. Either one implies its own scope.
##
## `--module-options <path>`
##   Search an `options.json` produced by `nixosOptionsDoc`.
##
## `--nix <path>` (with optional `--prefix <attr>`)
##   Scan a Nix file or directory for RFC 145 `/** … */` doc comments. Comments
##   are parsed by `nixdoc`; locating them and binding each to the attribute it
##   documents is a lexical scan, so files that do not evaluate, or do not yet
##   parse completely, still yield results. Because the scan sees only the
##   binding site, `lib/strings.nix` yields `concatStrings` rather than
##   `lib.strings.concatStrings`; `--prefix` supplies the enclosing attribute
##   path. Doc comments that document no binding, such as a file-level comment
##   above `{ lib }:`, are not indexed, as there is no name to record them under.
##
## Indexing
## ========
##
## `spam index` writes one database. Each source option contributes one scope,
## and several may be combined into a single file.
##
## ```
##
##   spam index --manifest packages.json --nix ./lib --output all.db
## ```
##
## `--nixpkgs <path>`
##   Index nixpkgs itself. Packages are enumerated with
##   `nix-env -qaP --xml --out-path` and their file listings fetched from a Nix
##   binary cache; library functions are scanned from the tree's `lib`
##   directory; module options are read from a `nixosOptionsDoc` build. All
##   three scopes are produced unless `--scope` narrows the set. The value is a
##   path, or a quoted search-path form such as `--nixpkgs '<nixpkgs>'`.
##
## `--manifest <path>`
##   Index the file paths of already-realized store outputs described by a JSON
##   manifest. Store hashes are not recorded; paths are stored relative to each
##   output and deduplicated across packages. Supported shapes are an array of
##   package objects, an object mapping attr names to store paths, and an object
##   mapping attr names to named output paths.
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
## `--options <path>`
##   Index an `options.json` produced by `nixosOptionsDoc`.
##
## `--nix <path>` (with optional `--prefix <attr>`)
##   Index documented attributes found by scanning a Nix file or directory.
##
## Options that only affect `--nixpkgs`:
##
## `--cache-url <url>`
##   Binary cache URL. Defaults to `https://cache.nixos.org`.
##
## `--system <system>`
##   Override the target system, for example `x86_64-linux`.
##
## `--attr-set <attr>`
##   Limit package indexing to a single attr set, for example `python3Packages`.
##
## `--attrs <attrs>`
##   Limit package indexing to a comma-separated list of explicit attr paths,
##   for example `hello,gitMinimal,ripgrep`. This is intended for bounded
##   benchmarks that must not enumerate all of nixpkgs.
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
## Report issues at <https://github.com/feel-co/spam/issues>.

import std/[algorithm, asyncdispatch, hashes, json, os, parseopt, sequtils,
    sets, strformat, strutils, tables]
from std/unicode import validateUtf8
import filemeta
import cache
import dbformat
import index
import indexv2
import zstdffi
import libindex
import nixdoc
import nixeval

export filemeta.sharedPrefixLen

const
  DefaultDbName = "spam/spam.db"
  IndexBuckets = 256
  IndexEntrySize = 16
  IndexSize = IndexBuckets * IndexEntrySize
  PackageSpoolPartitions = 256
  ZstdBufferSize = 128 * 1024
  BucketCompressionLevel = 3
  IndexCompressionLevel = 19
  IndexV1BlockSize = 128 * 1024
  IndexV1SectionPackages = 1'u16
  IndexV1SectionBlockTable = 2'u16
  IndexV1SectionBlocks = 3'u16
  IndexV1SectionTrigrams = 4'u16
  IndexV1SectionPostings = 5'u16
  IndexV1TrigramSkipped = 1'u8
  MinPathsForCoverageCheck = 100
    ## Below this many store paths the listing-coverage ratio is noise.
  MinListingCoveragePercent = 10
    ## For nixpkgs unstable roughly 94% of enumerated store paths have a
    ## listing in the cache, so anything under this is a spam-side failure,
    ## not an absent-object one.

type
  Command = enum
    cmdNone, cmdSearch, cmdIndex

  Config = object
    command: Command
    jsonOutput: bool
    verbose: bool
    database: string
    output: string
    query: string
    scopes: ScopeSet
      ## Scopes named on the command line. Empty means "whatever is there".
    ## Sources. Each implies its own scope.
    manifest: string
    moduleOptions: string
    libSource: string
    libPrefix: string
    ## Options for indexing nixpkgs
    indexNixpkgs: string
    indexSystem: string
    indexAttrSet: string
    indexAttrs: seq[string]
    indexCacheUrl: string
    indexConcurrent: int
    indexFollowRefs: bool

  OptionRecord = object
    name: string
    summary: string

  LibRecord = object
    ## A documented Nix library function, as stored in a lib database.
    name: string
    summary: string
    typeSig: string
    location: string
    deprecated: bool

  PackageOutput = object
    name: string
    path: string

  IndexedDatabaseBuilder = object
    path: string
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

proc fail(message: string) {.noreturn.} =
  stderr.writeLine("spam: " & message)
  quit(1)

proc showHelp() {.noreturn.} =
  stdout.write("""
spam - search Nix packages, module options and library functions

Usage:
  spam search [--scope <list>] [--pkg] [--opt] [--lib] [--db <path>]
              [--module-options <path>] [--nix <path>] [--prefix <attr>]
              [--json] <query>
  spam index  [--nixpkgs <path>] [--manifest <path>] [--options <path>]
              [--nix <path>] [--prefix <attr>] [--scope <list>]
              [--output <path>] [--json] [--verbose] [index options]
  spam --help

Commands:
  search    Search a database, or a source given directly on the command line.
  index     Build a database from nixpkgs, a manifest, an options.json or a
            Nix tree. Sources may be combined into one database.

Scopes:
  pkg       Package file paths.
  opt       NixOS module options.
  lib       Documented Nix library functions.

Global options:
  -h, --help         Show this help text.
      --json         Emit JSON results.
      --verbose      Print progress to stderr.
      --db <path>    Database path. Defaults to $XDG_CACHE_HOME/""" &
      DefaultDbName & """.
      --scope <list> Comma-separated scopes, or 'all'. Searching with no scope
                     covers every scope the database has; indexing with no
                     scope produces every scope the sources can supply.
      --pkg          Shorthand for adding 'pkg' to --scope.
      --opt          Shorthand for adding 'opt' to --scope.
      --lib          Shorthand for adding 'lib' to --scope.

Sources (search reads them live, index writes them into a database):
      --module-options <path>  An options.json from nixosOptionsDoc. Implies
                               --opt. Named --options when indexing.
      --nix <path>             A Nix file or directory to scan for RFC 145
                               doc comments. Implies --lib.
      --prefix <attr>          Attribute path to prepend to names discovered by
                               --nix, e.g. 'lib.strings'. A lexical scan sees
                               only the binding site, so this supplies the
                               enclosing attribute path.

index sources:
      --nixpkgs <path>     Index nixpkgs: packages from the binary cache,
                           library functions from its lib directory, and module
                           options from nixosOptionsDoc. Accepts a path or a
                           quoted search-path form, e.g. --nixpkgs '<nixpkgs>'.
      --manifest <path>    JSON package manifest of realized store outputs.
                           Implies --pkg.
      --options <path>     An options.json from nixosOptionsDoc. Implies --opt.
      --nix <path>         Nix file or directory to scan. Implies --lib.
      --output <path>      Database output path. Defaults to the --db value.

index options for --nixpkgs:
      --cache-url <url>    Binary cache URL. Defaults to https://cache.nixos.org.
      --system <system>    Override the target system (e.g. x86_64-linux).
      --attr-set <attr>    Limit packages to a single attr set (e.g. python3Packages).
      --attrs <attrs>      Comma-separated attr paths for bounded benchmarks
                           (e.g. hello,gitMinimal,ripgrep).
      --concurrent <n>     Maximum parallel HTTP requests (default: 32).
      --follow-refs        Also index transitive references from each package.
      --no-follow-refs     Only index direct package outputs, skip transitive
                           reference traversal (much faster). Enabled by default.

Manifest formats:
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

const RetiredCommands = {
  "opt": "search --opt",
  "pkg": "search --pkg",
  "lib": "search --lib",
  "db": "index",
}.toTable

proc parseCommand(config: var Config, value: string) =
  if config.command != cmdNone:
    config.rememberQuery(value)
    return

  case value
  of "search": config.command = cmdSearch
  of "index": config.command = cmdIndex
  else:
    if value in RetiredCommands:
      fail("unknown command '" & value & "' (did you mean '" &
        RetiredCommands[value] & "'?)")
    fail("unknown command: " & value)

proc parseArgs(): Config =
  result.database = defaultDatabasePath()
  result.indexCacheUrl = DefaultCacheUrl
  result.indexConcurrent = MaxConcurrent

  var parser = initOptParser(
    shortNoVal = {'h'},
    longNoVal = @["help", "json", "verbose", "follow-refs", "no-follow-refs",
      "pkg", "opt", "lib"],
  )

  for kind, key, value in parser.getopt():
    case kind
    of cmdArgument:
      result.parseCommand(key)
    of cmdLongOption, cmdShortOption:
      case key
      of "h", "help":
        showHelp()
      of "json":
        result.jsonOutput = true
      of "verbose":
        result.verbose = true
      of "pkg":
        result.scopes.incl(scopePkg)
      of "opt":
        result.scopes.incl(scopeOpt)
      of "lib":
        result.scopes.incl(scopeLib)
      of "scope":
        result.scopes.incl(parseScopes(requireValue("--scope", value)))
      of "db":
        result.database = requireValue("--db", value)
      of "module-options", "options":
        result.moduleOptions = requireValue("--" & key, value)
      of "manifest":
        result.manifest = requireValue("--manifest", value)
      of "nix":
        result.libSource = requireValue("--nix", value)
      of "prefix":
        result.libPrefix = requireValue("--prefix", value)
      of "output":
        result.output = requireValue("--output", value)
      of "nixpkgs":
        result.indexNixpkgs = requireValue("--nixpkgs", value)
      of "cache-url":
        result.indexCacheUrl = requireValue("--cache-url", value)
      of "system":
        result.indexSystem = requireValue("--system", value)
      of "attr-set":
        result.indexAttrSet = requireValue("--attr-set", value)
      of "attrs":
        for attr in requireValue("--attrs", value).split(','):
          let stripped = attr.strip()
          if stripped.len > 0:
            result.indexAttrs.add(stripped)
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

proc validateNixSource(path: string) =
  if not (fileExists(path) or dirExists(path)):
    fail("nix source does not exist: " & path)

proc sourceScopes(config: Config): ScopeSet =
  ## The scopes the command line's source options can supply on their own.
  if config.moduleOptions.len > 0: result.incl(scopeOpt)
  if config.libSource.len > 0: result.incl(scopeLib)
  if config.manifest.len > 0: result.incl(scopePkg)
  if config.indexNixpkgs.len > 0: result.incl(AllScopes)

proc validate(config: Config) =
  case config.command
  of cmdSearch:
    if config.query.len == 0:
      fail("search requires a query")
    if config.manifest.len > 0:
      fail("--manifest builds a database; use 'spam index --manifest'")
    if config.moduleOptions.len > 0:
      validatePath(config.moduleOptions, "options file")
    if config.libSource.len > 0:
      validateNixSource(config.libSource)
    let live = config.sourceScopes()
    # Only the database is consulted for scopes no source covers, so it only
    # has to exist when at least one such scope remains.
    if config.scopes - live != {} or live == {}:
      validatePath(config.database, "database")
  of cmdIndex:
    if config.query.len > 0:
      fail("unexpected argument: " & config.query)
    if config.sourceScopes() == {}:
      fail("index requires --nixpkgs, --manifest, --options or --nix")
    if config.indexNixpkgs.len > 0 and
        (config.manifest.len > 0 or config.moduleOptions.len > 0 or
        config.libSource.len > 0):
      fail("--nixpkgs already supplies every scope; drop the other sources")
    if config.indexAttrSet.len > 0 and config.indexAttrs.len > 0:
      fail("index accepts either --attr-set or --attrs, not both")
    if config.scopes - config.sourceScopes() != {}:
      fail("no source supplies scope " &
        (config.scopes - config.sourceScopes()).describe())
    if config.manifest.len > 0:
      validatePath(config.manifest, "manifest")
    if config.moduleOptions.len > 0:
      validatePath(config.moduleOptions, "options file")
    if config.libSource.len > 0:
      validateNixSource(config.libSource)
  of cmdNone:
    discard

proc zstdDecompress(input: string): string =
  ## Decompress a section or block of a spam database.
  ##
  ## Database frames are written by spam and always carry a content size, so a
  ## failure here means the file is corrupt; report it and exit.
  try:
    decompressFrame(input)
  except ZstdError as e:
    fail(e.msg & " in database")

proc searchableKey(line: string): string =
  let tab = line.find('\t')
  if tab < 0: line else: line[0 ..< tab]

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

proc initIndexedDatabaseBuilder(path: string): IndexedDatabaseBuilder =
  result.path = path
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
  ## Write the bucketed section payload: a fixed index table followed by one
  ## zstd blob per bucket. Offsets are relative to the payload, so the result
  ## can sit at any position within a database.
  builder.path.ensureParent()
  builder.closeBucketFiles()

  var output = open(builder.path, fmWrite)
  defer: output.close()

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

  output.setFilePos(0)
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
  try:
    compressBlock(data, IndexCompressionLevel)
  except ZstdError as e:
    fail(e.msg & ": " & name)

proc compressedSection(data, tempDir, name: string): string =
  compressString(data, tempDir, "index-v1-" & name)

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
  blocks: seq[IndexV1Block],
  trigrams: var seq[IndexV1TrigramEntry],
): string =
  var postingsByTrigram = initTable[uint32, seq[uint64]]()
  for blockId, recordBlock in blocks:
    var blockTrigrams = initHashSet[uint32]()
    let
      first = int(recordBlock.firstRecordId)
      last = first + int(recordBlock.recordCount)
    for record in records[first ..< last]:
      for trigram in uniquePathTrigrams(record.path):
        blockTrigrams.incl(trigram)
    for trigram in blockTrigrams:
      postingsByTrigram.mgetOrPut(trigram, @[]).add(uint64(blockId))

  let threshold = max(1, blocks.len div 8)
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

proc writeIndexV1Payload*(path: string, records: seq[FileEntry]) =
  ## Write the blocked, trigram-indexed section payload for `records`.
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

  let packagesPayload = encodePackageTable(uniquePackages)
  var blocks: seq[IndexV1Block]
  let blocksSection = encodeRecordBlocks(records, packageIds, tempDir, blocks)
  let blockTableSection = encodeBlockTable(blocks)
  var trigramEntries: seq[IndexV1TrigramEntry]
  let postingsPayload = encodePostings(records, blocks, trigramEntries)
  let trigramPayload = encodeTrigramTable(trigramEntries)
  let packagesSection = compressedSection(packagesPayload, tempDir, "packages")
  let trigramSection = compressedSection(trigramPayload, tempDir, "trigrams")
  let postingsSection = compressedSection(postingsPayload, tempDir, "postings")

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
  output.writeRaw(fixed, "v1 fixed header")
  output.writeRaw(sectionTable, "v1 section table")
  output.writeRaw(packagesSection, "v1 package table")
  output.writeRaw(blockTableSection, "v1 block table")
  output.writeRaw(blocksSection, "v1 record blocks")
  output.writeRaw(trigramSection, "v1 trigram table")
  output.writeRaw(postingsSection, "v1 postings")

proc indexedBucketLines(db: Database, section: DbSection,
    bucket: int): seq[string] =
  let path = db.path
  var file = open(path, fmRead)
  defer: file.close()

  let
    indexStart = db.start(section)
    dataStart = indexStart + IndexSize
  if uint64(IndexSize) > section.length:
    fail("truncated bucket index in " & path)
  file.setFilePos(indexStart)
  let index = file.readExact(path, IndexSize)

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

proc writeBucketedPayload(path: string, lines: seq[string]) =
  var builder = initIndexedDatabaseBuilder(path)
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

proc matchingIndexV1*(db: Database, section: DbSection,
    query: string): seq[FileEntry] =
  let path = db.path
  var file = open(path, fmRead)
  defer: file.close()
  let dataStart = db.start(section)
  if section.length > uint64(int.high):
    fail("v1 index is too large for this platform")
  let payloadLength = BiggestInt(section.length)
  file.setFilePos(dataStart)
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
    packages = parseV1Packages(zstdDecompress(file.readSectionPayload(path,
      dataStart, packagesSection)), packageCount)
    blocks = parseV1Blocks(file.readSectionPayload(path, dataStart,
      blockTableSection), blockCount,
      recordCount, blocksSection.length)
    postings = zstdDecompress(file.readSectionPayload(path, dataStart,
      postingsSection))
    trigrams = parseV1Trigrams(zstdDecompress(file.readSectionPayload(path,
      dataStart, trigramsSection)),
      trigramCount, postings.len, uint64(blockCount))

  var trigramIndex = initTable[uint32, IndexV1TrigramEntry]()
  for entry in trigrams:
    trigramIndex[entry.trigram] = entry
    if (entry.flags and IndexV1TrigramSkipped) == 0:
      discard decodeV1Postings(entry, postings, uint64(blockCount))

  var candidateBlocks: seq[uint64]
  if query.len < 3:
    for blockId in 0'u64 ..< uint64(blockCount):
      candidateBlocks.add(blockId)
  else:
    var postingLists: seq[seq[uint64]]
    for trigram in uniqueQueryTrigrams(query):
      if trigram notin trigramIndex:
        return
      let entry = trigramIndex[trigram]
      if (entry.flags and IndexV1TrigramSkipped) == 0:
        postingLists.add(decodeV1Postings(entry, postings, uint64(blockCount)))
    if postingLists.len == 0:
      for blockId in 0'u64 ..< uint64(blockCount):
        candidateBlocks.add(blockId)
    else:
      postingLists.sort(proc(a, b: seq[uint64]): int = cmp(a.len, b.len))
      candidateBlocks = postingLists[0]
      for i in 1 ..< postingLists.len:
        candidateBlocks = intersectSorted(candidateBlocks, postingLists[i])
        if candidateBlocks.len == 0:
          return

  for blockIdValue in candidateBlocks:
    if blockIdValue > uint64(int.high) or int(blockIdValue) >= blocks.len:
      fail("v1 candidate block id out of bounds")
    let
      blockId = int(blockIdValue)
      recordBlock = blocks[blockId]
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
    for (_, entry) in decodeV1Block(raw, recordBlock.firstRecordId,
        recordBlock.recordCount, packages):
      if query in entry.path:
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

proc writeOptionsPayload(path: string, records: seq[OptionRecord]) =
  var lines: seq[string]
  for record in records:
    lines.add(record.name & "\t" & record.summary)
  writeBucketedPayload(path, lines)

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

proc loadMatchingOptionsDatabase(db: Database, section: DbSection,
    query: string): seq[OptionRecord] =
  matchingOptions(parseOptions(indexedBucketLines(db, section,
      query.queryBucket)), query)

proc optionsJson(records: seq[OptionRecord]): JsonNode =
  result = newJArray()
  for record in records:
    var item = %* {"name": record.name}
    if record.summary.len > 0:
      item["summary"] = %record.summary
    result.add(item)

proc printOptions(records: seq[OptionRecord]) =
  for record in records:
    echo record.name

proc flatten(value: string): string =
  ## Collapse a field to a single line so it survives the tab-separated record
  ## format. Doc comments are multi-line Markdown; the stored summary is a
  ## one-line gloss, not a substitute for reading the comment.
  value.splitWhitespace().join(" ")

proc stripTypeName(typeSig: string): string =
  ## Drop the leading `name ::` that a nixpkgs type signature repeats.
  ##
  ## The record already carries the name, and often a more qualified one than
  ## the signature does, so printing both reads as `lib.mapAttrs :: mapAttrs ::
  ## …`.
  const IdentChars = {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '_', '\'', '-'}
  let sep = typeSig.find(" :: ")
  if sep <= 0:
    return typeSig
  let head = typeSig[0 ..< sep]
  for c in head:
    if c notin IdentChars:
      return typeSig
  typeSig[sep + 4 .. ^1]

proc toLibRecord(function: LibFunction): LibRecord =
  LibRecord(
    name: function.name,
    summary: function.doc.summary().flatten(),
    typeSig: function.doc.typeSig.flatten().stripTypeName(),
    location: function.file & ":" & $function.line,
    deprecated: function.doc.deprecated,
  )

proc encodeLibRecord(record: LibRecord): string =
  record.name & "\t" & record.summary & "\t" & record.typeSig & "\t" &
    record.location & "\t" & (if record.deprecated: "1" else: "0")

proc decodeLibRecord(line: string): LibRecord =
  let parts = line.split('\t')
  if parts.len < 5:
    return LibRecord(name: if parts.len > 0: parts[0] else: "")
  LibRecord(
    name: parts[0],
    summary: parts[1],
    typeSig: parts[2],
    location: parts[3],
    deprecated: parts[4] == "1",
  )

proc libRecords(source, prefix: string): seq[LibRecord] =
  var functions = scanNixTree(source, prefix)
  functions.sort(proc(a, b: LibFunction): int = cmp(a.name, b.name))
  for function in functions:
    result.add(function.toLibRecord())

proc writeLibPayload(path: string, records: seq[LibRecord]) =
  var lines: seq[string]
  for record in records:
    lines.add(encodeLibRecord(record))
  writeBucketedPayload(path, lines)

proc matchingLib(records: seq[LibRecord], query: string): seq[LibRecord] =
  for record in records:
    if query in record.name:
      result.add(record)

proc loadMatchingLibDatabase(db: Database, section: DbSection,
    query: string): seq[LibRecord] =
  var records: seq[LibRecord]
  for line in indexedBucketLines(db, section, query.queryBucket):
    let record = decodeLibRecord(line)
    if record.name.len > 0:
      records.add(record)
  matchingLib(records, query)

proc libJson(records: seq[LibRecord]): JsonNode =
  result = newJArray()
  for record in records:
    var item = %* {"name": record.name, "location": record.location}
    if record.summary.len > 0:
      item["summary"] = %record.summary
    if record.typeSig.len > 0:
      item["type"] = %record.typeSig
    if record.deprecated:
      item["deprecated"] = %true
    result.add(item)

proc printLib(records: seq[LibRecord]) =
  for record in records:
    var line = record.name
    if record.typeSig.len > 0:
      line &= " :: " & record.typeSig
    if record.deprecated:
      line &= "  [deprecated]"
    echo line
    if record.summary.len > 0:
      echo "    " & record.summary
    echo "    " & record.location

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

proc writePackagesPayload(
  path: string,
  records: Table[string, HashSet[string]],
) =
  ## Write a bucketed package payload in the (path\tpkg,...) line format.
  var paths = toSeq(records.keys)
  paths.sort()

  var lines: seq[string]
  for p in paths:
    var packages = toSeq(records[p])
    packages.sort()
    lines.add(p & "\t" & packages.join(","))
  writeBucketedPayload(path, lines)

proc parsePackages(lines: seq[string]): seq[FileEntry] =
  for line in lines:
    let entry = decodeEntry(line)
    if entry.path.len > 0:
      result.add(entry)

proc matchingPackages(records: seq[FileEntry], query: string): seq[FileEntry] =
  for record in records:
    if query in record.path:
      result.add(record)

proc loadMatchingPackagesDatabase(db: Database, section: DbSection,
    query: string): seq[FileEntry] =
  case section.encoding
  of encBuckets:
    matchingPackages(parsePackages(indexedBucketLines(db, section,
        query.queryBucket)), query)
  of encIndexV1:
    matchingIndexV1(db, section, query)
  of encIndexV2:
    matchingIndexV2(db, section, query)

proc packagesJson(records: seq[FileEntry]): JsonNode =
  result = newJArray()
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
    result.add(item)

proc printPackages(records: seq[FileEntry]) =
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

proc optionsFromJson(path: string): seq[OptionRecord] =
  let manifest = parseFile(path)
  let shapes = countOptionShapes(manifest)
  if shapes.options == 0:
    fail(path & " contains no nixosOptionsDoc options")
  if shapes.other > 0:
    fail(path & " mixes options with non-option entries")
  optionRecords(manifest)

proc searchScopes(config: Config, db: Database, haveDb: bool): ScopeSet =
  ## Which scopes this search covers, and where each is read from.
  ##
  ## Naming a source is enough to select its scope, so `--nix ./lib QUERY`
  ## needs no `--lib`. With nothing named at all the search covers everything
  ## available, which is the point of a global search.
  let live = config.sourceScopes()
  result = config.scopes + live
  if result == {}:
    result = if haveDb: db.scopes() else: {}
  if result == {}:
    fail("nothing to search")

proc runSearch(config: Config) =
  let live = config.sourceScopes()
  let needsDb = config.scopes - live != {} or config.scopes + live == {}
  var db: Database
  if needsDb:
    db = openDatabase(config.database)

  let wanted = config.searchScopes(db, needsDb)
  var
    output = newJObject()
    printed = 0
  let labelled = wanted.card > 1

  for scope in Scope:
    if scope notin wanted:
      continue

    let fromDb = scope notin live
    if fromDb and not db.hasScope(scope):
      # An explicit request for a scope the database lacks is a mistake worth
      # reporting; sweeping every scope and finding one absent is not.
      if scope in config.scopes:
        fail("database has no " & $scope & " section: " & config.database)
      continue

    let section = if fromDb: db.section(scope) else: default(DbSection)

    # JSON keeps a key per searched scope so the shape does not depend on what
    # matched; text output drops empty groups, which are pure noise.
    template emit(records, toJson, toText: untyped) =
      if config.jsonOutput:
        output[$scope] = toJson(records)
      elif records.len > 0:
        if labelled:
          if printed > 0: echo ""
          echo "== " & $scope & " =="
        toText(records)
        inc printed

    case scope
    of scopePkg:
      let records = loadMatchingPackagesDatabase(db, section, config.query)
      emit(records, packagesJson, printPackages)
    of scopeOpt:
      let records =
        if fromDb: loadMatchingOptionsDatabase(db, section, config.query)
        else: matchingOptions(optionsFromJson(config.moduleOptions),
          config.query)
      emit(records, optionsJson, printOptions)
    of scopeLib:
      let records =
        if fromDb: loadMatchingLibDatabase(db, section, config.query)
        else: matchingLib(libRecords(config.libSource, config.libPrefix),
          config.query)
      emit(records, libJson, printLib)

  if config.jsonOutput:
    echo output.pretty()

proc indexPackagesFromCache(config: Config, nixpkgs, payloadPath: string,
    summary: var JsonNode) =
  var opts = defaultIndexOptions()
  opts.cacheUrl = config.indexCacheUrl
  opts.nixpkgs = nixpkgs
  opts.system = config.indexSystem
  opts.scope = config.indexAttrSet
  opts.attrs = config.indexAttrs
  opts.maxConcurrent = config.indexConcurrent
  opts.followRefs = config.indexFollowRefs
  opts.verbose = config.verbose

  var spool = initPackageEntrySpool()
  defer: spool.cleanup()

  let stats = waitFor buildIndexDatabase(opts, proc(entry: FileEntry) =
    spool.addEntry(entry)
  )

  # A store path the cache has no listing for is routine; almost every path
  # lacking one is not. That pattern means spam could not read the listings it
  # did fetch, and writing the resulting near-empty database as if it were a
  # real index is worse than failing. Only trip on runs large enough for the
  # ratio to mean something.
  if stats.visited >= MinPathsForCoverageCheck and
      stats.listed * 100 < stats.visited * MinListingCoveragePercent:
    fail("only " & $stats.listed & " of " & $stats.visited &
      " store paths yielded a file listing; refusing to write an index that " &
      "is almost certainly incomplete")

  let records = spool.collectIndexRecords()
  writeIndexV2Payload(payloadPath, records)
  summary = %* {
    "files": records.len,
    "entries": stats.entries,
    "paths": stats.visited,
    "listed": stats.listed,
    "missing": stats.missing,
  }

proc indexPackagesFromManifest(config: Config, payloadPath: string,
    summary: var JsonNode) =
  let outputs = manifestOutputs(parseFile(config.manifest))
  if outputs.len == 0:
    fail("manifest contained no existing package output paths")
  let records = packageFileRecords(outputs)
  writePackagesPayload(payloadPath, records)
  summary = %* {"files": records.len, "outputs": outputs.len}

proc indexOptions(path, payloadPath: string, summary: var JsonNode) =
  let records = optionsFromJson(path)
  writeOptionsPayload(payloadPath, records)
  summary = %* {"options": records.len}

proc indexLib(source, prefix, payloadPath: string, summary: var JsonNode) =
  let records = libRecords(source, prefix)
  if records.len == 0:
    fail("no documented Nix attributes found under " & source)
  writeLibPayload(payloadPath, records)
  summary = %* {"functions": records.len}

proc runIndex(config: Config) =
  let outPath =
    if config.output.len > 0: config.output
    else: config.database

  let wanted =
    if config.scopes != {}: config.scopes
    else: config.sourceScopes()

  var assembler = initDatabaseAssembler()
  defer: assembler.cleanup()

  var report = newJObject()

  # A nixpkgs index draws each scope from a different place: packages from the
  # binary cache, library functions from the tree, options from a
  # nixosOptionsDoc build.
  if config.indexNixpkgs.len > 0:
    let nixpkgs = resolveNixpkgs(config.indexNixpkgs, config.verbose)
    if config.verbose:
      stderr.writeLine("spam: indexing " & nixpkgs & " (" & wanted.describe() &
        ") -> " & outPath)

    if scopePkg in wanted:
      var summary: JsonNode
      indexPackagesFromCache(config, config.indexNixpkgs,
        assembler.reserve(scopePkg, encIndexV2), summary)
      report["pkg"] = summary

    if scopeLib in wanted:
      let libDir = nixpkgs / "lib"
      if not dirExists(libDir):
        fail("no lib directory under " & nixpkgs)
      var summary: JsonNode
      indexLib(libDir, "lib", assembler.reserve(scopeLib, encBuckets), summary)
      report["lib"] = summary

    if scopeOpt in wanted:
      var summary: JsonNode
      indexOptions(nixosOptionsJson(nixpkgs, config.indexSystem,
        config.verbose), assembler.reserve(scopeOpt, encBuckets), summary)
      report["opt"] = summary
  else:
    if scopePkg in wanted:
      var summary: JsonNode
      indexPackagesFromManifest(config,
        assembler.reserve(scopePkg, encBuckets), summary)
      report["pkg"] = summary

    if scopeOpt in wanted:
      var summary: JsonNode
      indexOptions(config.moduleOptions,
        assembler.reserve(scopeOpt, encBuckets), summary)
      report["opt"] = summary

    if scopeLib in wanted:
      var summary: JsonNode
      indexLib(config.libSource, config.libPrefix,
        assembler.reserve(scopeLib, encBuckets), summary)
      report["lib"] = summary

  assembler.finish(outPath)

  if config.jsonOutput:
    report["output"] = %outPath
    report["scopes"] = %wanted.describe()
    echo report.pretty()
  else:
    for scope in Scope:
      if $scope in report:
        stderr.writeLine("spam: " & $scope & " " & $report[$scope])
    stderr.writeLine(&"wrote {wanted.describe()} -> {outPath}")

proc main() {.used.} =
  try:
    let config = parseArgs()
    validate(config)

    case config.command
    of cmdSearch:
      runSearch(config)
    of cmdIndex:
      runIndex(config)
    of cmdNone:
      discard
  except DbError as e:
    fail(e.msg)
  except NixEvalError as e:
    fail(e.msg)

when isMainModule:
  main()
