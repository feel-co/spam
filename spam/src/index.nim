## Autonomous Nix package indexing for spam.
##
## Enumerates packages via `nix-env -qaP --xml --out-path`, then performs
## recursive reference traversal (BFS workset) to discover transitive
## dependencies, fetching file listings from the binary cache for each.
##
## The result is a seq[FileEntry] suitable for writing to a spam packages
## database via writeIndexedDatabase.

import std/[algorithm, asyncdispatch, os, osproc, parsexml, sequtils, sets,
    streams, strutils, syncio, tables]
import cache
import filemeta

type
  StoreOutput* = object
    ## One output of a Nix derivation.
    attr*: string
      ## Nix attribute path, e.g. "hello".
    pname*: string
      ## Package name, e.g. "hello".
    version*: string
      ## Package version, e.g. "2.12".
    output*: string
      ## Output name, e.g. "out", "dev", "man".
    storePath*: string
      ## Full /nix/store path.
    hash*: string
      ## 32-char nixbase32 hash prefix.

  IndexOptions* = object
    ## Options for the indexing run.
    cacheUrl*: string
    nixpkgs*: string
      ## Path or expression passed to nix-env -f. Defaults to "<nixpkgs>".
    system*: string
      ## Optional --argstr system override.
    scope*: string
      ## Optional -A scope filter.
    maxConcurrent*: int
      ## Max parallel HTTP requests. Defaults to MaxConcurrent from cache.nim.
    followRefs*: bool
      ## If true, follow transitive store references (BFS). Much slower.
    verbose*: bool

proc defaultIndexOptions*(): IndexOptions =
  IndexOptions(
    cacheUrl: DefaultCacheUrl,
    nixpkgs: "<nixpkgs>",
    maxConcurrent: MaxConcurrent,
    followRefs: false,
  )

proc hashFromPath*(storePath: string): string =
  ## Extract the 32-char hash from a /nix/store/HASH-name path.
  let base = storePath.lastPathPart()
  let dash = base.find('-')
  if dash > 0: base[0 ..< dash] else: base

proc enumeratePackages*(opts: IndexOptions): seq[StoreOutput] =
  ## Run nix-env -qaP --out-path --xml and parse the output into StoreOutputs.
  ## Parses the XML stream incrementally without buffering the entire output
  ## (100K+ packages with full store paths would otherwise OOM the process).
  var args = @[
    "-qaP", "--out-path", "--xml",
    "--arg", "config", "{ allowAliases = false; }",
    "--arg", "overlays", "[ ]",
    "--file", opts.nixpkgs,
  ]
  if opts.system.len > 0:
    args.add(["--argstr", "system", opts.system])
  if opts.scope.len > 0:
    args.add(["-A", opts.scope])

  if opts.verbose:
    stderr.writeLine("spam: running nix-env " & args.join(" "))

  let nix = startProcess("nix-env", args = args, options = {poUsePath})

  # Parse stdout incrementally — the XML for 126K packages is easily
  # 100+ MiB; buffering it all with readAll() causes OOM.
  var parser: XmlParser
  open(parser, nix.outputStream, "nix-env output")
  defer: parser.close()

  var
    currentAttr = ""
    currentSystem = ""
    inItem = false

  while true:
    parser.next()
    case parser.kind
    of xmlElementOpen:
      case parser.elementName
      of "item":
        inItem = true
        currentAttr = ""
        currentSystem = ""
      of "output":
        if inItem:
          var outputName = ""
          var outputPath = ""
          while true:
            parser.next()
            if parser.kind == xmlAttribute:
              case parser.attrKey
              of "name": outputName = parser.attrValue
              of "path": outputPath = parser.attrValue
            else:
              break
          if outputPath.len > 0 and outputName.len > 0:
            let hash = hashFromPath(outputPath)
            let dashPos = outputPath.lastPathPart().find('-')
            let nameVer =
              if dashPos > 0: outputPath.lastPathPart()[dashPos + 1 .. ^1]
              else: currentAttr
            var pname = nameVer
            var version = ""
            for i in countdown(nameVer.len - 1, 1):
              if nameVer[i] == '-' and i + 1 < nameVer.len and
                  nameVer[i + 1] in {'0' .. '9'}:
                pname = nameVer[0 ..< i]
                version = nameVer[i + 1 .. ^1]
                break
            result.add(StoreOutput(
              attr: currentAttr,
              pname: pname,
              version: version,
              output: outputName,
              storePath: outputPath,
              hash: hash,
            ))
      else:
        discard
    of xmlAttribute:
      case parser.attrKey
      of "attrPath": currentAttr = parser.attrValue
      of "system": currentSystem = parser.attrValue
    of xmlElementClose, xmlElementEnd:
      if parser.kind == xmlElementEnd and parser.elementName == "item":
        inItem = false
    of xmlEof:
      break
    else:
      discard

  # stderr from nix-env is small (a few eval warnings); read after stdout
  # EOF to avoid pipe deadlock.
  let errOutput = nix.errorStream.readAll()
  let exitCode = nix.waitForExit()
  nix.close()
  if exitCode != 0:
    raise newException(OSError, "nix-env failed:\n" & errOutput)
  if errOutput.len > 0 and opts.verbose:
    stderr.write("spam: nix-env stderr: " & errOutput)

proc indexWithCache*(
  outputs: seq[StoreOutput],
  opts: IndexOptions,
): Future[seq[FileEntry]] {.async.} =
  ## Perform BFS reference traversal starting from `outputs`.
  ##
  ## For each store path:
  ##   1. Fetch .narinfo to get direct references.
  ##   2. Fetch .ls to get the file listing with metadata.
  ##   3. Add referenced hashes to the workset if not yet visited.
  ##
  ## Returns a deduplicated seq of FileEntry with full metadata.
  let client = newCacheClient(opts.cacheUrl)

  # visited: hashes we've already fetched or enqueued
  var visited = initHashSet[string]()
  # retried: hashes that have already been re-queued once after a failure
  var retried = initHashSet[string]()
  # hashToAttr: maps hash -> attr name for top-level packages
  var hashToAttr = initTable[string, string]()

  # Initialise workset from the top-level outputs
  var queue: seq[string]
  for o in outputs:
    if o.hash notin visited:
      visited.incl(o.hash)
      queue.add(o.hash)
      hashToAttr[o.hash] = o.attr & (if o.output != "out": "." &
          o.output else: "")

  # path -> set of package attr names
  var fileTable = initTable[string, HashSet[string]]()
  # path -> LsEntry (for metadata: size, kind, exec, target)
  var metaTable = initTable[string, LsEntry]()

  var processed = 0

  while queue.len > 0:
    # Drain up to maxConcurrent items in parallel
    let batch = queue[0 ..< min(opts.maxConcurrent, queue.len)]
    queue = queue[batch.len .. ^1]

    # Launch narinfo + file listing fetches concurrently
    var narFutures: seq[Future[NarInfo]]
    var lsFutures: seq[Future[seq[LsEntry]]]
    for hash in batch:
      narFutures.add(client.fetchNarInfo(hash))
      lsFutures.add(client.fetchFileListing(hash))

    # Await all futures
    for i, hash in batch:
      try:
        let narInfo = await narFutures[i]
        let entries = await lsFutures[i]

        inc processed
        if opts.verbose and processed mod 100 == 0:
          stderr.writeLine("spam: indexed " & $processed & " paths, queue=" & $queue.len)

        # Enqueue newly discovered references (only if followRefs is enabled)
        if opts.followRefs:
          for refHash in narInfo.references:
            if refHash notin visited:
              visited.incl(refHash)
              queue.add(refHash)

        # The attr name for this path: use hashToAttr if top-level, else use storePath basename
        let attr =
          if hash in hashToAttr: hashToAttr[hash]
          else:
            let name = narInfo.storePath.lastPathPart()
            let dash = name.find('-')
            if dash > 0: name[dash + 1 .. ^1] else: name

        # Merge file entries into the deduplication tables
        for entry in entries:
          # Skip directory entries from the merge (they clutter queries)
          if entry.kind == "directory":
            continue
          metaTable[entry.path] = entry
          fileTable.mgetOrPut(entry.path, initHashSet[string]()).incl(attr)

      except Exception as e:
        # Catch both CatchableError and Defect (e.g. AssertionDefect from
        # httpclient when a connection is torn down under high concurrency).
        # Individual hash failures are non-fatal; log and re-queue for one
        # more attempt.
        if opts.verbose:
          stderr.writeLine("spam: warning: failed to index " & hash & ": " & e.msg)
        # Re-queue if not yet retried to recover transient failures.
        if hash notin retried:
          retried.incl(hash)
          queue.add(hash)

  if opts.verbose:
    stderr.writeLine("spam: traversal complete. visited=" & $visited.len &
      " unique paths, files=" & $fileTable.len)

  # Build the final FileEntry seq
  var paths = toSeq(fileTable.keys)
  paths.sort()

  for path in paths:
    let pkgs = toSeq(fileTable[path])
    let meta = metaTable.getOrDefault(path)
    let kind =
      if meta.kind == "symlink": fkSymlink
      elif meta.kind == "directory": fkDirectory
      else: fkRegular
    result.add(FileEntry(
      path: path,
      size: meta.size,
      kind: kind,
      executable: meta.executable,
      target: meta.target,
      packages: pkgs,
    ))


proc buildIndexDatabase*(opts: IndexOptions): Future[seq[FileEntry]] {.async.} =
  ## Top-level entry: enumerate packages via nix-env, then index via binary cache.
  let outputs = enumeratePackages(opts)
  if opts.verbose:
    stderr.writeLine("spam: enumerated " & $outputs.len & " store outputs")
  return await indexWithCache(outputs, opts)
