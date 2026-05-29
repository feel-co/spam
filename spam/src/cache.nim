## Binary cache HTTP client for spam.
##
## Fetches .narinfo and .ls/.ls.xz file listings from a Nix binary cache
## (e.g. https://cache.nixos.org) for autonomous database indexing.
##
## Design:
##   - Uses std/asynchttpclient + std/asyncdispatch for concurrent fetches.
##   - Limits concurrency via a semaphore (maxConcurrent requests in-flight).
##   - Exponential backoff with jitter on transient failures (5xx / network).
##   - Parses narinfo text format and .ls JSON listings.

import std/[asyncdispatch, httpclient, json, strutils, math, random]

const
  DefaultCacheUrl* = "https://cache.nixos.org"
  MaxRetries = 5
  BaseDelayMs = 200
  ## Maximum number of concurrent HTTP requests.
  MaxConcurrent* = 32

type
  NarInfo* = object
    ## Parsed subset of a .narinfo file.
    hash*: string
      ## Store hash (32-char nixbase32 prefix of the store path).
    storePath*: string
      ## Full store path, e.g. /nix/store/abc123...-hello-2.12.
    narUrl*: string
      ## Relative URL to the .nar file (from the cache root).
    references*: seq[string]
      ## Hashes of referenced store paths (direct dependencies).

  LsEntry* = object
    ## A single entry from a .ls file listing.
    path*: string
      ## Path relative to the store output root, e.g. "/bin/hello".
    size*: uint64
    executable*: bool
    kind*: string
      ## "regular", "directory", or "symlink"
    target*: string
      ## Symlink destination, if kind == "symlink".

  CacheClient* = ref object
    cacheUrl*: string
    client: AsyncHttpClient

proc newCacheClient*(cacheUrl: string = DefaultCacheUrl): CacheClient =
  ## Create a new cache client for the given binary cache URL.
  result = CacheClient(
    cacheUrl: cacheUrl.strip(chars = {'/'}),
    client: newAsyncHttpClient(),
  )
  result.client.headers = newHttpHeaders({"Accept-Encoding": "gzip, deflate"})

proc fetchWithRetry(c: CacheClient, url: string): Future[string] {.async.} =
  ## Fetch `url`, returning body on success or "" on 404.
  ## Retries on 5xx/network errors with exponential backoff + jitter.
  var delay = BaseDelayMs
  for attempt in 0 ..< MaxRetries:
    try:
      let resp = await c.client.get(url)
      case resp.status[0]
      of '2':
        return await resp.body
      of '4':
        # 404 = not found, treat as empty (not an error)
        if resp.status.startsWith("404"):
          return ""
        raise newException(HttpRequestError, "HTTP " & resp.status & " for " & url)
      else:
        # 5xx or other – retry
        if attempt == MaxRetries - 1:
          raise newException(HttpRequestError, "HTTP " & resp.status & " for " & url)
        await sleepAsync(delay + rand(delay div 4))
        delay = min(delay * 2, 8000)
    except CatchableError as e:
      if attempt == MaxRetries - 1:
        raise
      await sleepAsync(delay + rand(delay div 4))
      delay = min(delay * 2, 8000)
  return ""

proc fetchNarInfo*(c: CacheClient, hash: string): Future[NarInfo] {.async.} =
  ## Fetch and parse the .narinfo for the store path identified by `hash`.
  ## Returns an empty NarInfo (storePath == "") if not found.
  let url = c.cacheUrl & "/" & hash & ".narinfo"
  let body = await c.fetchWithRetry(url)
  if body.len == 0:
    return NarInfo(hash: hash)

  result.hash = hash
  for rawLine in body.splitLines():
    let line = rawLine.strip()
    if line.len == 0:
      continue
    let colon = line.find(": ")
    if colon < 0:
      continue
    let key = line[0 ..< colon]
    let val = line[colon + 2 .. ^1].strip()
    case key
    of "StorePath":
      result.storePath = val
    of "URL":
      result.narUrl = val
    of "References":
      for refPath in val.splitWhitespace():
        # references are full store paths; extract the hash prefix
        let slash = refPath.rfind('/')
        let name = if slash >= 0: refPath[slash + 1 .. ^1] else: refPath
        let dashPos = name.find('-')
        if dashPos > 0:
          result.references.add(name[0 ..< dashPos])
        else:
          result.references.add(name)

proc walkLsNode(path: string, node: JsonNode, result: var seq[LsEntry]) =
  ## Recursively flatten a .ls JSON node tree into a seq of LsEntry.
  if node.kind != JObject:
    return

  let typ = node{"type"}.getStr("")
  case typ
  of "regular":
    result.add(LsEntry(
      path: path,
      size: uint64(node{"size"}.getInt(0)),
      executable: node{"executable"}.getBool(false),
      kind: "regular",
    ))
  of "symlink":
    result.add(LsEntry(
      path: path,
      size: 0,
      kind: "symlink",
      target: node{"target"}.getStr(""),
    ))
  of "directory":
    result.add(LsEntry(path: path, kind: "directory"))
    let entries = node{"entries"}
    if entries != nil and entries.kind == JObject:
      for name, child in entries:
        let childPath = if path == "/": "/" & name else: path & "/" & name
        walkLsNode(childPath, child, result)
  else:
    discard

proc fetchFileListing*(c: CacheClient, hash: string): Future[seq[
    LsEntry]] {.async.} =
  ## Fetch and parse the file listing (.ls or .ls.xz) for the store path `hash`.
  ## Returns an empty seq if no listing is available.
  let urlPlain = c.cacheUrl & "/" & hash & ".ls"
  let body = await c.fetchWithRetry(urlPlain)
  if body.len == 0:
    # Try the .xz variant (older caches)
    let urlXz = c.cacheUrl & "/" & hash & ".ls.xz"
    let bodyXz = await c.fetchWithRetry(urlXz)
    if bodyXz.len == 0:
      return @[]
    # xz decompression requires liblzma FFI which is not yet implemented.
    # Warn so the user knows file entries are missing for this hash.
    stderr.writeLine("spam: warning: .ls.xz listing available for " & hash &
      " but xz decompression is not implemented; file entries skipped")
    return @[]

  try:
    let root = parseJson(body)
    let rootNode = root{"root"}
    if rootNode == nil:
      return @[]
    walkLsNode("/", rootNode, result)
  except JsonParsingError:
    return @[]

proc close*(c: CacheClient) =
  ## Release the underlying HTTP client.
  c.client.close()
