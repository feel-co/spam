## Binary cache HTTP client for spam.
##
## Fetches .narinfo and .ls/.ls.xz file listings from a Nix binary cache
## (e.g. https://cache.nixos.org) for autonomous database indexing.
import std/[asyncdispatch, httpclient, json, strutils, math, random]

{.passL: "-lbrotlidec".}

type BrotliDecoderResult = cint

const
  BrotliResultSuccess = BrotliDecoderResult(1)
  BrotliResultNeedsOutput = BrotliDecoderResult(3)

proc brotliDecoderDecompress(
  encodedSize: csize_t,
  encodedBuffer: pointer,
  decodedSize: ptr csize_t,
  decodedBuffer: pointer,
): BrotliDecoderResult {.importc: "BrotliDecoderDecompress".}

proc brotliDecompress(data: string): string =
  ## Decompress a Brotli-encoded string. Raises IOError on failure.
  if data.len == 0:
    return ""

  # Brotli has no frame header with decompressed size; start at 8x and double.
  var capacity = csize_t(max(data.len * 8, 4096))
  while true:
    result = newString(int(capacity))
    var outLen = capacity
    let rc = brotliDecoderDecompress(
      csize_t(data.len), unsafeAddr data[0],
      addr outLen, addr result[0],
    )
    if rc == BrotliResultSuccess:
      result.setLen(int(outLen))
      return
    elif rc == BrotliResultNeedsOutput:
      if capacity >= csize_t(64 * 1024 * 1024):
        raise newException(IOError, "brotli output exceeds 64 MiB")
      capacity = capacity * 2
    else:
      raise newException(IOError, "brotli decompression failed (result=" & $rc & ")")

const
  DefaultCacheUrl* = "https://cache.nixos.org"
  MaxRetries = 20
  BaseDelayMs = 50
  ## Maximum number of concurrent HTTP requests.
  ## 512 concurrent connections overwhelms cache.nixos.org and triggers
  ## server-side disconnects as well as assertion failures in Nim's httpclient.
  MaxConcurrent* = 32
  ## Per-request timeout in milliseconds.
  RequestTimeoutMs = 30_000
  ## cache.nixos.org caches 5xx errors for ~5 seconds, so retries must
  ## wait at least this long to avoid hitting the same cached error.
  ServerErrorFloorMs = 5000

type
  PermanentHttpError* = object of HttpRequestError
    ## Raised for non-retriable HTTP errors (4xx except 404).
    ## Must not be retried; propagates immediately out of fetchWithRetry.

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

proc newCacheClient*(cacheUrl: string = DefaultCacheUrl): CacheClient =
  ## Create a new cache client for the given binary cache URL.
  result = CacheClient(
    cacheUrl: cacheUrl.strip(chars = {'/'}),
  )

proc fetchWithRetry(c: CacheClient, url: string): Future[string] {.async.} =
  ## Fetch `url`, returning body on success or "" on 404.
  ## Retries on 5xx/network errors with exponential backoff + jitter.
  ## 5xx retries use a 5 s floor (cache.nixos.org caches server errors for ~5 s).
  ## Non-404 4xx responses raise PermanentHttpError immediately (no retry).
  ## Creates a fresh AsyncHttpClient per attempt to avoid concurrent reuse issues.
  var delay = BaseDelayMs
  var statusStr = ""
  for attempt in 0 ..< MaxRetries:
    let client = newAsyncHttpClient()
    client.timeout = RequestTimeoutMs
    client.headers = newHttpHeaders()
    statusStr = ""
    try:
      let resp = await client.get(url)
      statusStr = resp.status
      case statusStr[0]
      of '2':
        let raw = await resp.body
        let encoding = resp.headers.getOrDefault(
            "content-encoding").toLowerAscii()
        result =
          if encoding == "br": brotliDecompress(raw)
          else: raw
        try: client.close() except CatchableError: discard
        return
      of '4':
        try: client.close() except CatchableError: discard
        if statusStr.startsWith("404"):
          return ""
        # 4xx (non-404) is a permanent client error; retrying will not help.
        raise newException(PermanentHttpError, "HTTP " & statusStr & " for " & url)
      else:
        try: client.close() except CatchableError: discard
        if attempt == MaxRetries - 1:
          raise newException(HttpRequestError, "HTTP " & statusStr & " for " & url)
    except PermanentHttpError:
      raise
    except CatchableError:
      try: client.close() except CatchableError: discard
      if attempt == MaxRetries - 1:
        raise

    if attempt == MaxRetries - 1:
      return ""

    # 5xx responses from cache.nixos.org are cached for ~5 seconds, so
    # subsequent retries within that window will hit the same cached error.
    let isServerError = statusStr.len > 0 and statusStr[0] notin {'2', '4'}
    let waitMs =
      if isServerError:
        max(delay + rand(delay div 4), ServerErrorFloorMs)
      else:
        delay + rand(delay div 4)
    await sleepAsync(waitMs)
    delay = min(delay * 2, ServerErrorFloorMs)
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
