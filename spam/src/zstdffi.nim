## Shared libzstd bindings for spam.
##
## Both the binary-cache HTTP client (`cache`) and the database writer (`spam`)
## need zstd, so the bindings live here rather than being duplicated.
##
## Two decompression entry points are provided because the two callers have
## different guarantees:
##
## - `decompressFrame` is for data spam wrote itself, where the frame header
##   always carries the content size, so the output can be allocated exactly.
## - `decompressStream` is for data from the network, where the frame may have
##   been produced by a streaming encoder that omitted the content size.
##
## Both raise `ZstdError` rather than exiting, so callers can decide whether a
## failure is fatal.

{.passL: "-lzstd".}

const
  DecompressBufferSize* = 128 * 1024
    ## Chunk size for streaming operations.
  MaxDecompressedSize* = 512 * 1024 * 1024
    ## Refuse to decompress beyond this, so a hostile or corrupt frame cannot
    ## exhaust memory. File listings for even the largest store paths are
    ## orders of magnitude below this.
  ContentSizeUnknown* = uint64.high
  ContentSizeError* = uint64.high - 1

type
  ZstdError* = object of CatchableError
    ## Raised for any libzstd failure or malformed input.

  ZstdInBuffer* = object
    src*: pointer
    size*: csize_t
    pos*: csize_t

  ZstdOutBuffer* = object
    dst*: pointer
    size*: csize_t
    pos*: csize_t

proc zstdGetFrameContentSize*(src: pointer, srcSize: csize_t): uint64 {.
    importc: "ZSTD_getFrameContentSize".}
proc zstdDecompress*(
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  compressedSize: csize_t,
): csize_t {.importc: "ZSTD_decompress".}
proc zstdCompressBound*(srcSize: csize_t): csize_t {.
    importc: "ZSTD_compressBound".}
proc zstdCompress*(
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  srcSize: csize_t,
  compressionLevel: cint,
): csize_t {.importc: "ZSTD_compress".}
proc zstdIsError*(code: csize_t): cuint {.importc: "ZSTD_isError".}
proc zstdGetErrorName*(code: csize_t): cstring {.importc: "ZSTD_getErrorName".}
proc zstdCreateCStream*(): pointer {.importc: "ZSTD_createCStream".}
proc zstdFreeCStream*(stream: pointer): csize_t {.importc: "ZSTD_freeCStream".}
proc zstdInitCStream*(stream: pointer, compressionLevel: cint): csize_t {.
    importc: "ZSTD_initCStream".}
proc zstdSetPledgedSrcSize*(stream: pointer, pledgedSrcSize: uint64): csize_t {.
    importc: "ZSTD_CCtx_setPledgedSrcSize".}
proc zstdCompressStream*(
  stream: pointer,
  output: ptr ZstdOutBuffer,
  input: ptr ZstdInBuffer,
): csize_t {.importc: "ZSTD_compressStream".}
proc zstdEndStream*(stream: pointer, output: ptr ZstdOutBuffer): csize_t {.
    importc: "ZSTD_endStream".}
proc zstdCreateDStream*(): pointer {.importc: "ZSTD_createDStream".}
proc zstdFreeDStream*(stream: pointer): csize_t {.importc: "ZSTD_freeDStream".}
proc zstdInitDStream*(stream: pointer): csize_t {.importc: "ZSTD_initDStream".}
proc zstdDecompressStreamRaw(
  stream: pointer,
  output: ptr ZstdOutBuffer,
  input: ptr ZstdInBuffer,
): csize_t {.importc: "ZSTD_decompressStream".}

proc check*(code: csize_t, action: string) =
  ## Raise `ZstdError` if `code` is a libzstd error code.
  if zstdIsError(code) != 0:
    raise newException(ZstdError, action & ": " & $zstdGetErrorName(code))

proc decompressFrame*(input: string): string =
  ## Decompress a zstd frame whose header declares its content size.
  ##
  ## Raises `ZstdError` if the size is absent, implausible, or the frame is
  ## malformed. Use this only for frames spam produced itself.
  if input.len == 0:
    return ""

  let contentSize = zstdGetFrameContentSize(unsafeAddr input[0],
    csize_t(input.len))
  if contentSize == ContentSizeError:
    raise newException(ZstdError, "invalid zstd frame")
  if contentSize == ContentSizeUnknown:
    raise newException(ZstdError, "zstd frame has unknown decompressed size")
  if contentSize > uint64(int.high) or contentSize > uint64(MaxDecompressedSize):
    raise newException(ZstdError, "zstd frame is too large: " & $contentSize)

  result = newString(int(contentSize))
  if result.len == 0:
    return

  let decompressedSize = zstdDecompress(addr result[0], csize_t(result.len),
    unsafeAddr input[0], csize_t(input.len))
  check(decompressedSize, "zstd decompression failed")
  result.setLen(int(decompressedSize))

proc decompressStream*(input: string): string =
  ## Decompress a zstd frame of unknown decompressed size.
  ##
  ## Needed for HTTP bodies: cache.nixos.org serves `.ls` listings with
  ## `Content-Encoding: zstd`, and those frames do not always carry a content
  ## size in the header.
  ##
  ## Raises `ZstdError` on malformed input, on truncated input (a frame that
  ## never completes), or if the output would exceed `MaxDecompressedSize`.
  if input.len == 0:
    return ""

  let stream = zstdCreateDStream()
  if stream == nil:
    raise newException(ZstdError, "could not create zstd decompression stream")
  defer: discard zstdFreeDStream(stream)

  check(zstdInitDStream(stream), "zstd decompression failed")

  var
    inputBuffer = ZstdInBuffer(
      src: unsafeAddr input[0],
      size: csize_t(input.len),
      pos: 0,
    )
    outputChunk = newString(DecompressBufferSize)

  result = newStringOfCap(input.len * 4)

  while true:
    var outputBuffer = ZstdOutBuffer(
      dst: addr outputChunk[0],
      size: csize_t(outputChunk.len),
      pos: 0,
    )
    let remaining = zstdDecompressStreamRaw(stream, addr outputBuffer,
      addr inputBuffer)
    check(remaining, "zstd decompression failed")

    if outputBuffer.pos > 0:
      if result.len + int(outputBuffer.pos) > MaxDecompressedSize:
        raise newException(ZstdError,
          "zstd output exceeds " & $(MaxDecompressedSize div (1024 * 1024)) &
          " MiB")
      let start = result.len
      result.setLen(start + int(outputBuffer.pos))
      copyMem(addr result[start], addr outputChunk[0], int(outputBuffer.pos))

    if remaining == 0:
      # A frame just ended. Stop unless more frames are concatenated after it;
      # ZSTD_decompressStream starts the next frame on its own.
      if inputBuffer.pos >= inputBuffer.size:
        break
    elif inputBuffer.pos >= inputBuffer.size and outputBuffer.pos == 0:
      # All input consumed, nothing left to flush, yet the frame is unfinished.
      raise newException(ZstdError, "truncated zstd stream")

proc compressStreamString*(data: string, level: cint = 3): string =
  ## Compress `data` with the streaming API and no pledged source size, so the
  ## frame header omits the content size.
  ##
  ## This is how an HTTP origin compresses a response body, which makes it the
  ## shape `decompressStream` has to cope with; `decompressFrame` cannot read
  ## these. Used by the tests to build realistic cache responses.
  let stream = zstdCreateCStream()
  if stream == nil:
    raise newException(ZstdError, "could not create zstd compression stream")
  defer: discard zstdFreeCStream(stream)

  check(zstdInitCStream(stream, level), "zstd compression failed")

  var outputChunk = newString(DecompressBufferSize)

  proc drain(output: var string, buffer: ZstdOutBuffer) =
    if buffer.pos > 0:
      let start = output.len
      output.setLen(start + int(buffer.pos))
      copyMem(addr output[start], buffer.dst, int(buffer.pos))

  if data.len > 0:
    var inputBuffer = ZstdInBuffer(
      src: unsafeAddr data[0],
      size: csize_t(data.len),
      pos: 0,
    )
    while inputBuffer.pos < inputBuffer.size:
      var outputBuffer = ZstdOutBuffer(
        dst: addr outputChunk[0],
        size: csize_t(outputChunk.len),
        pos: 0,
      )
      check(zstdCompressStream(stream, addr outputBuffer, addr inputBuffer),
        "zstd compression failed")
      result.drain(outputBuffer)

  while true:
    var outputBuffer = ZstdOutBuffer(
      dst: addr outputChunk[0],
      size: csize_t(outputChunk.len),
      pos: 0,
    )
    let remaining = zstdEndStream(stream, addr outputBuffer)
    check(remaining, "zstd compression failed")
    result.drain(outputBuffer)
    if remaining == 0:
      break

proc compressBlock*(data: string, level: cint): string =
  ## One-shot compress `data` at `level`. Raises `ZstdError` on failure.
  if data.len == 0:
    return ""
  let bound = zstdCompressBound(csize_t(data.len))
  if bound > csize_t(int.high):
    raise newException(ZstdError, "input is too large to compress")
  result = newString(int(bound))
  let written = zstdCompress(addr result[0], bound, unsafeAddr data[0],
    csize_t(data.len), level)
  check(written, "zstd compression failed")
  result.setLen(int(written))
