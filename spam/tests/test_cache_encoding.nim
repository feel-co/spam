## Regression tests for binary-cache response decoding.
##
## cache.nixos.org serves `.ls` and `.narinfo` objects pre-compressed, with the
## encoding fixed by the stored object rather than negotiated: `Accept-Encoding`
## is ignored. spam originally only decoded `br`, so once the cache moved to
## `zstd` every listing failed to parse and was reported as "this path has no
## files". A full nixpkgs index silently collapsed from ~36 million entries to
## 1806, and the build still exited 0.
##
## These tests pin down both halves of that failure: zstd bodies must decode,
## and anything spam cannot decode must raise instead of passing bytes through.

import std/[json, strutils]
import cache
import zstdffi

const listing = """{"version":1,"root":{"type":"directory","entries":{"bin":{"type":"directory","entries":{"hello":{"type":"regular","size":64472,"executable":true}}}}}}"""

block zstdBodiesDecode:
  # Compressed the way an HTTP origin does it: streaming, so the frame header
  # carries no content size.
  let encoded = compressStreamString(listing)
  doAssert encoded != listing
  doAssert decodeBody(encoded, "zstd", "test://ls") == listing

block zstdFramesLackContentSize:
  # The reason decompressStream exists: the one-shot path cannot read these.
  let encoded = compressStreamString(listing)
  var raised = false
  try:
    discard decompressFrame(encoded)
  except ZstdError:
    raised = true
  doAssert raised, "expected a streamed frame to have no declared content size"
  doAssert decompressStream(encoded) == listing

block headerCasingAndAbsence:
  doAssert decodeBody(listing, "", "test://ls") == listing
  doAssert decodeBody(listing, "identity", "test://ls") == listing

block unknownEncodingIsFatal:
  # Passing an undecoded body through is what turned a codec change into a
  # silently empty index, so an unrecognised encoding must be loud.
  var raised = false
  try:
    discard decodeBody(listing, "deflate", "test://ls")
  except IOError as e:
    raised = true
    doAssert "deflate" in e.msg
  doAssert raised, "unknown content-encoding must raise"

block corruptZstdIsFatal:
  var raised = false
  try:
    discard decodeBody("not actually zstd at all", "zstd", "test://ls")
  except IOError:
    raised = true
  doAssert raised, "undecodable zstd body must raise"

block decodedListingParses:
  # End to end: what decodeBody returns must be what the .ls parser consumes.
  let decoded = decodeBody(compressStreamString(listing), "zstd", "test://ls")
  let root = parseJson(decoded){"root"}
  doAssert root != nil
  doAssert root{"type"}.getStr() == "directory"

echo "test_cache_encoding: ok"
