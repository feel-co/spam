## Nim bindings for the `nixdoc-ffi` C ABI.
##
## `nixdoc` (https://github.com/feel-co/nixdoc) parses RFC 145 `/** ... */` doc
## comments into a typed structure: title, description, type signature,
## arguments, examples, notes, warnings and deprecation state. spam uses it so
## the doc-comment grammar lives in one implementation rather than being
## re-guessed here.
##
## NOTE: nixdoc parses *comment text*. It does not read Nix files and has
## no notion of which attribute a comment documents. Locating comments and
## binding them to attribute paths is spam's job -- see `libindex`.
##
## Every accessor returns owned memory that must be released through the
## matching `nixdoc_free_*` entry point. The wrappers below copy into Nim
## strings and free immediately, so no C-owned memory escapes this module.

import std/strutils

{.passL: "-lnixdoc".}

type
  NixdocDocComment = object
    ## Opaque handle; the layout lives on the Rust side.

  NixdocStringArray = object
    data: ptr UncheckedArray[cstring]
    len: csize_t

  DocComment* = object
    ## A parsed doc comment, fully owned by Nim.
    title*: string
    description*: string
    typeSig*: string
    arguments*: seq[string]
    examples*: seq[string]
    notes*: seq[string]
    warnings*: seq[string]
    deprecated*: bool
    deprecationNotice*: string

  NixdocError* = object of CatchableError

const
  NixdocSuccess = 0.cint
  NixdocErrorParse = 1.cint
  NixdocErrorNull = 2.cint
  NixdocErrorPanic = 3.cint

proc nixdocParseInto(input: cstring,
    outDoc: ptr ptr NixdocDocComment): cint {.importc: "nixdoc_parse_into".}
proc nixdocFree(doc: ptr NixdocDocComment) {.importc: "nixdoc_free".}
proc nixdocIsDocComment(input: cstring): bool {.
    importc: "nixdoc_is_doc_comment".}
proc nixdocTitle(doc: ptr NixdocDocComment): cstring {.importc: "nixdoc_title".}
proc nixdocDescription(doc: ptr NixdocDocComment): cstring {.
    importc: "nixdoc_description".}
proc nixdocTypeSig(doc: ptr NixdocDocComment): cstring {.
    importc: "nixdoc_type_sig".}
proc nixdocIsDeprecated(doc: ptr NixdocDocComment): bool {.
    importc: "nixdoc_is_deprecated".}
proc nixdocDeprecationNotice(doc: ptr NixdocDocComment): cstring {.
    importc: "nixdoc_deprecation_notice".}
proc nixdocArguments(doc: ptr NixdocDocComment): ptr NixdocStringArray {.
    importc: "nixdoc_arguments".}
proc nixdocExamples(doc: ptr NixdocDocComment): ptr NixdocStringArray {.
    importc: "nixdoc_examples".}
proc nixdocNotes(doc: ptr NixdocDocComment): ptr NixdocStringArray {.
    importc: "nixdoc_notes".}
proc nixdocWarnings(doc: ptr NixdocDocComment): ptr NixdocStringArray {.
    importc: "nixdoc_warnings".}
proc nixdocFreeString(value: cstring) {.importc: "nixdoc_free_string".}
proc nixdocFreeStringArray(arr: ptr NixdocStringArray) {.
    importc: "nixdoc_free_string_array".}

proc takeString(value: cstring): string =
  ## Copy a C string into Nim and free the original.
  if value == nil:
    return ""
  result = $value
  nixdocFreeString(value)

proc takeStringArray(arr: ptr NixdocStringArray): seq[string] =
  ## Copy a C string array into Nim and free the original.
  if arr == nil:
    return @[]
  if arr.data != nil:
    for i in 0 ..< int(arr.len):
      let item = arr.data[i]
      if item != nil:
        result.add($item)
  nixdocFreeStringArray(arr)

proc isDocComment*(input: string): bool =
  ## True if `input` is shaped like an RFC 145 doc comment.
  nixdocIsDocComment(input.cstring)

proc parseDocComment*(input: string): DocComment =
  ## Parse a raw `/** … */` doc comment, delimiters included.
  ##
  ## Raises `NixdocError` if the input is not a well-formed doc comment.
  var handle: ptr NixdocDocComment = nil
  let status = nixdocParseInto(input.cstring, addr handle)
  case status
  of NixdocSuccess:
    discard
  of NixdocErrorParse:
    raise newException(NixdocError, "not a valid nixdoc comment")
  of NixdocErrorNull:
    raise newException(NixdocError, "null pointer passed to nixdoc")
  of NixdocErrorPanic:
    raise newException(NixdocError, "nixdoc panicked while parsing")
  else:
    raise newException(NixdocError, "unknown nixdoc status: " & $status)

  if handle == nil:
    raise newException(NixdocError, "nixdoc returned no document")
  defer: nixdocFree(handle)

  result = DocComment(
    title: takeString(nixdocTitle(handle)),
    description: takeString(nixdocDescription(handle)),
    typeSig: takeString(nixdocTypeSig(handle)),
    arguments: takeStringArray(nixdocArguments(handle)),
    examples: takeStringArray(nixdocExamples(handle)),
    notes: takeStringArray(nixdocNotes(handle)),
    warnings: takeStringArray(nixdocWarnings(handle)),
    deprecated: nixdocIsDeprecated(handle),
    deprecationNotice: takeString(nixdocDeprecationNotice(handle)),
  )

proc summary*(doc: DocComment): string =
  ## A one-line gloss for search output.
  ##
  ## Prefers the title, then the first non-empty line of the description, so a
  ## result stays readable on a single terminal row.
  if doc.title.len > 0:
    return doc.title.splitWhitespace().join(" ")
  for line in doc.description.splitLines():
    let stripped = line.strip()
    if stripped.len > 0:
      return stripped.splitWhitespace().join(" ")
  ""
