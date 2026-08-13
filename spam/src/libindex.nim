## Discovery of documented Nix library functions.
##
## `nixdoc` parses doc-comment text but has no notion of Nix files or of which
## attribute a comment belongs to. This module supplies that half: it walks Nix
## source, finds `/** … */` doc comments, and binds each to the attribute it
## documents, so `lib.strings.concatStrings` can be looked up by name.
##
## The scan is lexical, not a full Nix parse. That is a deliberate trade: the
## files spam is pointed at are often fragments a user is editing, which need
## not evaluate or even parse completely, and a lexer still yields useful
## results for them. What the lexer must get right is knowing when it is inside
## a string or an ordinary comment, since `/**` appearing in either is not a doc
## comment. A binding is only recorded when a doc comment is followed by an
## attribute path and `=`, which keeps stray comments from attaching to
## something arbitrary.

import std/[os, strutils]
import nixdoc

type
  LibFunction* = object
    ## A documented attribute discovered in Nix source.
    name*: string
      ## Attribute path as written at the binding site, e.g. "concatStrings"
      ## or "types.nullOr".
    file*: string
      ## Source file the binding was found in.
    line*: int
      ## 1-based line of the binding.
    doc*: DocComment
      ## Parsed doc comment.

  Scanner = object
    source: string
    pos: int
    line: int

proc atEnd(s: Scanner): bool {.inline.} =
  s.pos >= s.source.len

proc peek(s: Scanner, offset = 0): char {.inline.} =
  let at = s.pos + offset
  if at < s.source.len: s.source[at] else: '\0'

proc advance(s: var Scanner) {.inline.} =
  if s.source[s.pos] == '\n':
    inc s.line
  inc s.pos

proc advance(s: var Scanner, count: int) {.inline.} =
  for _ in 0 ..< count:
    if s.atEnd:
      return
    s.advance()

proc skipLineComment(s: var Scanner) =
  while not s.atEnd and s.peek() != '\n':
    s.advance()

proc skipBlockComment(s: var Scanner) =
  ## Consume a `/* … */` comment. Nix block comments do not nest.
  s.advance(2)
  while not s.atEnd:
    if s.peek() == '*' and s.peek(1) == '/':
      s.advance(2)
      return
    s.advance()

proc skipDoubleQuoted(s: var Scanner)
proc skipIndentedString(s: var Scanner)

proc skipInterpolation(s: var Scanner) =
  ## Consume a `${ … }` interpolation.
  ##
  ## The body is arbitrary Nix, so it can contain braces, strings and comments
  ## of its own. Tracking those is what keeps a `"` inside an interpolation
  ## from being mistaken for the end of the enclosing string.
  s.advance(2)
  var depth = 1
  while not s.atEnd and depth > 0:
    let c = s.peek()
    if c == '{':
      depth.inc
      s.advance()
    elif c == '}':
      depth.dec
      s.advance()
    elif c == '"':
      s.skipDoubleQuoted()
    elif c == '\'' and s.peek(1) == '\'':
      s.skipIndentedString()
    elif c == '#':
      s.skipLineComment()
    elif c == '/' and s.peek(1) == '*':
      s.skipBlockComment()
    else:
      s.advance()

proc skipDoubleQuoted(s: var Scanner) =
  ## Consume a `"…"` string, honouring backslash escapes and interpolation.
  s.advance()
  while not s.atEnd:
    let c = s.peek()
    if c == '\\':
      s.advance(2)
    elif c == '$' and s.peek(1) == '{':
      s.skipInterpolation()
    elif c == '"':
      s.advance()
      return
    else:
      s.advance()

proc skipIndentedString(s: var Scanner) =
  ## Consume a `''…''` string. Inside one, `'''`, `''$` and `''\` are escapes
  ## rather than terminators.
  s.advance(2)
  while not s.atEnd:
    if s.peek() == '\'' and s.peek(1) == '\'':
      case s.peek(2)
      of '\'', '$', '\\':
        s.advance(3)
      else:
        s.advance(2)
        return
    elif s.peek() == '$' and s.peek(1) == '{':
      s.skipInterpolation()
    else:
      s.advance()

proc isIdentStart(c: char): bool {.inline.} =
  c in {'a' .. 'z', 'A' .. 'Z', '_'}

proc isIdentChar(c: char): bool {.inline.} =
  c in {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '_', '\'', '-'}

proc skipTrivia(s: var Scanner) =
  ## Skip whitespace and ordinary comments, stopping before anything else.
  while not s.atEnd:
    let c = s.peek()
    if c in {' ', '\t', '\r', '\n'}:
      s.advance()
    elif c == '#':
      s.skipLineComment()
    elif c == '/' and s.peek(1) == '*':
      s.skipBlockComment()
    else:
      return

proc readAttrPath(s: var Scanner): string =
  ## Read a dotted attribute path at the current position.
  ##
  ## Returns "" if what follows is not an attribute path. Dynamic components
  ## (`${…}`) make the name unusable as a search key, so those are rejected
  ## outright rather than recorded under a misleading name.
  while true:
    s.skipTrivia()
    var component = ""
    if s.peek().isIdentStart():
      while not s.atEnd and s.peek().isIdentChar():
        component.add(s.peek())
        s.advance()
    elif s.peek() == '"':
      let start = s.pos
      s.skipDoubleQuoted()
      component = s.source[start + 1 ..< max(start + 1, s.pos - 1)]
      if '$' in component or '\\' in component:
        return ""
    else:
      return ""

    if component.len == 0:
      return ""
    if result.len > 0:
      result.add('.')
    result.add(component)

    let mark = s.pos
    let markLine = s.line
    s.skipTrivia()
    if s.peek() == '.':
      s.advance()
    else:
      s.pos = mark
      s.line = markLine
      return

proc bindingAfterDoc(s: var Scanner): tuple[name: string, line: int] =
  ## Read the attribute path bound immediately after a doc comment.
  ##
  ## Returns an empty name unless the path is followed by `=` (and not `==`),
  ## which is what makes this a definition rather than a use.
  let mark = s.pos
  let markLine = s.line

  s.skipTrivia()
  let line = s.line
  let name = s.readAttrPath()
  if name.len == 0 or name == "inherit":
    s.pos = mark
    s.line = markLine
    return ("", 0)

  s.skipTrivia()
  if s.peek() == '=' and s.peek(1) != '=':
    return (name, line)

  s.pos = mark
  s.line = markLine
  ("", 0)

proc scanNixSource*(source, file: string): seq[LibFunction] =
  ## Find documented attributes in `source`.
  ##
  ## Comments that parse as doc comments but document nothing bindable (a
  ## file-level comment above `{ … }:`, for instance) are skipped rather than
  ## attached to an unrelated attribute.
  var s = Scanner(source: source, pos: 0, line: 1)

  while not s.atEnd:
    let c = s.peek()
    if c == '#':
      s.skipLineComment()
    elif c == '"':
      s.skipDoubleQuoted()
    elif c == '\'' and s.peek(1) == '\'':
      s.skipIndentedString()
    elif c == '/' and s.peek(1) == '*':
      let start = s.pos
      # `/**` opens a doc comment, but `/**/` is just an empty block comment.
      let isDoc = s.peek(2) == '*' and s.peek(3) != '/'
      s.skipBlockComment()
      if not isDoc:
        continue

      let text = s.source[start ..< s.pos]
      let binding = s.bindingAfterDoc()
      if binding.name.len == 0:
        continue

      var parsed: DocComment
      try:
        parsed = parseDocComment(text)
      except NixdocError:
        # Malformed doc comments are common in files being edited; skipping
        # one is correct, failing the whole scan is not.
        continue

      result.add(LibFunction(
        name: binding.name,
        file: file,
        line: binding.line,
        doc: parsed,
      ))
    else:
      s.advance()

proc scanNixFile*(path: string): seq[LibFunction] =
  ## Find documented attributes in the Nix file at `path`.
  scanNixSource(readFile(path), path)

iterator nixFiles*(root: string): string =
  ## Yield Nix files under `root`, or `root` itself if it is a file.
  if fileExists(root):
    yield root
  else:
    for path in walkDirRec(root, yieldFilter = {pcFile, pcLinkToFile}):
      if path.endsWith(".nix"):
        yield path

proc scanNixTree*(root, prefix: string): seq[LibFunction] =
  ## Find documented attributes in every Nix file under `root`.
  ##
  ## `prefix` is prepended to each discovered name. A lexical scan sees only
  ## the binding site, so `lib/strings.nix` yields `concatStrings`, not
  ## `lib.strings.concatStrings`; the caller supplies the missing context
  ## rather than spam inferring it from directory layout.
  for file in nixFiles(root):
    for function in scanNixFile(file):
      var entry = function
      if prefix.len > 0:
        entry.name = prefix & "." & entry.name
      result.add(entry)
