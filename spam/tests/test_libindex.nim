## Tests for binding doc comments to the attributes they document.
##
## The scan is lexical, so the cases that matter are the ones where `/**` or a
## quote appears somewhere it does not mean what it looks like: inside a
## string, inside an interpolation, inside an ordinary comment. Getting those
## wrong does not produce an error, it silently shifts every subsequent binding,
## so they are pinned here.

import std/[strutils]
import libindex

proc names(source: string): seq[string] =
  for function in scanNixSource(source, "test.nix"):
    result.add(function.name)

block bindsSimpleAttribute:
  let found = scanNixSource("""
{
  /** Concatenate strings. */
  concatStrings = xs: builtins.concatStringsSep "" xs;
}
""", "test.nix")
  doAssert found.len == 1
  doAssert found[0].name == "concatStrings"
  # Nim strips the leading newline of a triple-quoted string, so `{` is line 1.
  doAssert found[0].line == 3
  doAssert found[0].file == "test.nix"
  doAssert "Concatenate" in found[0].doc.description

block bindsDottedAndQuotedPaths:
  doAssert names("""
{
  /** A nested one. */
  types.nullOr = x: x;
  /** A quoted one. */
  "with-dashes" = 1;
}
""") == @["types.nullOr", "with-dashes"]

block ignoresDocCommentsInsideStrings:
  # The `/**` here is string content. If the lexer treats it as a comment it
  # will bind `notAnAttribute` and desynchronise from there on.
  doAssert names("""
{
  literal = "/** not a doc comment */ notAnAttribute = 1;";
  indented = ''/** also not one */ alsoNot = 2;'';
  /** The only real one. */
  real = 3;
}
""") == @["real"]

block handlesInterpolationContainingQuotes:
  # A naive string skipper ends the outer string at the inner quote and then
  # reads the rest of the file in the wrong lexical state.
  doAssert names("""
{
  tricky = "prefix ${concatStringsSep "," ["a" "b"]} suffix";
  /** Found after tricky interpolation. */
  afterwards = 1;
}
""") == @["afterwards"]

block handlesInterpolationInIndentedStrings:
  doAssert names("""
{
  script = ''
    echo "${lib.getExe pkg} /** nope */"
  '';
  /** Found after indented interpolation. */
  afterwards = 1;
}
""") == @["afterwards"]

block ignoresPlainBlockAndLineComments:
  doAssert names("""
{
  /* ordinary block comment, notThis = 1; */
  # line comment, norThis = 2;
  /**/
  /** Real. */
  yes = 3;
}
""") == @["yes"]

block skipsCommentsBetweenDocAndBinding:
  doAssert names("""
{
  /** Documented. */
  # an aside about the implementation
  documented = 1;
}
""") == @["documented"]

block requiresABinding:
  # A file-level doc comment documents the file, not the function literal that
  # follows it, and there is no attribute name to file it under.
  doAssert names("""
/** This file provides string helpers. */
{ lib }:
{
  /** Real. */
  yes = 1;
}
""") == @["yes"]

block rejectsInheritAndComparisons:
  doAssert names("""
{
  /** Not bindable. */
  inherit (lib) foo;
  /** Also not bindable. */
  check = a == b;
}
""") == @["check"]

block malformedDocCommentIsSkippedNotFatal:
  # Files under edit contain half-written comments; one bad comment must not
  # cost the rest of the file.
  let found = scanNixSource("""
{
  /**/
  /** */
  empty = 1;
  /** Fine. */
  good = 2;
}
""", "test.nix")
  var seen: seq[string]
  for f in found:
    seen.add(f.name)
  doAssert "good" in seen

block prefixIsApplied:
  let found = scanNixSource("""
{
  /** Doc. */
  concatStrings = 1;
}
""", "test.nix")
  doAssert found.len == 1
  doAssert found[0].name == "concatStrings"

echo "test_libindex: ok"
