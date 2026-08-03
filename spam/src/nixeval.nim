## Shelling out to Nix for the pieces of a nixpkgs index that cannot be
## obtained from the binary cache.
##
## Packages come from the cache's file listings, but library functions live in
## the nixpkgs tree and module options only exist after the module system has
## been evaluated. Both are produced here.

import std/[os, osproc, streams, strutils]

type NixEvalError* = object of CatchableError

proc nixFail(message: string) {.noreturn.} =
  raise newException(NixEvalError, message)

proc run(command: string, args: openArray[string], what: string,
    verbose: bool): string =
  # The option-doc expression is a dozen lines long, so log the intent rather
  # than the argument vector.
  if verbose:
    stderr.writeLine("spam: " & what & " (" & command & ")")
  let process = startProcess(command, args = args, options = {poUsePath,
      poStdErrToStdOut})
  defer: process.close()
  let
    output = process.outputStream.readAll()
    code = process.waitForExit()
  if code != 0:
    nixFail(what & " failed (" & command & " exited " & $code & "):\n" &
      output.strip())
  output.strip()

proc resolveNixpkgs*(spec: string, verbose = false): string =
  ## Turn a `--nixpkgs` value into a directory that can be scanned.
  ##
  ## `nix-env -f` accepts both a path and a `<nixpkgs>` lookup, but a lexical
  ## scan of `lib/` needs a real directory, so search-path forms are resolved
  ## through `nix-instantiate --find-file`.
  if dirExists(spec):
    return spec.absolutePath()

  var name = spec
  if name.startsWith("<") and name.endsWith(">"):
    name = name[1 ..< name.len - 1]
  if name.len == 0:
    nixFail("empty --nixpkgs value")

  let resolved = run("nix-instantiate", ["--find-file", name],
    "resolving " & spec, verbose)
  if not dirExists(resolved):
    nixFail(spec & " resolved to " & resolved & ", which is not a directory")
  resolved

proc nixosOptionsJson*(nixpkgs, system: string, verbose = false): string =
  ## Build `nixosOptionsDoc` for an empty NixOS configuration and return the
  ## path of the resulting `options.json`.
  ##
  ## An empty module list still pulls in every module nixpkgs declares, which
  ## is exactly the option set a global index should carry.
  let systemArg =
    if system.len > 0: "system = \"" & system & "\";"
    else: ""
  let expr = """
    let
      pkgs = import """ & nixpkgs & """ { };
      eval = import (""" & nixpkgs & """ + "/nixos/lib/eval-config.nix") {
        modules = [ ];
        """ & systemArg & """
      };
    in
    (pkgs.nixosOptionsDoc { inherit (eval) options; }).optionsJSON
  """

  let storePath = run("nix-build", ["--no-out-link", "--expr", expr],
    "building NixOS option documentation", verbose)
  # nix-build prints one path per output; the doc derivation has exactly one.
  let root = storePath.splitLines()[^1].strip()
  let optionsJson = root / "share" / "doc" / "nixos" / "options.json"
  if not fileExists(optionsJson):
    nixFail("nixosOptionsDoc produced no options.json at " & optionsJson)
  optionsJson
