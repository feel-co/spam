import std/[json, os, parseopt, streams, strutils]

proc showHelp() =
  stderr.writeLine("TBI") # TODO implement
  quit()

var
  optParser = initOptParser(shortNoVal = {'h'}, longNoVal = @["help"])
  argCount = 0
  subcommand = ""
  searchStr: string
  optJsonPath: string

for kind, key, val in optParser.getopt():
  case kind
  of cmdArgument:
    inc argCount
    if argCount == 1 and subcommand == "":
      case key
      of "opt", "pkg": subcommand = key
    else:
      searchStr = key
      break
  of cmdLongOption, cmdShortOption:
    case key
    of "help", "h":
      showHelp()

    case subcommand
    of "opt":
      if key == "module-options":
        if not fileExists(val):
          stderr.writeLine("file ", val, " does not exist")
          quit(1)
        optJsonPath = val
        continue
    of "pkg":
      continue

    stderr.writeLine("unknown option: ", key)
    quit(1)

  of cmdEnd:
    showHelp()


if optJsonPath == "":
  stderr.writeLine("--module-options must be provided")
  quit(1)

let
  opts = parseJson(newFileStream(optJsonPath))

for k in keys(opts):
  if searchStr in k:
    echo k
