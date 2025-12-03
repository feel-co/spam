version       = "0.0.1"
author        = "éclairevoyant"
description   = "Search packages and module options"
license       = "CC-by-nc-sa-4.0"
srcDir        = "src"
bin           = @["spam"]

requires "nim >= 2.2.0"

task release, "Release build":
  exec "nimble build -d:release --opt:speed"
#  exec "pandoc -s -o FIXME.1 doc/FIXME.man1.md"
