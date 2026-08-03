version       = "0.0.1"
author        = "éclairevoyant"
description   = "Search packages and module options"
license       = "CC-by-nc-sa-4.0"
srcDir        = "src"
bin           = @["spam"]

requires "nim >= 2.2.0"

task test, "Run tests":
  exec "nim c --path:src --run -r tests/test_index_utf8.nim"
  exec "nim c --path:src --run -r tests/test_dbformat.nim"
  exec "nim c --path:src -d:ssl --run -r tests/test_cache_encoding.nim"
  exec "nim c --path:src --run -r tests/test_libindex.nim"

task release, "Release build":
  exec "nimble build -d:release -d:ssl --opt:speed"
