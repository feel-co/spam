{
  lib,
  buildNimPackage,
  pandoc,
  zstd,
  callPackage,
}:
let
  testOpt = callPackage ../test/opt.nix { };
in
buildNimPackage (finalAttrs: rec {
  pname = "spam";
  version = "0.0.1";

  src =
    let
      fs = lib.fileset;
      s = ../spam;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (fs.fileFilter (
          file:
          builtins.any file.hasExt [
            "md"
          ]
        ) (s + /doc))
        (fs.fileFilter (
          file:
          builtins.any file.hasExt [
            "nim"
          ]
        ) (s + /src))
        (fs.fileFilter (
          file:
          builtins.any file.hasExt [
            "nimble"
          ]
        ) s)
      ];
    };

  nativeBuildInputs = [
    pandoc
  ];

  buildInputs = [
    zstd
  ];

  postBuild = ''
    pandoc -s -o ${finalAttrs.pname}.1 doc/${pname}.man1.md
  '';

  postInstall = ''
    install -Dm644 ${finalAttrs.pname}.1 -t "$out/share/man/man1/"
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    test $($out/bin/spam opt --module-options ${testOpt}/share/doc/nixos/options.json bye) = "bye.a.b.c"
  '';

  meta = {
    description = "Search packages and module options";
    homepage = "https://github.com/feel-co/spam";
    license = lib.licenses.cc-by-nc-sa-40;
    mainProgram = "spam";
    maintainers = lib.teams.feel-co;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
})
