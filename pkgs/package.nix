{
  lib,
  buildNimPackage,
  jq,
  openssl,
  pandoc,
  zstd,
  brotli,
  callPackage,
}:
let
  testOpt = callPackage ../test/opt.nix { };
in
buildNimPackage (finalAttrs: {
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

  nimFlags = [ "-d:ssl" ];

  nativeBuildInputs = [
    jq
    pandoc
  ];

  buildInputs = [
    openssl
    zstd
    brotli
  ];

  postBuild = ''
    nim jsondoc -d:ssl --outdir:jsondocs src/spam.nim
    jq -r '.moduleDescription' jsondocs/spam.json > ${finalAttrs.pname}.1.html
    pandoc \
      -s \
      -f html \
      -t man \
      --metadata title=${lib.escapeShellArg finalAttrs.pname} \
      --metadata section=1 \
      -o ${finalAttrs.pname}.1 \
      ${finalAttrs.pname}.1.html
    nim doc -d:ssl --outdir:htmldocs src/spam.nim
  '';

  postInstall = ''
    install -Dm644 ${finalAttrs.pname}.1 -t "$out/share/man/man1/"
    mkdir -p "$out/share/doc/${finalAttrs.pname}"
    cp -R htmldocs/. "$out/share/doc/${finalAttrs.pname}/"
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
