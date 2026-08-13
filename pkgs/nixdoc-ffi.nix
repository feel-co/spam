{
  lib,
  stdenv,
  rustPlatform,
  fetchFromGitHub,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "nixdoc-ffi";
  version = "0-unstable-2026-08-03";
  __structuredAttrs = true;

  src = fetchFromGitHub {
    owner = "feel-co";
    repo = "nixdoc";
    rev = "04f125b4c56ccadc31f11245366c830e4b8d60b2";
    hash = "sha256-PNaf6N8fS66EICfZwY7lpNjTr+zdBv9QaJuRENPV/Q8=";
  };

  cargoLock.lockFile = "${finalAttrs.src}/Cargo.lock";
  buildAndTestSubdir = "crates/nixdoc-ffi";
  doCheck = false;

  # Doesn't look like buildRustPackage can actually install library targets
  # so we'll have to override the install phase to do it by ourselves :/
  installPhase = ''
    runHook preInstall

    install -Dm755 -t "$out/lib" \
      "target/${stdenv.hostPlatform.rust.cargoShortTarget}/release/libnixdoc${stdenv.hostPlatform.extensions.sharedLibrary}"
    install -Dm644 -t "$out/lib" \
      "target/${stdenv.hostPlatform.rust.cargoShortTarget}/release/libnixdoc.a"

    runHook postInstall
  '';

  meta = {
    description = "C shared/static library build of nixdoc";
    homepage = "https://github.com/feel-co/nixdoc";
    license = lib.licenses.mpl20;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
})
