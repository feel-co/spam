{
  lib,
  stdenv,
  fixDarwinDylibNames,
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
    rev = "2d3cb7c9b6dd8b7f48cd90a99980b8c47b965c7f";
    hash = "sha256-Zu2MAYNsmz2gCYUX8uS0dtwWcul7c/k1MN2bNluJPrY=";
  };

  nativeBuildInputs = lib.optional stdenv.hostPlatform.isDarwin fixDarwinDylibNames;

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
