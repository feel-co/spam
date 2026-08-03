{inputs, ...}: {
  imports = [inputs.fp.flakeModules.easyOverlay];

  perSystem = {
    final,
    self',
    system,
    config,
    lib,
    ...
  }: {
    _module.args.pkgs = import inputs.nixpkgs {
      inherit system;
      config.allowlistedLicenses = with lib.licenses; [cc-by-nc-sa-40];
    };

    devShells.default = final.mkShell {
      strictDeps = true;
      inputsFrom = [self'.packages.default];
      packages = [
        final.nimble

        # Rust
        final.cargo
        final.rustc
        final.lld
      ];
    };

    overlayAttrs = {
      spam = self'.packages.default;
    };

    packages = {
      nixdoc-ffi = final.callPackage ./nixdoc-ffi.nix {};
      spam = final.callPackage ./spam.nix {
        inherit (config.packages) nixdoc-ffi;
      };

      default = self'.packages.spam;
    };
  };
}
