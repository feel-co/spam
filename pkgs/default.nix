{ inputs, ... }:
{
  imports = [ inputs.fp.flakeModules.easyOverlay ];

  perSystem =
    {
      final,
      self',
      system,
      lib,
      ...
    }:
    {
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        config.allowlistedLicenses = with lib.licenses; [ cc-by-nc-sa-40 ];
      };

      devShells.default = final.mkShell {
        strictDeps = true;
        inputsFrom = [ self'.packages.default ];
        packages = [
          final.nimble

          # Rust
          final.cargo
          final.rustc
          final.lld
        ];
      };

      overlayAttrs = {
        MYNAME = self'.packages.default;
      };

      packages = {
        spam = final.callPackage ./package.nix { };
        default = self'.packages.spam;
      };
    };
}
