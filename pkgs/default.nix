{ inputs, ... }:
{
  imports = [ inputs.fp.flakeModules.easyOverlay ];

  perSystem =
    {
      final,
      lib,
      self',
      system,
      ...
    }:
    {
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        config.allowlistedLicenses = with lib.licenses; [ cc-by-nc-sa-40 ];
      };

      devShells.default = final.mkShell {
        inputsFrom = [ self'.packages.default ];
        packages = [ final.nimble ];
      };

      overlayAttrs = {
        MYNAME = self'.packages.default;
      };

      packages.default = final.callPackage ./package.nix { };
    };
}
