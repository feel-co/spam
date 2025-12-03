{
  lib,
  nixosOptionsDoc,
}:
let
  evaluatedModules = lib.evalModules {
    modules = [
      {
        options = {
          hello = lib.mkOption {
            default = "world";
            defaultText = lib.literalMD ''
              ```nix
              # comment
              a: lib.hasSuffix "test" a
              ```
            '';
            description = "Example option.";
            type = lib.types.str;
          };

          bye.a.b.c = lib.mkEnableOption "";
        };
        config._module.check = false;
      }
    ];
  };
in
(nixosOptionsDoc {
  inherit (evaluatedModules) options;
}).optionsJSON
