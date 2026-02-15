{
  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

    fp = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    { fp, nixpkgs, ... }@inputs:
    fp.lib.mkFlake { inherit inputs; } {
      imports = [ ./pkgs ];

      systems = nixpkgs.lib.systems.flakeExposed;
      perSystem =
        { pkgs, ... }:
        {
          formatter = pkgs.writeShellApplication {
            name = "nimpretty-nixfmt-wrapper";

            runtimeInputs = [
              pkgs.coreutils-full
              pkgs.fd
              pkgs.nim
              pkgs.nixfmt-rfc-style
            ];

            text = ''
              realpath "$@"
              fd "$@" -t f -e nix -x nixfmt '{}'
              fd "$@" -t f -e nim -x nimpretty '{}'
            '';
          };
        };
    };
}
