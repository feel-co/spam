{
  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

    fp = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    {
      fp,
      nixpkgs,
      ...
    }@inputs:
    fp.lib.mkFlake { inherit inputs; } {
      imports = [ ./pkgs ];

      systems = nixpkgs.lib.systems.flakeExposed;
      perSystem =
        { pkgs, ... }:
        {
          formatter = pkgs.writeShellApplication {
            name = "nix3-nixfmt-wrapper";

            runtimeInputs = [
              pkgs.coreutils-full
              pkgs.fd
              pkgs.nim
              pkgs.nixfmt

              # Rust
              (pkgs.rustfmt.override { asNightly = true; })
              pkgs.taplo
            ];

            text = ''
              fd "$@" -t f -e nix -x nixfmt '{}'
              fd "$@" -t f -e nim -x nimpretty '{}'
              fd "$@" -t f -e toml -x taplo fmt '{}'
              fd "$@" -t f -e rust -x rustfmt --edition 2024 --config-path ./spam-db/.rustfmt.toml '{}'
            '';
          };
        };
    };
}
