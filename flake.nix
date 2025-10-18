{
  description = "apk-info";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      fenix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        fenix-pkgs = fenix.packages.${system};
        toolchain =
          with fenix-pkgs;
          combine [
            (latest.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
            ])
          ];
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo-fuzz
            maturin
            openssl
            pkg-config
            toolchain
            fenix-pkgs.latest.rust-analyzer
          ];
        };

        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = manifest.name;
            version = manifest.version;
            cargoLock.lockFile = ./Cargo.lock;
            src = pkgs.lib.cleanSource ./.;
          };
        };
      }
    );
}
