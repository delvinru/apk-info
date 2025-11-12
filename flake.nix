{
  description = "apk-info";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = {
    nixpkgs,
    flake-utils,
    fenix,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pname = "apk-info";

        pkgs = import nixpkgs {
          inherit system;
        };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).workspace.package;
        fenix-pkgs = fenix.packages.${system};
        toolchain = with fenix-pkgs;
          combine [
            (latest.withComponents [
              "cargo"
              "clippy"
              "miri"
              "rust-src"
              "rustc"
              "rustfmt"
            ])
          ];
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo-fuzz
            cargo-machete
            maturin
            openssl
            pkg-config
            toolchain
            fenix-pkgs.latest.rust-analyzer
          ];
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = pname;
          version = manifest.version;
          src = pkgs.lib.cleanSource ./.;
          cargoBuildFlags = "--package apk-info-cli";
          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          doCheck = false;

          nativeBuildInputs = with pkgs; [
            openssl
            perl
            pkg-config
            installShellFiles
          ];

          postInstall = ''
            installShellCompletion --cmd apk-info \
              --bash <($out/bin/apk-info completion bash) \
              --fish <($out/bin/apk-info completion fish) \
              --zsh <($out/bin/apk-info completion zsh)
          '';

          CARGO_PROFILE = "release-lto";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };
      }
    );
}
