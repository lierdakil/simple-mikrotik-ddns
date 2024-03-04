{
  description = "Simple Mikrotik DDNS";

  inputs = {
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem [flake-utils.lib.system.x86_64-linux] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
      in
      with pkgs;
      {
        inherit pkgs;
        devShells.default = mkShell {
          buildInputs = [
            rustc
            cargo
            clippy
            rust-analyzer
            rustfmt
            openssl
          ];
          # Environment variables
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
        packages.default = rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          src = lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          # cargoSha256 = "sha256-kDOopnsFzshSXsA6XGpcMsJ92Rno4pqBQkZ5ES54JbM="; #lib.fakeSha256;
          nativeBuildInputs = [ pkg-config ];
          buildInputs = [ openssl ];
        };
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };
      }
    );
}
