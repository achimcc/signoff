{
  description = "Is the service really done? Live acceptance checks for a self-hosted service";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "signoff";
          version = (nixpkgs.lib.importTOML ./Cargo.toml).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = "Is the service really done? Live acceptance checks for a self-hosted service";
            homepage = "https://github.com/achimcc/signoff";
            license = pkgs.lib.licenses.agpl3Only;
            mainProgram = "signoff";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = with pkgs; [ cargo rustc rustfmt clippy ]; };
      });

      checks = forAll (
        pkgs:
        let
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          inherit package;
          clippy = package.overrideAttrs (old: {
            pname = "signoff-clippy";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
            buildPhase = "cargo clippy --all-targets -- -D warnings";
            doCheck = false;
            installPhase = "touch $out";
          });
          fmt = package.overrideAttrs (old: {
            pname = "signoff-fmt";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.rustfmt ];
            buildPhase = "cargo fmt --check";
            doCheck = false;
            installPhase = "touch $out";
          });
        }
      );
    };
}
