{
  description = "High performance C++ OpenPGP library, fully compliant to RFC 4880";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    sexp.url = "github:rnpgp/sexp";
  };

  outputs = { self, nixpkgs, flake-utils, sexp }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        thePackage = pkgs.callPackage ./default.nix { };
      in
      rec {
        defaultApp = flake-utils.lib.mkApp {
          drv = defaultPackage;
        };
        defaultPackage = thePackage;
        devShell = pkgs.mkShell {
          buildInputs = [
            thePackage
          ];
        };
      });
}
