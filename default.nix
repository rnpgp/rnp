{ pkgs ? import <nixpkgs> { }
, lib ? pkgs.lib
, stdenv ? pkgs.stdenv
, fetchgit
}:
let
  sexpSource = fetchgit {
    name = "sexp";
    url = "https://github.com/rnpgp/sexp.git";
    rev = "refs/tags/v0.6.0";
    sha256 = "oWOzVn7j2pYr4CxyN8O5f1n0tUxCIQ5YG5GZFvLMeGA=";
  };
in
stdenv.mkDerivation rec {
  pname = "rnp";
  version = "unstable";

  src = ./.;

  sexp = import sexpSource { inherit pkgs; };

  buildInputs = with pkgs; [ zlib bzip2 json_c botan2 sexp ];

  cmakeFlags = [
    "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
    "-DBUILD_SHARED_LIBS=on"
    "-DBUILD_TESTING=on"
    "-DDOWNLOAD_GTEST=off"
    "-DDOWNLOAD_RUBYRNP=off"
  ];

  nativeBuildInputs = with pkgs; [ asciidoctor cmake gnupg gtest pkg-config python3 ];

  # NOTE: check-only inputs should ideally be moved to checkInputs, but it
  # would fail during buildPhase.
  # checkInputs = [ gtest python3 ];

  outputs = [ "out" "lib" "dev" ];

  preConfigure = ''
    commitEpoch=$(date +%s)
    baseVersion=$(cat version.txt)
    echo "v$baseVersion-0-g0-dirty+$commitEpoch" > version.txt

    # For generating the correct timestamp in cmake
    export SOURCE_DATE_EPOCH=$commitEpoch
  '';

  meta = with lib; {
    homepage = "https://github.com/rnpgp/rnp";
    description = "High performance C++ OpenPGP library, fully compliant to RFC 4880";
    license = licenses.bsd2;
    platforms = platforms.all;
    maintainers = with maintainers; [ ribose-jeffreylau ];
  };
}
