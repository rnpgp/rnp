#!/usr/bin/env bash
# ci/write_sbom_manifests.sh
#
# Emit deterministic per-component vcpkg.json manifests under
# <dest_dir>/share/rnp/components/<name>/vcpkg.json so syft's default
# vcpkg-manifest-cataloger captures component identities, versions, and
# SPDX license expressions in both SPDX 3.0 and CycloneDX 1.7 SBOMs.
#
# Usage:
#   ci/write_sbom_manifests.sh source   <dest_dir> <rnp_version> [rnp_src]
#   ci/write_sbom_manifests.sh prebuilt <dest_dir> <rnp_version> <backend> [rnp_src]

set -euo pipefail

MODE="${1:?usage: write_sbom_manifests.sh <source|prebuilt> <dest_dir> <rnp_version> [backend] [rnp_src]}"
DEST_DIR="${2:?missing dest_dir}"
RAW_VERSION="${3:?missing rnp_version}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$MODE" == "source" ]]; then
    BACKEND=""
    RNP_SRC="${4:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
elif [[ "$MODE" == "prebuilt" ]]; then
    BACKEND="${4:?missing backend (botan|openssl)}"
    RNP_SRC="${5:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
else
    echo "ERROR: unknown mode '$MODE' (expected source or prebuilt)" >&2
    exit 1
fi

# Resolve RNP version: strip leading 'v'; if not semver-like, fall back to version.txt.
RNP_VERSION="${RAW_VERSION#v}"
if [[ ! "$RNP_VERSION" =~ ^[0-9]+\.[0-9]+ ]]; then
    if [[ -f "${RNP_SRC}/version.txt" ]]; then
        RNP_VERSION="$(tr -d '[:space:]' < "${RNP_SRC}/version.txt")"
    fi
fi

# Resolve bundled sexpp version from submodule version.txt.
SEXPP_VERSION="0.9.0"
if [[ -f "${RNP_SRC}/src/libsexpp/version.txt" ]]; then
    SEXPP_VERSION="$(tr -d '[:space:]' < "${RNP_SRC}/src/libsexpp/version.txt")"
fi

# Resolve vendored nlohmann-json version from header comment.
NLOHMANN_JSON_VERSION="3.11.3"
if [[ -f "${RNP_SRC}/src/lib/nlohmann/nlohmann/json.hpp" ]]; then
    parsed_json_ver="$(awk '/version [0-9]+\.[0-9]+\.[0-9]+/ { if (match($0, /[0-9]+\.[0-9]+\.[0-9]+/)) { print substr($0, RSTART, RLENGTH); exit } }' "${RNP_SRC}/src/lib/nlohmann/nlohmann/json.hpp")"
    if [[ -n "$parsed_json_ver" ]]; then
        NLOHMANN_JSON_VERSION="$parsed_json_ver"
    fi
fi

# Source pinned component versions (single source of truth).
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/prebuilt-versions.env"
: "${SHA1CD_VERSION:?missing in prebuilt-versions.env}"

MANIFEST_ROOT="${DEST_DIR}/share/rnp/components"

write_manifest() {
    local name="$1"
    local version="$2"
    local license="$3"
    local homepage="$4"
    local dir="${MANIFEST_ROOT}/${name}"
    mkdir -p "$dir"
    cat > "${dir}/vcpkg.json" <<EOF
{
  "name": "${name}",
  "version-string": "${version}",
  "license": "${license}",
  "homepage": "${homepage}"
}
EOF
}

# Core RNP and vendored/submodule components present in both source and prebuilt tarballs.
write_manifest "rnp" "${RNP_VERSION}" "BSD-2-Clause AND Apache-2.0 AND BSD-3-Clause AND MIT" "https://github.com/rnpgp/rnp"
write_manifest "sexpp" "${SEXPP_VERSION}" "MIT" "https://github.com/rnpgp/sexpp"
write_manifest "nlohmann-json" "${NLOHMANN_JSON_VERSION}" "MIT" "https://github.com/nlohmann/json"
write_manifest "sha1collisiondetection" "${SHA1CD_VERSION}" "MIT" "https://github.com/cr-marcstevens/sha1collisiondetection"

# Prebuilt tarballs additionally bundle static archives for zlib, bzip2, and the crypto backend.
if [[ "$MODE" == "prebuilt" ]]; then
    : "${ZLIB_VERSION:?missing in prebuilt-versions.env}"
    : "${BZIP2_VERSION:?missing in prebuilt-versions.env}"
    : "${BOTAN_VERSION:?missing in prebuilt-versions.env}"
    : "${OPENSSL_VERSION:?missing in prebuilt-versions.env}"

    write_manifest "zlib" "${ZLIB_VERSION}" "Zlib" "https://zlib.net"
    write_manifest "bzip2" "${BZIP2_VERSION}" "bzip2-1.0.6" "https://sourceware.org/bzip2/"

    case "$BACKEND" in
        botan)
            write_manifest "botan" "${BOTAN_VERSION}" "BSD-2-Clause" "https://botan.randombit.net"
            ;;
        openssl)
            write_manifest "openssl" "${OPENSSL_VERSION}" "Apache-2.0" "https://www.openssl.org"
            ;;
        *)
            echo "ERROR: unsupported backend '$BACKEND' (expected botan or openssl)" >&2
            exit 1
            ;;
    esac
fi
