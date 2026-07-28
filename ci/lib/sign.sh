#!/usr/bin/env bash
# ci/lib/sign.sh
#
# GPG detached-signature helper. Sources nothing; call sign_file()
# after sourcing this file.
#
# Usage:
#   source ci/lib/sign.sh
#   sign_file <path-to-file>            # produces <path>.asc
#
# If RNP_GPG_KEY_ID is unset or the key isn't in the keyring, the
# function is a no-op (prints a notice). The workflow is responsible
# for importing the key before the build script runs.

sign_file() {
    local file="$1"
    if [[ -z "${RNP_GPG_KEY_ID:-}" ]]; then
        echo "RNP_GPG_KEY_ID not set; skipping GPG signature for $(basename "$file")."
        return 0
    fi
    if ! gpg --list-secret-keys "$RNP_GPG_KEY_ID" >/dev/null 2>&1; then
        echo "RNP_GPG_KEY_ID='$RNP_GPG_KEY_ID' not in keyring; skipping signature for $(basename "$file")."
        return 0
    fi
    echo "Signing $(basename "$file") with key $RNP_GPG_KEY_ID"
    gpg --batch --yes --detach-sign --armor \
        --local-user "$RNP_GPG_KEY_ID" \
        --output "${file}.asc" \
        "$file"
}
