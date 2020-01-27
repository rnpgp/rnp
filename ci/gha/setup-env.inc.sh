set -euxo pipefail
# execute this script in a separate, early step

echo "::set-env name=LOCAL_BUILDS::$GITHUB_WORKSPACE/builds"

# To install and cache our dependencies we need an absolute path
# that does not change, is writable, and resides within
# GITHUB_WORKSPACE.
# On macOS GITHUB_WORKSPACE includes the github runner version,
# so it does not remain constant.
# This causes problems with, for example, pkgconfig files
# referencing paths that no longer exist.
mkdir -p installs
ln -s "$GITHUB_WORKSPACE/installs" /tmp/rnp-local-installs
echo "::set-env name=CACHE_DIR::installs"
echo "::set-env name=LOCAL_INSTALLS::/tmp/rnp-local-installs"

# set this explicitly since we don't want to cache the rnp installation
echo "::set-env name=RNP_INSTALL::$GITHUB_WORKSPACE/rnp-install"

echo "::set-env name=VERSION_OVERRIDE_BRANCH::${GITHUB_REF#refs/heads/}"

