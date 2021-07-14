set -euxo pipefail
# execute this script in a separate, early step

echo "LOCAL_BUILDS=$GITHUB_WORKSPACE/builds" >> $GITHUB_ENV

# To install and cache our dependencies we need an absolute path
# that does not change, is writable, and resides within
# GITHUB_WORKSPACE.
# On macOS GITHUB_WORKSPACE includes the github runner version,
# so it does not remain constant.
# This causes problems with, for example, pkgconfig files
# referencing paths that no longer exist.
mkdir -p installs
ln -s "$GITHUB_WORKSPACE/installs" /tmp/rnp-local-installs
echo "CACHE_DIR=installs" >> $GITHUB_ENV
echo "LOCAL_INSTALLS=/tmp/rnp-local-installs" >> $GITHUB_ENV

# When building packages, dependencies with non-standard installation paths must 
# be found by the (DEB) package builder.
echo "BOTAN_INSTALL=/tmp/rnp-local-installs/botan-install" >> $GITHUB_ENV
echo "JSONC_INSTALL=/tmp/rnp-local-installs/jsonc-install" >> $GITHUB_ENV
echo "GPG_INSTALL=/tmp/rnp-local-installs/gpg-install" >> $GITHUB_ENV

# set this explicitly since we don't want to cache the rnp installation
echo "RNP_INSTALL=$GITHUB_WORKSPACE/rnp-install" >> $GITHUB_ENV
