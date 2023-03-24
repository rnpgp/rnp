#!/usr/bin/env bash

: "${LOCAL_BUILDS:=$HOME/local-builds}"
: "${LOCAL_INSTALLS:=$HOME/local-installs}"
: "${BOTAN_INSTALL:=$LOCAL_INSTALLS/botan-install}"
: "${JSONC_INSTALL:=$LOCAL_INSTALLS/jsonc-install}"
: "${GPG_INSTALL:=$LOCAL_INSTALLS/gpg-install}"
: "${RNP_INSTALL:=$LOCAL_INSTALLS/rnp-install}"
: "${RUBY_RNP_INSTALL:=$LOCAL_INSTALLS/ruby-rnp}"
: "${RUBY_RNP_VERSION:=main}"
: "${CPU:=}"
: "${SUDO:=}"

for var in LOCAL_BUILDS LOCAL_INSTALLS BOTAN_INSTALL JSONC_INSTALL \
  GPG_INSTALL RNP_INSTALL RUBY_RNP_INSTALL \
  RUBY_RNP_VERSION CPU SUDO; do
  export "${var?}"
done

: "${BUILD_MODE:=normal}"

if [ "$BUILD_MODE" = "sanitize" ]; then
  export CXX=clang++
  export CC=clang
fi

BOTAN_MODULES=$(<ci/botan-modules tr '\n' ',')

export BOTAN_MODULES

# Don't clean up tempdirs when in CI runners to save time. Unset to disable.
export RNP_KEEP_TEMP=1
