#!/usr/bin/env bash

: "${LOCAL_BUILDS:=$HOME/local-builds}"
: "${LOCAL_INSTALLS:=$HOME/local-installs}"
: "${RNP_INSTALL:=$LOCAL_INSTALLS/rnp-install}"
: "${RUBY_RNP_INSTALL:=$LOCAL_INSTALLS/ruby-rnp}"
: "${RUBY_RNP_VERSION:=main}"
: "${CPU:=}"
: "${SUDO:=}"

for var in LOCAL_BUILDS LOCAL_INSTALLS RNP_INSTALL \
   RUBY_RNP_INSTALL RUBY_RNP_VERSION CPU SUDO; do
  export "${var?}"
done

: "${BUILD_MODE:=normal}"

if [ "$BUILD_MODE" = "sanitize" ]; then
  export CXX=clang++
  export CC=clang
fi

BOTAN_MODULES=$(<ci/botan-modules tr '\n' ',')

export BOTAN_MODULES
