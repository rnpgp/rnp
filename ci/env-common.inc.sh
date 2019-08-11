: "${LOCAL_BUILDS:=$HOME/local-builds}"
export LOCAL_BUILDS
: "${LOCAL_INSTALLS:=$HOME/local-installs}"
export LOCAL_INSTALLS

export BOTAN_INSTALL="${LOCAL_INSTALLS}/botan-install"
export JSONC_INSTALL="${LOCAL_INSTALLS}/jsonc-install"
export GPG_INSTALL="${LOCAL_INSTALLS}/gpg-install"
export RNP_INSTALL="${LOCAL_INSTALLS}/rnp-install"
export RUBY_RNP_INSTALL="${LOCAL_INSTALLS}/ruby-rnp"
export RUBY_RNP_VERSION="master"

if [ "$BUILD_MODE" = "sanitize" ]; then
  export CXX=clang++
  export CC=clang
fi

