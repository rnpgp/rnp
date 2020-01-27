: "${LOCAL_BUILDS:=$HOME/local-builds}"
: "${LOCAL_INSTALLS:=$HOME/local-installs}"
: "${BOTAN_INSTALL:=$LOCAL_INSTALLS/botan-install}"
: "${JSONC_INSTALL:=$LOCAL_INSTALLS/jsonc-install}"
: "${GPG_INSTALL:=$LOCAL_INSTALLS/gpg-install}"
: "${RNP_INSTALL:=$LOCAL_INSTALLS/rnp-install}"
: "${RUBY_RNP_INSTALL:=$LOCAL_INSTALLS/ruby-rnp}"
: "${RUBY_RNP_VERSION:=master}"
: "${VERSION_OVERRIDE_BRANCH:=master}"
for var in LOCAL_BUILDS LOCAL_INSTALLS BOTAN_INSTALL JSONC_INSTALL \
  GPG_INSTALL RNP_INSTALL RUBY_RNP_INSTALL RUBY_RNP_VERSION \
  VERSION_OVERRIDE_BRANCH; do
  export "${var?}"
done

if [ "$BUILD_MODE" = "sanitize" ]; then
  export CXX=clang++
  export CC=clang
fi

export BOTAN_MODULES=$(cat ci/botan-modules | tr '\n' ',')

